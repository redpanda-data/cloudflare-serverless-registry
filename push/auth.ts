// registry.pkg's token endpoint normally returns expires_in (900s observed
// in production) and doRefresh() honors it. This is only the fallback for a
// response that omits the field, kept in the same ~15-min ballpark.
const BEARER_TTL_MS = 15 * 60 * 1000;
const REFRESH_MARGIN_MS = 2 * 60 * 1000;

export type Challenge = { scheme: "bearer"; realm: string; service: string } | { scheme: "basic" };

// Splits a WWW-Authenticate header value into its individual challenges. A
// response can carry more than one, in either order (fetch's Headers joins
// repeated header lines with ", "), e.g.
//   Bearer realm="...",service="...", Basic realm="..."
// A challenge boundary is a comma (outside any quoted value) followed by a
// bare scheme token rather than a "key=" continuation of the same
// challenge; quoted spans are masked first so a comma inside a value (e.g.
// a "pull,push" scope) is never mistaken for one.
function splitChallenges(header: string): string[] {
  const masked = header.replace(/"[^"]*"/g, (m) => `"${" ".repeat(m.length - 2)}"`);
  const challenges: string[] = [];
  let start = 0;
  for (const boundary of masked.matchAll(/,\s*(?![\w-]+=)/g)) {
    challenges.push(header.slice(start, boundary.index));
    start = boundary.index! + boundary[0].length;
  }
  challenges.push(header.slice(start));
  return challenges;
}

// Parses a Docker Registry v2 WWW-Authenticate challenge, e.g.
//   Bearer realm="https://auth.pkg.redpanda.com/token",service="registry.pkg.redpanda.com",scope="repository:foo:pull"
// The scope param (if present) is intentionally not extracted: callers derive
// their own scope from the target image path rather than trusting the
// challenge's scope. If multiple challenges are present, a Bearer challenge
// is preferred wherever it appears -- params are read only from that one
// challenge, so another challenge's own "realm" can't leak in -- and Basic
// is only used when no Bearer challenge is present at all.
export function parseWwwAuthenticate(header: string): Challenge | null {
  const challenges = splitChallenges(header);

  for (const challenge of challenges) {
    const spaceIdx = challenge.indexOf(" ");
    const scheme = (spaceIdx === -1 ? challenge : challenge.slice(0, spaceIdx)).toLowerCase();
    if (scheme !== "bearer") continue;

    const params: Record<string, string> = {};
    for (const match of challenge.matchAll(/(\w+)="([^"]*)"/g)) {
      params[match[1]] = match[2];
    }
    if (params.realm && params.service) return { scheme: "bearer", realm: params.realm, service: params.service };
  }

  for (const challenge of challenges) {
    const spaceIdx = challenge.indexOf(" ");
    const scheme = (spaceIdx === -1 ? challenge : challenge.slice(0, spaceIdx)).toLowerCase();
    if (scheme === "basic") return { scheme: "basic" };
  }

  return null;
}

// TokenAuth implements the Docker Registry v2 auth flow: start with Basic,
// and if the registry challenges with a Bearer realm, exchange the Basic
// credential for a scoped Bearer token and use that for every request after,
// refreshing proactively before the assumed TTL runs out.
export class TokenAuth {
  private usingBearer = false;
  private bearerToken = "";
  private bearerExpiresAt = 0;
  private realm: string | undefined;
  private service: string | undefined;
  private refreshing: Promise<void> | undefined;

  constructor(
    private username: string | undefined,
    private password: string | undefined,
    private scope: string,
    private fetchFn: (url: string | URL, init?: RequestInit) => Promise<Response> = fetch,
  ) {}

  basicHeader(): string {
    return `Basic ${btoa(`${this.username}:${this.password}`)}`;
  }

  async header(): Promise<string> {
    if (!this.usingBearer) return this.basicHeader();
    if (Date.now() >= this.bearerExpiresAt - REFRESH_MARGIN_MS) await this.refresh();
    return `Bearer ${this.bearerToken}`;
  }

  // Call after a request 401s. Returns true if the caller should retry the
  // same request with a fresh header() value; false if there's nothing left
  // to try (e.g. the Basic credential itself is wrong).
  async handle401(response: Response): Promise<boolean> {
    const wwwAuth = response.headers.get("WWW-Authenticate");
    if (!wwwAuth) return false;
    const challenge = parseWwwAuthenticate(wwwAuth);
    if (challenge === null) return false;

    if (challenge.scheme === "basic") {
      if (!this.usingBearer) return false; // already sent Basic, still 401: bad creds
      this.usingBearer = false; // registry stopped honoring the bearer; fall back to Basic and retry
      return true;
    }

    this.realm = challenge.realm;
    this.service = challenge.service;
    await this.refresh();
    return true;
  }

  private refresh(): Promise<void> {
    if (!this.refreshing) {
      this.refreshing = this.doRefresh().finally(() => {
        this.refreshing = undefined;
      });
    }
    return this.refreshing;
  }

  private async doRefresh(): Promise<void> {
    if (!this.realm || !this.service) {
      throw new Error("TokenAuth: cannot mint a bearer token before seeing a Bearer challenge");
    }
    const url = new URL(this.realm);
    url.searchParams.set("service", this.service);
    url.searchParams.set("scope", this.scope);

    const res = await this.fetchFn(url.toString(), {
      headers: { Authorization: this.basicHeader(), Accept: "application/json" },
    });
    if (!res.ok) {
      throw new Error(`token exchange at ${url.toString()} failed: ${res.status} ${await res.text()}`);
    }

    const body = (await res.json()) as { token?: string; access_token?: string; expires_in?: number };
    const token = body.token ?? body.access_token;
    if (!token) throw new Error(`token exchange response from ${url.toString()} is missing "token"`);

    this.usingBearer = true;
    this.bearerToken = token;
    this.bearerExpiresAt = Date.now() + (body.expires_in ?? BEARER_TTL_MS / 1000) * 1000;
    console.log("Exchanged Basic credential for a scoped Bearer token");
  }
}

// authorizedFetch sends a request with the current auth header and, on a 401
// that TokenAuth can recover from, retries exactly once with a fresh header.
// Only safe for requests whose body (if any) can be sent twice — do NOT use
// this for the chunked PATCH upload, whose body is a single-use stream.
export async function authorizedFetch(
  auth: TokenAuth,
  url: string,
  init: RequestInit,
  fetchImpl: (url: string | URL, init?: RequestInit) => Promise<Response> = fetch,
): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set("authorization", await auth.header());
  let response = await fetchImpl(url, { ...init, headers });
  if (response.status === 401 && (await auth.handle401(response))) {
    headers.set("authorization", await auth.header());
    response = await fetchImpl(url, { ...init, headers });
  }
  return response;
}
