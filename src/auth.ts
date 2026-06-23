import { decodeBase64Loose, errorString } from "./utils";

export type RegistryTokenCapability = "push" | "pull";
export type RegistryAuthProtocolTokenPayload = {
  username: string;
  account_id?: string;
  capabilities: RegistryTokenCapability[];
  exp: number;
  aud: string;
  iat?: number;
  /**
   * Optional JWT ID. When set, the registry can check `jti` against a
   * deny-list KV namespace and reject revoked tokens before expiry.
   */
  jti?: string;
  /**
   * Optional Docker Registry token scope claim (RFC-ish, see
   * https://distribution.github.io/distribution/spec/auth/scope/). When set,
   * the registry restricts every authenticated request to a repository
   * named by one of the scope tokens and to an action present in that
   * token's actions list.
   *
   * Wire format: either a single string ("repository:a:pull repository:b:pull,push")
   * or an array of strings (one scope token per element).
   */
  scope?: string | string[];
};

/** Parsed Docker Registry token scope: `<type>:<name>:<actions>`. */
export type ParsedScope = {
  type: string;
  name: string;
  actions: string[];
};

/**
 * Parse the `scope` claim into structured tokens. Accepts both the
 * space-separated single-string form and the array-of-strings form. Tokens
 * that don't match the `type:name:actions` shape are dropped (rather than
 * raising) so a malformed claim fails closed: no parsed scopes -> no
 * granted access via the scope path.
 */
export function parseScopeClaim(scope: string | string[] | undefined): ParsedScope[] {
  if (scope === undefined) return [];
  const raw = Array.isArray(scope) ? scope : scope.split(/\s+/);
  const out: ParsedScope[] = [];
  for (const tok of raw) {
    if (!tok) continue;
    // Repository names can contain colons in theory (port in a registry
    // hostname), but in the Distribution spec the scope syntax uses ":"
    // as the structural separator, so we split into exactly 3 segments.
    const firstColon = tok.indexOf(":");
    const lastColon = tok.lastIndexOf(":");
    if (firstColon === -1 || lastColon === firstColon) continue;
    const type = tok.slice(0, firstColon);
    const name = tok.slice(firstColon + 1, lastColon);
    const actions = tok
      .slice(lastColon + 1)
      .split(",")
      .map((a) => a.trim())
      .filter((a) => a.length > 0);
    if (!type || !name || actions.length === 0) continue;
    out.push({ type, name, actions });
  }
  return out;
}

/**
 * Per-request store for the verified token payload, keyed by the Request object
 * (which is unique per request). Handlers need the payload to authorise
 * operations whose target repository isn't in the URL path (the cross-repo
 * mount `from` source). We deliberately DON'T stash it on `env`: the bindings
 * object is shared across concurrent requests in an isolate, so mutating it
 * risks bleeding one request's auth context into another — a correctness and
 * (since it drives an authz decision) security hazard. A WeakMap keyed by the
 * request is request-scoped and garbage-collected automatically.
 */
const requestAuthPayloads = new WeakMap<Request, RegistryAuthProtocolTokenPayload>();

export function setRequestAuthPayload(request: Request, payload: RegistryAuthProtocolTokenPayload | null): void {
  if (payload) requestAuthPayloads.set(request, payload);
}

export function getRequestAuthPayload(request: Request): RegistryAuthProtocolTokenPayload | undefined {
  return requestAuthPayloads.get(request);
}

/**
 * Does this token's `scope` claim authorise `action` on `repo`? A token with no
 * `scope` claim is treated as unrestricted (single-tenant USERNAME/PASSWORD or
 * a no-scope JWT deploy); a token that DOES carry a scope claim must name the
 * repository and an authorising action (or the `*` wildcard). Used to gate
 * operations whose target repository isn't the request URL path — notably the
 * cross-repository blob mount `from` source.
 */
export function scopeAuthorizes(
  payload: RegistryAuthProtocolTokenPayload | null | undefined,
  repo: string,
  action: string,
): boolean {
  if (!payload || payload.scope === undefined) return true;
  return parseScopeClaim(payload.scope).some(
    (s) => s.type === "repository" && s.name === repo && (s.actions.includes(action) || s.actions.includes("*")),
  );
}

/**
 * Extract the OCI repository name from a v2 request URL. Returns null for
 * non-repository endpoints (like /v2/ or /v2/_catalog) — those bypass the
 * scope check and rely on capabilities-only gating in `verifyPayload`.
 *
 * The list of boundary segments must cover EVERY repository-scoped route the
 * router exposes; otherwise a missing entry becomes a scope-bypass bug
 * (a token scoped to repository A could act on repository B via that route
 * if it carries the matching capability). The router exposes `/gc` as a
 * repository-scoped operation that is not part of the OCI Distribution
 * spec — keep it in this list.
 */
export function repositoryNameFromUrl(url: string): string | null {
  let pathname: string;
  try {
    pathname = new URL(url).pathname;
  } catch {
    return null;
  }
  if (!pathname.startsWith("/v2/")) return null;
  const rest = pathname.slice("/v2/".length);
  const boundaries = ["/manifests/", "/blobs/", "/tags/list", "/referrers/", "/gc"];
  for (const b of boundaries) {
    const idx = rest.indexOf(b);
    if (idx > 0) return rest.slice(0, idx);
  }
  return null;
}

/**
 * Is the v2 path repository-scoped? Used to decide whether a token with a
 * `scope` claim must produce a matching parsed scope or fail closed. The
 * truth source is `repositoryNameFromUrl`: anything it can extract a name
 * from is repository-scoped.
 */
export function isRepositoryScopedRequest(url: string): boolean {
  return repositoryNameFromUrl(url) !== null;
}

/**
 * For an HTTP method, return the registry action the request requires
 * (used to verify against the scope's `actions` list).
 */
export function actionForMethod(method: string): "pull" | "push" | "delete" | null {
  switch (method) {
    case "GET":
    case "HEAD":
      return "pull";
    case "POST":
    case "PUT":
    case "PATCH":
      return "push";
    case "DELETE":
      return "delete";
    default:
      return null;
  }
}

export type AuthenticatorCheckCredentialsResponse = {
  verified: boolean;
  payload: RegistryAuthProtocolTokenPayload | null;
};

export interface Authenticator {
  authmode: string;
  checkCredentials(r: Request): Promise<AuthenticatorCheckCredentialsResponse>;
}

/**
 * Extract a Bearer token from the Authorization header, or null if the request
 * doesn't use the Bearer scheme. Used by the JWT authenticator so standard OCI
 * clients can present `Authorization: Bearer <registry-jwt>` after the Docker
 * Registry v2 token-auth exchange, in addition to the legacy Basic-password
 * form. The token is verified by the same `verifyToken` path as the Basic
 * password JWT.
 */
export function bearerTokenFromHeader(r: Request): string | null {
  const authorization = r.headers.get("Authorization") ?? "";
  // Per RFC 7235 the auth scheme is case-insensitive and any amount of
  // whitespace may separate it from the credentials, so match loosely rather
  // than splitting on a single space — some OCI clients/proxies emit
  // `bearer <token>` or pad with extra spaces.
  // The Bearer credential is a single non-whitespace token (RFC 6750 b64token).
  // Capturing `\S+` (rather than `.*?`) rejects a value with embedded spaces or
  // trailing junk like "Bearer <jwt> extra" instead of passing a malformed
  // token downstream.
  const match = authorization.match(/^\s*Bearer\s+(\S+)\s*$/i);
  if (!match) return null;
  return match[1];
}

export function stripUsernamePasswordFromHeader(r: Request): [string, string] | { verified: false; payload: null } {
  // first check if we have an Authorization header, this is the basis for all auth stuff in our registry
  const authorization = r.headers.get("Authorization") ?? "";
  if (!authorization) {
    // missing authorization header
    // do not log this. the /v2/ sends this request without any credentials to do version checking
    // we do not want to remove /v2/ from the auth middleware as well
    return { verified: false, payload: null };
  }

  // Match the Basic scheme case-insensitively with whitespace tolerance per
  // RFC 7235 (the scheme is case-insensitive and any amount of whitespace may
  // separate it from the credentials); a strict `split(" ")` + exact-case
  // check rejects valid headers from some clients/proxies. The base64 token
  // itself contains no whitespace.
  const match = authorization.match(/^\s*Basic\s+(\S+)\s*$/i);
  if (!match) {
    console.warn("failed checkCredentials: Authorization doesn't include Basic scheme");
    return { verified: false, payload: null };
  }
  const encoded = match[1];

  try {
    // RFC 7617 Basic credentials are STANDARD base64 (may contain `+` and `/`),
    // so decode with `atob` — a base64url decoder rejects those characters and
    // would drop otherwise-valid headers. `atob` yields one byte per char;
    // re-decode as UTF-8 so multi-byte usernames survive.
    const decoded = new TextDecoder().decode(Uint8Array.from(decodeBase64Loose(encoded), (ch) => ch.charCodeAt(0)));

    // The username & password are split by the first colon.
    //=> example: "username:password"
    const index = decoded.indexOf(":");

    // The user & password are split by the first colon and MUST NOT contain control characters.
    // @see https://tools.ietf.org/html/rfc5234#appendix-B.1 (=> "CTL = %x00-1F / %x7F")
    // eslint-disable-next-line no-control-regex
    if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
      return { verified: false, payload: null };
    }

    const username = decoded.substring(0, index);
    const password = decoded.substring(index + 1);
    return [username, password];
  } catch (err) {
    console.error(`Failure getting data from Authorization header: ${errorString(err)}`);
    return { verified: false, payload: null };
  }
}
