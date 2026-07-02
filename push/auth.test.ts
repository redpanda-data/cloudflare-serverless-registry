import { describe, expect, test } from "bun:test";
import { parseWwwAuthenticate, TokenAuth, authorizedFetch } from "./auth";

describe("parseWwwAuthenticate", () => {
  test("parses a Bearer challenge with realm and service", () => {
    const header = 'Bearer realm="https://auth.pkg.redpanda.com/token",service="registry.pkg.redpanda.com"';
    expect(parseWwwAuthenticate(header)).toEqual({
      scheme: "bearer",
      realm: "https://auth.pkg.redpanda.com/token",
      service: "registry.pkg.redpanda.com",
    });
  });

  test("ignores a scope param containing an embedded comma", () => {
    const header =
      'Bearer realm="https://auth.pkg.redpanda.com/token",service="registry.pkg.redpanda.com",scope="repository:foo/bar:pull,push"';
    expect(parseWwwAuthenticate(header)).toEqual({
      scheme: "bearer",
      realm: "https://auth.pkg.redpanda.com/token",
      service: "registry.pkg.redpanda.com",
    });
  });

  test("does not let a second, comma-merged challenge overwrite the Bearer realm/service", () => {
    const header =
      'Bearer realm="https://auth.pkg.redpanda.com/token",service="registry.pkg.redpanda.com", Basic realm="https://registry.pkg.redpanda.com/v2/"';
    expect(parseWwwAuthenticate(header)).toEqual({
      scheme: "bearer",
      realm: "https://auth.pkg.redpanda.com/token",
      service: "registry.pkg.redpanda.com",
    });
  });

  test("prefers a Bearer challenge even when a Basic challenge comes first", () => {
    const header =
      'Basic realm="https://registry.pkg.redpanda.com/v2/", Bearer realm="https://auth.pkg.redpanda.com/token",service="registry.pkg.redpanda.com"';
    expect(parseWwwAuthenticate(header)).toEqual({
      scheme: "bearer",
      realm: "https://auth.pkg.redpanda.com/token",
      service: "registry.pkg.redpanda.com",
    });
  });

  test("parses a Basic challenge", () => {
    expect(parseWwwAuthenticate('Basic realm="https://registry.pkg.redpanda.com/v2/"')).toEqual({
      scheme: "basic",
    });
  });

  test("returns null for a Bearer challenge missing realm or service", () => {
    expect(parseWwwAuthenticate('Bearer service="registry.pkg.redpanda.com"')).toBeNull();
  });

  test("returns null for an unrecognized scheme", () => {
    expect(parseWwwAuthenticate('Digest realm="whatever"')).toBeNull();
  });
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function challengeResponse(header: string): Response {
  return new Response("unauthorized", { status: 401, headers: { "WWW-Authenticate": header } });
}

describe("TokenAuth", () => {
  test("header() returns a Basic credential before any challenge is seen", async () => {
    const auth = new TokenAuth("v0", "clusterjwt", "repository:foo:pull,push");
    expect(await auth.header()).toBe(`Basic ${btoa("v0:clusterjwt")}`);
  });

  test("handle401() exchanges the Basic credential for a Bearer token on a Bearer challenge", async () => {
    let calls = 0;
    const fetchFn = async (url: string | URL, init?: RequestInit) => {
      calls++;
      expect(url.toString()).toBe(
        "https://auth.pkg.redpanda.com/token?service=registry.pkg.redpanda.com&scope=repository%3Afoo%3Apull%2Cpush",
      );
      expect((init?.headers as Record<string, string>)["Authorization"]).toBe(`Basic ${btoa("v0:clusterjwt")}`);
      return jsonResponse({ token: "minted-token" });
    };
    const auth = new TokenAuth("v0", "clusterjwt", "repository:foo:pull,push", fetchFn);

    const res401 = challengeResponse(
      'Bearer realm="https://auth.pkg.redpanda.com/token",service="registry.pkg.redpanda.com"',
    );
    const shouldRetry = await auth.handle401(res401);

    expect(shouldRetry).toBe(true);
    expect(calls).toBe(1);
    expect(await auth.header()).toBe("Bearer minted-token");
  });

  test("refresh is single-flight under concurrent 401s", async () => {
    let calls = 0;
    const fetchFn = async () => {
      calls++;
      return jsonResponse({ token: "minted-token" });
    };
    const auth = new TokenAuth("v0", "clusterjwt", "repository:foo:pull,push", fetchFn);
    const res401 = challengeResponse(
      'Bearer realm="https://auth.pkg.redpanda.com/token",service="registry.pkg.redpanda.com"',
    );

    await Promise.all([auth.handle401(res401), auth.handle401(res401), auth.handle401(res401)]);

    expect(calls).toBe(1);
  });

  test("header() does not re-exchange immediately after a fresh mint", async () => {
    let calls = 0;
    const fetchFn = async () => {
      calls++;
      return jsonResponse({ token: "minted-token" });
    };
    const auth = new TokenAuth("v0", "clusterjwt", "repository:foo:pull,push", fetchFn);
    await auth.handle401(
      challengeResponse('Bearer realm="https://auth.pkg.redpanda.com/token",service="registry.pkg.redpanda.com"'),
    );

    await auth.header();
    await auth.header();

    expect(calls).toBe(1);
  });

  test("handle401() returns false when already on Basic and challenged with Basic again", async () => {
    const auth = new TokenAuth("v0", "clusterjwt", "repository:foo:pull,push");
    const shouldRetry = await auth.handle401(challengeResponse('Basic realm="https://registry.pkg.redpanda.com/v2/"'));
    expect(shouldRetry).toBe(false);
  });

  test("handle401() returns false when there is no WWW-Authenticate header", async () => {
    const auth = new TokenAuth("v0", "clusterjwt", "repository:foo:pull,push");
    const shouldRetry = await auth.handle401(new Response("unauthorized", { status: 401 }));
    expect(shouldRetry).toBe(false);
  });

  test("doRefresh() throws if the token endpoint response has no token field", async () => {
    const fetchFn = async () => jsonResponse({ notAToken: true });
    const auth = new TokenAuth("v0", "clusterjwt", "repository:foo:pull,push", fetchFn);
    await expect(
      auth.handle401(
        challengeResponse('Bearer realm="https://auth.pkg.redpanda.com/token",service="registry.pkg.redpanda.com"'),
      ),
    ).rejects.toThrow(/missing "token"/);
  });
});

describe("authorizedFetch", () => {
  test("retries once with a fresh header after a handled 401", async () => {
    const auth = new TokenAuth("v0", "clusterjwt", "repository:foo:pull,push", async () =>
      jsonResponse({ token: "minted-token" }),
    );
    let call = 0;
    const fetchImpl = async (_url: string | URL, init?: RequestInit) => {
      call++;
      if (call === 1) {
        expect((init?.headers as Headers).get("authorization")).toBe(`Basic ${btoa("v0:clusterjwt")}`);
        return challengeResponse(
          'Bearer realm="https://auth.pkg.redpanda.com/token",service="registry.pkg.redpanda.com"',
        );
      }
      expect((init?.headers as Headers).get("authorization")).toBe("Bearer minted-token");
      return new Response("ok", { status: 200 });
    };

    const res = await authorizedFetch(
      auth,
      "https://registry.pkg.redpanda.com/v2/foo/blobs/sha256:abc",
      { method: "HEAD" },
      fetchImpl,
    );

    expect(call).toBe(2);
    expect(res.status).toBe(200);
  });

  test("does not retry when handle401 has nothing left to try", async () => {
    const auth = new TokenAuth("v0", "clusterjwt", "repository:foo:pull,push");
    let call = 0;
    const fetchImpl = async () => {
      call++;
      return new Response("unauthorized", { status: 401 });
    };

    const res = await authorizedFetch(
      auth,
      "https://registry.pkg.redpanda.com/v2/foo/blobs/sha256:abc",
      { method: "HEAD" },
      fetchImpl,
    );

    expect(call).toBe(1);
    expect(res.status).toBe(401);
  });
});
