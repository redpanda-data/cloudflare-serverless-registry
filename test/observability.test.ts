import { afterEach, describe, expect, test, vi } from "vitest";
import worker from "../index";
import type { Env } from "..";
import { env } from "cloudflare:workers";
import { createExecutionContext, reset, waitOnExecutionContext } from "cloudflare:test";
import { getSHA256 } from "../src/user";

afterEach(async () => {
  vi.restoreAllMocks();
  await reset();
});

function createRequest(method: string, path: string, headers: Record<string, string> = {}): Request {
  return new Request(new URL("https://registry.com" + path), { method, headers });
}

function basicAuth(username: string, password: string): string {
  return `Basic ${btoa(`${username}:${password}`)}`;
}

describe("observability", () => {
  test("emits a structured warn log and a failure metric on denied auth", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const bindings = env as Env;
    const metricsSpy = vi.spyOn(bindings.METRICS!, "writeDataPoint");

    const ctx = createExecutionContext();
    const res = await worker.fetch(
      createRequest("GET", "/v2/", { Authorization: basicAuth("hello", "wrong") }),
      bindings,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(401);

    expect(warnSpy).toHaveBeenCalled();
    const logged = JSON.parse(warnSpy.mock.calls.at(-1)![0] as string);
    expect(logged).toMatchObject({ level: "warn", event: "auth_denied" });

    expect(metricsSpy).toHaveBeenCalledWith(
      expect.objectContaining({ blobs: ["registry", "auth_denied"], indexes: ["401"] }),
    );
  });

  test("tags the anonymous version probe distinctly from a real auth denial", async () => {
    const bindings = env as Env;
    const metricsSpy = vi.spyOn(bindings.METRICS!, "writeDataPoint");

    const ctx = createExecutionContext();
    // No Authorization header at all: the routine anonymous GET /v2/ probe
    // every OCI/Docker client sends before presenting real credentials.
    const res = await worker.fetch(createRequest("GET", "/v2/"), bindings, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(401);
    expect(metricsSpy).toHaveBeenCalledWith(
      expect.objectContaining({ blobs: ["registry", "anonymous_probe"], indexes: ["401"] }),
    );
  });

  test("tags an unauthenticated request to a non-/v2 path as a real denial, not an anonymous probe", async () => {
    const bindings = env as Env;
    const metricsSpy = vi.spyOn(bindings.METRICS!, "writeDataPoint");

    const ctx = createExecutionContext();
    // No Authorization header, but not the /v2 version-probe path: this is a
    // real denial (e.g. an attempted anonymous manifest pull), not the
    // routine docker-login-style preflight.
    const res = await worker.fetch(createRequest("GET", "/v2/some-repo/manifests/latest"), bindings, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(401);
    expect(metricsSpy).toHaveBeenCalledWith(
      expect.objectContaining({ blobs: ["registry", "auth_denied"], indexes: ["401"] }),
    );
  });

  test("fails closed with config_error, not unhandled_error, on a malformed JWT_REGISTRY_TOKENS_PUBLIC_KEY", async () => {
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const bindings: Env = { ...(env as Env), JWT_REGISTRY_TOKENS_PUBLIC_KEY: "not-valid-base64-jwk!!!" };
    const metricsSpy = vi.spyOn(bindings.METRICS!, "writeDataPoint");

    const ctx = createExecutionContext();
    const res = await worker.fetch(createRequest("GET", "/v2/"), bindings, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(401);
    const logged = JSON.parse(errorSpy.mock.calls.at(-1)![0] as string);
    expect(logged).toMatchObject({ level: "error", event: "jwt_auth_config_invalid" });
    expect(metricsSpy).toHaveBeenCalledWith(
      expect.objectContaining({ blobs: ["registry", "config_error"], indexes: ["401"] }),
    );
  });

  test("emits a success metric on a successful request", async () => {
    const bindings = env as Env;
    const metricsSpy = vi.spyOn(bindings.METRICS!, "writeDataPoint");

    const ctx = createExecutionContext();
    const res = await worker.fetch(
      createRequest("GET", "/v2/", { Authorization: basicAuth("hello", "world") }),
      bindings,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(200);
    expect(metricsSpy).toHaveBeenCalledWith(
      expect.objectContaining({ blobs: ["registry", "success"], indexes: ["200"] }),
    );
  });

  test("tags a non-2xx response returned (not thrown) by the router as response_error, not success", async () => {
    const bindings = env as Env;
    const metricsSpy = vi.spyOn(bindings.METRICS!, "writeDataPoint");

    const ctx = createExecutionContext();
    // Authenticates fine, but hits the catch-all "*" route, which returns a
    // plain 404 Response rather than throwing.
    const res = await worker.fetch(
      createRequest("GET", "/not-a-real-route", { Authorization: basicAuth("hello", "world") }),
      bindings,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(404);
    expect(metricsSpy).toHaveBeenCalledWith(
      expect.objectContaining({ blobs: ["registry", "response_error"], indexes: ["404"] }),
    );
  });

  test("tags a 304 Not Modified cache hit as success, not response_error", async () => {
    const bindings = env as Env;
    const name = "cache-hit-metric";
    const reference = "latest";
    const data = "{}";
    const sha256 = await getSHA256(data);
    await bindings.REGISTRY.put(`${name}/manifests/${reference}`, data, {
      httpMetadata: { contentType: "application/gzip" },
      sha256: sha256.slice(sha256.indexOf(":") + 1),
    });
    const metricsSpy = vi.spyOn(bindings.METRICS!, "writeDataPoint");

    const ctx = createExecutionContext();
    const req = createRequest("GET", `/v2/${name}/manifests/${reference}`, {
      Authorization: basicAuth("hello", "world"),
    });
    req.headers.set("If-None-Match", `"${sha256}"`);
    const res = await worker.fetch(req, bindings, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(304);
    expect(metricsSpy).toHaveBeenCalledWith(
      expect.objectContaining({ blobs: ["registry", "success"], indexes: ["304"] }),
    );
    await bindings.REGISTRY.delete(`${name}/manifests/${reference}`);
  });

  test("does not mutate the shared env binding with a request-scoped REGISTRY_CLIENT", async () => {
    const bindings = env as Env;
    expect(bindings.REGISTRY_CLIENT).toBeUndefined();

    const ctx = createExecutionContext();
    await worker.fetch(createRequest("GET", "/v2/", { Authorization: basicAuth("hello", "world") }), bindings, ctx);
    await waitOnExecutionContext(ctx);

    // The shared `env` binding object must come out exactly as it went in:
    // fetch() builds its own per-request copy rather than assigning
    // REGISTRY_CLIENT onto the object every request shares, which would let
    // one in-flight request's client leak into a concurrent one.
    expect(bindings.REGISTRY_CLIENT).toBeUndefined();
  });
});
