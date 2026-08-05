/**
 * The core server that runs on a Cloudflare worker.
 */

import { Router } from "itty-router";
import { AuthErrorResponse, InternalError } from "./src/errors";
import v2Router from "./src/router";
import { authenticationMethodFromEnv } from "./src/authentication-method";
import { RegistryTokens } from "./src/token";
import { Registry } from "./src/registry/registry";
import { R2Registry } from "./src/registry/r2";
import { setRequestAuthPayload } from "./src/auth";
import { log } from "./src/log";
import { safeErrorString } from "./src/utils";

// A full compatibility mode means that the r2 registry will try its best to
// help the client on the layer push. See how we let the client push layers with chunked uploads for more information.
type PushCompatibilityMode = "full" | "none";

export interface Env {
  REGISTRY: R2Bucket;
  METRICS?: AnalyticsEngineDataset;
  ENVIRONMENT: string;
  JWT_REGISTRY_TOKENS_PUBLIC_KEY?: string;
  /**
   * JWT signing algorithm to verify against `JWT_REGISTRY_TOKENS_PUBLIC_KEY`.
   * Accepts ES256 (default, back-compat), ES384, ES512, RS256, RS384, RS512.
   */
  JWT_REGISTRY_TOKENS_ALGORITHM?: string;
  /**
   * Optional KV namespace acting as a deny-list of revoked JWT IDs. When
   * bound, the JWT auth path rejects any presented token whose `jti` claim
   * is a key in this namespace. Tokens without `jti` cannot be revoked
   * out-of-band; rely on natural `exp` expiry instead.
   */
  JWT_REGISTRY_TOKENS_DENY_LIST?: KVNamespace;
  /**
   * Token endpoint URL advertised in the `WWW-Authenticate: Bearer realm=...`
   * 401 challenge. When set, the registry speaks the Docker Registry v2
   * token-auth flow; when unset, it falls back to a Basic challenge.
   */
  REGISTRY_TOKEN_REALM?: string;
  USERNAME?: string;
  PASSWORD?: string;
  READONLY_USERNAME?: string;
  READONLY_PASSWORD?: string;
  PUSH_COMPATIBILITY_MODE?: PushCompatibilityMode;
  REGISTRIES_JSON?: string; // should be in the format of RegistryConfiguration[];
  REGISTRY_CLIENT: Registry;
  /**
   * Prefix prepended to the R2 object keys that make up the durable OCI
   * data this Worker owns (manifests, blobs, upload state, referrers,
   * etc). A few short-lived, purely internal keys are deliberately left
   * unprefixed (e.g. the multipart-upload scratch/chunk-helper objects,
   * keyed by a bare UUID) since they never collide across namespaces and
   * aren't part of what's being namespaced. Used to namespace container
   * artifacts within a bucket shared with other, non-container artifact
   * types (e.g. set to "artifacts/containers/"). Unset/empty is a
   * no-op — keys are written unprefixed at the bucket root, which keeps
   * local dev (`wrangler dev`) and other consumers of this fork working
   * without any configuration. A trailing "/" is optional and normalized on
   * (see `normalizeR2KeyPrefix`), so "artifacts/containers" and
   * "artifacts/containers/" behave identically.
   */
  R2_KEY_PREFIX?: string;
}

const router = Router();

/**
 * V2 Api
 */
router.all("/v2/*", v2Router.fetch);

router.all("*", () => new Response("Not Found.", { status: 404 }));

// Matches exactly the two existence-check routes registered in src/router.ts
// ("/:name+/manifests/:reference" and "/:name+/blobs/:tag", both mounted
// under "/v2/"): itty-router's `:name+` compiles to zero-or-more path
// segments (an empty name, e.g. a leading "//", still dispatches to the same
// handler), then a fixed "manifests" or "blobs" segment, then exactly one
// more segment for the reference/tag. Deliberately narrower than "any HEAD
// 404" — see the fetch handler below. The leading `.*` (not `.+`) and
// trailing `\/*` both mirror itty-router's own compiled route semantics --
// without them, an empty-name or trailing-slash request still dispatches to
// the same handler with the same params, but this regex would miss it.
const OCI_EXISTENCE_CHECK_PATH = /^\/v2\/.*\/(manifests|blobs)\/[^/]+\/*$/;

function recordMetric(env: Env, outcome: string, status: number, durationMs: number): void {
  // blobs[0] is a fixed "registry" source tag: the METRICS dataset is shared
  // with the auth Worker (a separate deployable, instrumented in the
  // companion devprod-infra plan), so the alerting Worker's queries group by
  // this dimension to compute per-source error rates.
  try {
    env.METRICS?.writeDataPoint({
      blobs: ["registry", outcome],
      doubles: [durationMs],
      indexes: [String(status)],
    });
  } catch (err) {
    // Instrumentation is best-effort: a metrics write failure must never
    // turn an otherwise-successful (or already-erroring) response into an
    // unhandled 500 via the caller's outer catch.
    log.error("metrics_write_failed", { error: safeErrorString(err) });
  }
}

export default {
  async fetch(request: Request, env: Env, context?: ExecutionContext) {
    const start = Date.now();
    const elapsed = () => Date.now() - start;

    try {
      if (!ensureConfig(env)) {
        // Storage prerequisite missing (the R2 bucket binding). Challenge with
        // Basic rather than Bearer — we can't service a token-auth flow without
        // a configured registry backend.
        recordMetric(env, "config_error", 401, elapsed());
        return new AuthErrorResponse(request);
      }

      const authMethod = await authenticationMethodFromEnv(env);
      if (!authMethod) {
        recordMetric(env, "config_error", 401, elapsed());
        return new AuthErrorResponse(request);
      }

      // Only advertise the Bearer token-auth flow when the JWT authenticator is
      // actually active. In USERNAME/PASSWORD (Basic) mode — or if JWT auth was
      // disabled (e.g. invalid algorithm) — the registry cannot satisfy a Bearer
      // challenge, so it must keep challenging with Basic.
      const tokenRealm = authMethod.authmode === "RegistryTokens" ? env.REGISTRY_TOKEN_REALM : undefined;

      const credentials = await authMethod.checkCredentials(request);
      if (!credentials.verified) {
        // No Authorization header at all (matching src/auth.ts's own falsy
        // convention in stripUsernamePasswordFromHeader/bearerTokenFromHeader)
        // AND on the /v2 version-probe path specifically is the routine
        // anonymous probe every OCI/Docker client sends before presenting
        // real credentials — tagging it the same as a genuine denial would
        // swamp the auth_denied outcome with expected traffic instead of
        // real credential failures. An unauthenticated request to any other
        // path (e.g. a manifest/blob route) is a real denial, not a probe.
        const anonymous = !request.headers.get("Authorization") && RegistryTokens.checkIfV2OnlyPath(request);
        const outcome = anonymous ? "anonymous_probe" : "auth_denied";
        const path = new URL(request.url).pathname;
        const method = request.method;
        // anonymous_probe is expected, high-volume traffic (every OCI/Docker
        // client's preflight); logging it at warn would swamp real denials
        // in a warning stream. info keeps it visible without the noise.
        if (anonymous) {
          log.info(outcome, { authmode: authMethod.authmode, path, method });
        } else {
          log.warn(outcome, { authmode: authMethod.authmode, path, method });
        }
        recordMetric(env, outcome, 401, elapsed());
        return new AuthErrorResponse(request, tokenRealm);
      }

      // Stash the verified payload request-scoped (NOT on the shared `env`) for
      // handlers that authorise non-URL-path repositories (cross-repo mount).
      setRequestAuthPayload(request, credentials.payload ?? null);
      // A request-scoped copy, not a mutation of the shared `env` binding
      // object: Workers can interleave concurrent requests within the same
      // isolate across `await` points, and mutating `env.REGISTRY_CLIENT`
      // directly would let one request's client leak into another's while
      // both are in flight. R2Registry self-references env.REGISTRY_CLIENT
      // (src/registry/r2.ts's cross-repo layer-mount resolution), so it must
      // be constructed with — and assigned onto — this same fresh object,
      // not the shared `env` it was built from.
      const requestEnv: Env = { ...env };
      requestEnv.REGISTRY_CLIENT = new R2Registry(requestEnv);
      // Dispatch the request to the appropriate route
      const res = await router.fetch(request, requestEnv, context);
      // Derived from the actual status, not hardcoded: a route can return a
      // non-2xx Response without throwing (404s, RangeErrors, the router's
      // catch-all 404), and those must not be counted as "success". Checked
      // against < 400 rather than res.ok (200-299 only): a 304 Not Modified
      // from maybeNotModified() on a warm docker-pull cache hit is a
      // legitimate, by-design outcome, not an error.
      //
      // A HEAD request answered 404 on a manifest/blob existence-check path
      // is the routine check every docker/buildx/crane push issues before
      // uploading, to see if it's already present — "not found yet" is the
      // designed, expected answer for a new tag or a new layer not already
      // cached, not a backend/config failure. Tagging it "response_error"
      // the same as a genuine origin failure would make ordinary push
      // traffic swamp the alerting Worker's error rate, the same
      // false-positive shape anonymous_probe (above) already prevents for
      // ordinary unauthenticated preflight — hence the same "_probe" suffix
      // convention. Scoped to exactly this path shape (not any HEAD 404)
      // deliberately: a HEAD 404 anywhere else still means something the
      // router doesn't recognize, which is a real routing signal worth
      // keeping visible, not something to fold into the same benign bucket.
      const isExistenceCheckPath = OCI_EXISTENCE_CHECK_PATH.test(new URL(request.url).pathname);
      const outcome =
        request.method === "HEAD" && res.status === 404 && isExistenceCheckPath
          ? "not_found_probe"
          : res.status < 400
            ? "success"
            : "response_error";
      recordMetric(env, outcome, res.status, elapsed());
      return res;
    } catch (err) {
      if (err instanceof Response) {
        log.warn("router_error_response", {
          method: request.method,
          status: err.status,
          path: new URL(request.url).pathname,
        });
        recordMetric(env, "router_error", err.status, elapsed());
        return err;
      }

      log.error("unhandled_error", { error: safeErrorString(err) });
      recordMetric(env, "unhandled_error", 500, elapsed());
      return new InternalError();
    }
  },
} satisfies ExportedHandler<Env>;

const ensureConfig = (env: Env): boolean => {
  if (!env.REGISTRY) {
    log.error("missing_registry_binding", {
      hint: "Setup an R2 bucket and add the binding in your wrangler config file. Try 'npx wrangler --env production r2 bucket create r2-registry'",
    });
    return false;
  }

  return true;
};
