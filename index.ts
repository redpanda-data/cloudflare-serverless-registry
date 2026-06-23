/**
 * The core server that runs on a Cloudflare worker.
 */

import { Router } from "itty-router";
import { AuthErrorResponse, InternalError } from "./src/errors";
import v2Router from "./src/router";
import { authenticationMethodFromEnv } from "./src/authentication-method";
import { Registry } from "./src/registry/registry";
import { R2Registry } from "./src/registry/r2";
import { setRequestAuthPayload } from "./src/auth";

// A full compatibility mode means that the r2 registry will try its best to
// help the client on the layer push. See how we let the client push layers with chunked uploads for more information.
type PushCompatibilityMode = "full" | "none";

export interface Env {
  REGISTRY: R2Bucket;
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
}

const router = Router();

/**
 * V2 Api
 */
router.all("/v2/*", v2Router.fetch);

router.all("*", () => new Response("Not Found.", { status: 404 }));

export default {
  async fetch(request: Request, env: Env, context?: ExecutionContext) {
    if (!ensureConfig(env)) {
      // No working auth configured yet — challenge with Basic, not Bearer.
      return new AuthErrorResponse(request);
    }

    const authMethod = await authenticationMethodFromEnv(env);
    if (!authMethod) {
      return new AuthErrorResponse(request);
    }

    // Only advertise the Bearer token-auth flow when the JWT authenticator is
    // actually active. In USERNAME/PASSWORD (Basic) mode — or if JWT auth was
    // disabled (e.g. invalid algorithm) — the registry cannot satisfy a Bearer
    // challenge, so it must keep challenging with Basic.
    const tokenRealm = authMethod.authmode === "RegistryTokens" ? env.REGISTRY_TOKEN_REALM : undefined;

    const credentials = await authMethod.checkCredentials(request);
    if (!credentials.verified) {
      console.warn(`Not Authorized. authmode=${authMethod.authmode}. verified=false`);
      return new AuthErrorResponse(request, tokenRealm);
    }

    // Stash the verified payload request-scoped (NOT on the shared `env`) for
    // handlers that authorise non-URL-path repositories (cross-repo mount).
    setRequestAuthPayload(request, credentials.payload ?? null);
    env.REGISTRY_CLIENT = new R2Registry(env);
    try {
      // Dispatch the request to the appropriate route
      const res = await router.fetch(request, env, context);
      return res;
    } catch (err) {
      if (err instanceof Response) {
        console.warn(`${request.method} ${err.status} ${err.url}`);
        return err;
      }

      // Unexpected error
      if (err instanceof Error) {
        console.error(
          "An error has been thrown by the router:\n",
          `${err.name}: ${err.message}: ${err.cause}: ${err.stack}`,
        );
        return new InternalError();
      }

      console.error(
        "An error has been thrown and is neither a Response or an Error, JSON.stringify() =",
        JSON.stringify(err),
      );
      return new InternalError();
    }
  },
} satisfies ExportedHandler<Env>;

const ensureConfig = (env: Env): boolean => {
  if (!env.REGISTRY) {
    console.error(
      "env.REGISTRY is not setup. Please setup an R2 bucket and add the binding in wrangler.toml. Try 'npx wrangler --env production r2 bucket create r2-registry'",
    );
    return false;
  }

  return true;
};
