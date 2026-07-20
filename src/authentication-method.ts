import { Env } from "..";
import { newRegistryTokens, parseJwtAlgorithm } from "./token";
import { UserAuthenticator } from "./user";
import type { AuthenticatorCredentials } from "./user";
import { log } from "./log";
import { safeErrorString } from "./utils";

export async function authenticationMethodFromEnv(env: Env) {
  if (env.JWT_REGISTRY_TOKENS_PUBLIC_KEY) {
    // Fail closed on a typo in JWT_REGISTRY_TOKENS_ALGORITHM or a malformed
    // JWT_REGISTRY_TOKENS_PUBLIC_KEY (bad base64, or base64 that decodes to
    // non-JSON — importKeyFromBase64 throws on either). A thrown error that
    // escapes this local catch would unwind into index.ts's outer catch,
    // which logs unhandled_error and returns a generic 500; either
    // misconfiguration should look like "auth not configured" (a 401
    // config_error) instead.
    try {
      const algorithm = parseJwtAlgorithm(env.JWT_REGISTRY_TOKENS_ALGORITHM);
      return await newRegistryTokens(env.JWT_REGISTRY_TOKENS_PUBLIC_KEY, algorithm, env.JWT_REGISTRY_TOKENS_DENY_LIST);
    } catch (err) {
      log.error("jwt_auth_config_invalid", { error: safeErrorString(err) });
      return undefined;
    }
  } else if ((env.USERNAME && env.PASSWORD) || (env.READONLY_USERNAME && env.READONLY_PASSWORD)) {
    const credentials: AuthenticatorCredentials[] = [];

    if (env.USERNAME && env.PASSWORD) {
      credentials.push({ username: env.USERNAME, password: env.PASSWORD, capabilities: ["pull", "push"] });
    }
    if (env.READONLY_USERNAME && env.READONLY_PASSWORD) {
      credentials.push({ username: env.READONLY_USERNAME, password: env.READONLY_PASSWORD, capabilities: ["pull"] });
    }

    return new UserAuthenticator(credentials);
  }

  log.error("auth_method_misconfigured", {
    hint: "Either env.JWT_REGISTRY_TOKENS_PUBLIC_KEY must be set or both env.USERNAME, env.PASSWORD must be set or both env.READONLY_USERNAME, env.READONLY_PASSWORD must be set.",
  });

  // invalid configuration
  return undefined;
}
