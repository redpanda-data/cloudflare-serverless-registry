import { Env } from "..";
import { newRegistryTokens, parseJwtAlgorithm } from "./token";
import { UserAuthenticator } from "./user";
import type { AuthenticatorCredentials } from "./user";

export async function authenticationMethodFromEnv(env: Env) {
  if (env.JWT_REGISTRY_TOKENS_PUBLIC_KEY) {
    // Fail closed on a typo in JWT_REGISTRY_TOKENS_ALGORITHM. Letting the
    // throw escape would surface as an unhandled 500 (the caller invokes
    // this outside the request try/catch in index.ts); a misconfigured
    // algorithm should look like "auth not configured" instead.
    let algorithm;
    try {
      algorithm = parseJwtAlgorithm(env.JWT_REGISTRY_TOKENS_ALGORITHM);
    } catch (err) {
      console.error(
        `authenticationMethodFromEnv: ${(err as Error).message}. JWT authentication is disabled until corrected.`,
      );
      return undefined;
    }
    return await newRegistryTokens(env.JWT_REGISTRY_TOKENS_PUBLIC_KEY, algorithm, env.JWT_REGISTRY_TOKENS_DENY_LIST);
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

  console.error(
    "Either env.JWT_REGISTRY_TOKENS_PUBLIC_KEY must be set or both env.USERNAME, env.PASSWORD must be set or both env.READONLY_USERNAME, env.READONLY_PASSWORD must be set.",
  );

  // invalid configuration
  return undefined;
}
