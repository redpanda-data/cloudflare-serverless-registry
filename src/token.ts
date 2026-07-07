import jwt from "@tsndr/cloudflare-worker-jwt";
import { decodeBase64Loose } from "./utils";
import {
  RegistryTokenCapability,
  RegistryAuthProtocolTokenPayload,
  stripUsernamePasswordFromHeader,
  bearerTokenFromHeader,
  Authenticator,
  actionForMethod,
  parseScopeClaim,
  repositoryNameFromUrl,
} from "./auth";
import { log } from "./log";

export function importKeyFromBase64(key: string): JsonWebKeyWithKid {
  // The key is a STANDARD base64-encoded JWK (e.g. produced by Python's
  // base64.b64encode, which uses `+`/`/`), so decode with `atob` — a base64url
  // decoder rejects those characters and could fail to load a valid key. The
  // JWK JSON is ASCII, so the one-byte-per-char `atob` result parses directly.
  // The library's `JsonWebKeyWithKid` type requires `kid`, but ES256/HS256 sign
  // and verify only need the key material at runtime, so casting is safe.
  return JSON.parse(decodeBase64Loose(key)) as JsonWebKeyWithKid;
}

// Algorithms accepted by `@tsndr/cloudflare-worker-jwt` that produce signatures
// supported by `crypto.subtle` in Workers. Keep this list narrow so the env
// variable can't enable HMAC modes by mistake (an HMAC public key is the
// signing key — a misconfiguration there is a silent auth bypass).
export const SUPPORTED_JWT_ALGORITHMS = ["ES256", "ES384", "ES512", "RS256", "RS384", "RS512"] as const;
export type JwtAlgorithm = (typeof SUPPORTED_JWT_ALGORITHMS)[number];

export const DEFAULT_JWT_ALGORITHM: JwtAlgorithm = "ES256";

export function parseJwtAlgorithm(value: string | undefined): JwtAlgorithm {
  if (value === undefined || value === "") return DEFAULT_JWT_ALGORITHM;
  if ((SUPPORTED_JWT_ALGORITHMS as readonly string[]).includes(value)) return value as JwtAlgorithm;
  throw new Error(
    `unsupported JWT_REGISTRY_TOKENS_ALGORITHM "${value}"; expected one of ${SUPPORTED_JWT_ALGORITHMS.join(", ")}`,
  );
}

export async function newRegistryTokens(
  jwtPublicKey: string,
  algorithm: JwtAlgorithm = DEFAULT_JWT_ALGORITHM,
  denyListKV?: KVNamespace,
): Promise<RegistryTokens> {
  return new RegistryTokens(importKeyFromBase64(jwtPublicKey), algorithm, denyListKV);
}

export class RegistryTokens implements Authenticator {
  private jwtPublicKey: JsonWebKeyWithKid;
  private algorithm: JwtAlgorithm;
  private denyListKV?: KVNamespace;
  authmode: string;

  constructor(
    jwtPublicKey: JsonWebKeyWithKid,
    algorithm: JwtAlgorithm = DEFAULT_JWT_ALGORITHM,
    denyListKV?: KVNamespace,
  ) {
    this.authmode = "RegistryTokens";
    this.jwtPublicKey = jwtPublicKey;
    this.algorithm = algorithm;
    this.denyListKV = denyListKV;
  }

  /**
   * Very util function that showcases how do we generate private and public keys
   *
   * @example
   *    // Sample usage:
   *    try {
   *      const [privateKey, publicKey] = await RegistryTokens.createPrivateAndPublicKey();
   *      const registryTokens = await newRegistryTokens(publicKey);
   *      const token = await registryTokens.createToken("some-account-id", ["pull", "push"], 30, privateKey, "https://hello.com");
   *      const result = await registryTokens.verifyToken(request, token);
   *      console.log(JSON.stringify(result));
   *    } catch (err) {
   *      console.log("Error generating keys:", err.message);
   *    }
   */
  static async createPrivateAndPublicKey(): Promise<[string, string]> {
    const key = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const exportedPrivateKey = btoa(JSON.stringify(await crypto.subtle.exportKey("jwk", key.privateKey)));
    const exportedPublicKey = btoa(JSON.stringify(await crypto.subtle.exportKey("jwk", key.publicKey)));
    return [exportedPrivateKey, exportedPublicKey];
  }

  async createToken(
    accountID: string,
    caps: RegistryTokenCapability[],
    expirationMinutes: number,
    privateKeyString: string,
    registryUrl: string,
  ): Promise<string> {
    const privateKey = importKeyFromBase64(privateKeyString);
    // password is the signed JWT from the tokenPayload. Clients would treat this as an opaque identifier
    const tokenPayload: RegistryAuthProtocolTokenPayload = {
      username: "v0",
      account_id: accountID,
      capabilities: caps,
      exp: Math.floor(Date.now() / 1000) + 60 * expirationMinutes,
      aud: registryUrl,
    };

    const token = await jwt.sign(tokenPayload, privateKey, {
      algorithm: this.algorithm,
    });

    return token;
  }

  static checkIfV2OnlyPath(request: Request): boolean {
    let pathname: string;
    try {
      pathname = new URL(request.url).pathname;
    } catch {
      return false;
    }
    // Tolerate a query string and an optional trailing slash so a `/v2` or
    // `/v2/?...` probe is still recognised as the version endpoint (the
    // bare `endsWith("/v2/")` check missed both).
    return pathname === "/v2/" || pathname === "/v2";
  }

  async verifyToken(
    request: Request,
    token: string,
  ): Promise<{
    verified: boolean;
    payload: RegistryAuthProtocolTokenPayload | null;
  }> {
    try {
      // first verify the JWT
      if (!(await jwt.verify(token, this.jwtPublicKey, { algorithm: this.algorithm }))) {
        log.warn("jwt_verify_failed", { reason: "signature_invalid" });
        return { verified: false, payload: null };
      }

      // the JWT signature is valid, decode it now
      const decoded = jwt.decode(token);
      const payload = decoded.payload as RegistryAuthProtocolTokenPayload;

      // Run the payload check (exp, capabilities, scope) before consulting
      // the deny-list KV. Expired or capability-mismatched tokens would be
      // rejected anyway; doing the KV read for them is a wasted hop on the
      // hot path, and the KV path costs more than a same-isolate timestamp
      // compare.
      const payloadResult = RegistryTokens.verifyPayload(request, payload);
      if (!payloadResult.verified) {
        return payloadResult;
      }

      // Revocation check: if a deny-list KV is bound and the token carries
      // a `jti`, reject when the JTI is present in the deny-list. Operators
      // can set any KV value (we don't read it — presence == revoked) and
      // optionally use the TTL on the KV entry to expire it automatically
      // alongside the JWT's `exp`. Tokens without a `jti` cannot be revoked
      // out-of-band and fall back to natural expiry only.
      if (this.denyListKV && payload.jti) {
        const revoked = await this.denyListKV.get(payload.jti, "text");
        if (revoked !== null) {
          log.warn("jwt_revoked", { jti: payload.jti });
          return { verified: false, payload: null };
        }
      }

      return payloadResult;
    } catch (error) {
      // If the verification fails (e.g., due to token expiration or signature mismatch),
      // jwt.verify() will throw an error which we can catch here.

      // We could throw this error further up to allow more specific error handling,
      // or simply return {verified: false, payload: null  }to indicate token verification failure.
      log.warn("jwt_verify_error", { message: (error as Error).message });
      return { verified: false, payload: null };
    }
  }

  static verifyPayload(request: Request, payload: RegistryAuthProtocolTokenPayload) {
    // Check if token has expired
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && now >= payload.exp) {
      // The token has expired
      log.warn("jwt_expired", { exp: payload.exp ?? null });
      return { verified: false, payload: null };
    }

    // Optional fine-grained scope check (Docker Registry token-scope syntax).
    // If the JWT carries a `scope` claim, the request's repository name AND
    // the action implied by the HTTP method must be authorised by at least
    // one scope token. This runs IN ADDITION to the `capabilities` check
    // below — both must pass — so a misconfigured issuer can't widen access
    // by emitting an over-broad scope.
    if (payload.scope !== undefined) {
      const scopes = parseScopeClaim(payload.scope);
      const repo = repositoryNameFromUrl(request.url, request.method);
      const action = actionForMethod(request.method);
      // A token that carries a `scope` claim is confined to (a) the `/v2/`
      // version probe and (b) the repositories its scope names. There is no
      // `allowed_repos` notion on the registry side, so the scope claim is the
      // only per-repository authorization signal — anything outside it must
      // fail closed.
      if (RegistryTokens.checkIfV2OnlyPath(request)) {
        // Version probe carries no repository; fall through to the capability
        // check below. This is what `docker login` hits (with an empty-scope
        // token minted for a no-scope request).
      } else if (repo === null) {
        // A non-repository endpoint that is not the version probe — notably
        // `/v2/_catalog`, which enumerates the whole R2 bucket. A scope-claimed
        // token must not reach it, or a token scoped to one repository could
        // list every tenant's repositories (cross-tenant disclosure).
        log.warn("scope_denied_non_repository_endpoint", { url: request.url });
        return { verified: false, payload: null };
      } else if (action !== null) {
        // The Docker token-scope syntax allows "*" as an actions wildcard
        // (e.g. `repository:foo:*` == any action on foo). Treat it the same
        // as the requested action being present in `actions`. An empty scope
        // (login-probe token) parses to zero scopes and therefore matches no
        // repository — failing closed here.
        const allowed = scopes.some(
          (s) => s.type === "repository" && s.name === repo && (s.actions.includes(action) || s.actions.includes("*")),
        );
        if (!allowed) {
          log.warn("scope_denied", { action, repo });
          return { verified: false, payload: null };
        }
      }
    }

    // ensure capabilities are satisfied
    switch (request.method) {
      // PULL or PUSH methods
      case "HEAD":
        // HEAD requests can be used by pushers like docker
        if (!payload.capabilities.includes("pull") && !payload.capabilities.includes("push")) {
          log.warn("jwt_capability_denied", { method: request.method, url: request.url, reason: "missing_any_capability" });
          return { verified: false, payload: null };
        }
        break;
      // PULL method
      case "GET":
        if (this.checkIfV2OnlyPath(request) && payload.capabilities.length === 0) {
          log.warn("jwt_capability_denied", { method: request.method, url: request.url, reason: "no_capabilities_for_v2" });
          return { verified: false, payload: null };
        }

        if (this.checkIfV2OnlyPath(request)) {
          return { verified: true, payload };
        }

        if (!payload.capabilities.includes("pull")) {
          log.warn("jwt_capability_denied", { method: request.method, url: request.url, required: "pull" });
          return { verified: false, payload: null };
        }
        break;

      // PUSH methods
      case "POST":
      case "PUT":
      case "DELETE":
      case "PATCH":
        if (!payload.capabilities.includes("push")) {
          log.warn("jwt_capability_denied", { method: request.method, required: "push" });
          return { verified: false, payload: null };
        }
        break;
      default:
        return { verified: false, payload: null };
    }

    return { verified: true, payload };
  }

  async checkCredentials(request: Request): Promise<{
    verified: boolean;
    payload: RegistryAuthProtocolTokenPayload | null;
  }> {
    // Docker Registry v2 token-auth: the client presents the scoped registry
    // JWT as `Authorization: Bearer <token>`. Verify it through the same path
    // as the Basic-password JWT.
    const bearer = bearerTokenFromHeader(request);
    if (bearer !== null) {
      return this.verifyToken(request, bearer);
    }

    const res = stripUsernamePasswordFromHeader(request);
    if ("verified" in res) {
      return res;
    }

    const [, password] = res;
    return this.verifyToken(request, password);
  }
}
