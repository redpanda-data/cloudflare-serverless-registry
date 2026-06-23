import type { State } from "./registry/r2";
import { actionForMethod, repositoryNameFromUrl } from "./auth";

/**
 * Is `v` safe to interpolate into the `WWW-Authenticate` quoted-string? Rejects
 * control characters (CR/LF/TAB/etc.) and `"`/`\`, any of which would break the
 * header or throw when the `Headers` object is constructed, and requires an
 * absolute URL. A misconfigured `REGISTRY_TOKEN_REALM` must not turn every 401
 * into a 500 / malformed challenge and take auth down entirely — callers fall
 * back to the Basic challenge instead.
 */
function isValidRealm(v: string): boolean {
  // The ORIGINAL string is interpolated into the header (not a normalized
  // serialization), so require printable ASCII only: reject controls, space,
  // DEL, and any non-ASCII (e.g. IDN/Unicode hostnames that would need
  // percent-encoding or throw when the Headers object is built), plus `"`/`\`
  // which would break the quoted-string.
  for (let i = 0; i < v.length; i++) {
    const c = v.charCodeAt(i);
    if (c < 0x21 || c > 0x7e || v[i] === '"' || v[i] === "\\") return false;
  }
  // Require the `https://` authority form explicitly: `new URL` would otherwise
  // accept authority-less inputs like `https:token` (normalized to a bare host)
  // that are never a usable token endpoint.
  if (!v.startsWith("https://")) return false;
  try {
    const u = new URL(v);
    // Require https (a non-TLS token endpoint would carry the cluster JWT and
    // the minted bearer in plaintext), a non-empty host, and no embedded
    // userinfo (a `user:pass@host` realm would leak those credentials to every
    // client in the WWW-Authenticate header). Anything else falls back to Basic.
    return u.protocol === "https:" && u.hostname !== "" && u.username === "" && u.password === "";
  } catch {
    return false;
  }
}

/**
 * Build the `WWW-Authenticate` challenge for a 401.
 *
 * When `tokenRealm` is set (Redpanda deploys via REGISTRY_TOKEN_REALM), emit a
 * Docker Registry v2 Bearer challenge so standard OCI clients run the
 * token-auth flow: hit the realm, exchange their credential for a scoped
 * Bearer, retry. `service` is this registry's own host; `scope` is the
 * per-operation repository:<name>:<action> derived from the request (omitted
 * for non-repository endpoints like `/v2/`, where the client logs in with no
 * scope). When `tokenRealm` is unset or invalid, fall back to upstream Basic
 * behavior.
 */
function wwwAuthenticate(r: Request, tokenRealm?: string): string {
  if (!tokenRealm || !isValidRealm(tokenRealm)) return `Basic realm="${r.url}"`;
  // Use the hostname WITHOUT the port: the token-auth `service` value is matched
  // against a fixed, portless service identifier on the auth server, so emitting
  // `host:443` here would make the client's token request fail to validate.
  const service = new URL(r.url).hostname;
  let challenge = `Bearer realm="${tokenRealm}",service="${service}"`;
  const repo = repositoryNameFromUrl(r.url);
  const action = actionForMethod(r.method);
  if (repo !== null && action !== null) {
    challenge += `,scope="repository:${repo}:${action}"`;
  }
  return challenge;
}

export class AuthErrorResponse extends Response {
  constructor(r: Request, tokenRealm?: string) {
    const jsonBody = JSON.stringify({
      errors: [
        {
          code: "UNAUTHORIZED",
          message: "authentication required",
          detail: null,
        },
      ],
    });
    const init = {
      status: 401,
      headers: {
        "content-type": "application/json;charset=UTF-8",
        "WWW-Authenticate": wwwAuthenticate(r, tokenRealm),
      },
    };
    super(jsonBody, init);
  }
}

export class RangeError extends Response {
  constructor(stateHash: string, state: State) {
    super(
      JSON.stringify({
        errors: [
          {
            code: "RANGE_ERROR",
            message: `stateHash ${stateHash} does not match state (upload id: ${state.registryUploadId})`,
            detail: {
              ...state,
              string: stateHash,
            },
          },
        ],
      }),
      {
        status: 416,
        headers: {
          "Location": `/v2/${state.name}/blobs/uploads/${state.registryUploadId}?_stateHash=${stateHash}`,
          "Range": `0-${state.byteRange - 1}`,
          "Docker-Upload-UUID": state.registryUploadId,
        },
      },
    );
  }
}

export class InternalError extends Response {
  constructor() {
    const jsonBody = JSON.stringify({
      errors: [
        {
          code: "INTERNAL_ERROR",
          message: "internal error",
          detail: null,
        },
      ],
    });
    const init = {
      status: 500,
      headers: {
        "content-type": "application/json;charset=UTF-8",
      },
    };
    super(jsonBody, init);
  }
}

export class ManifestError extends Response {
  constructor(
    code: "MANIFEST_INVALID" | "BLOB_UNKNOWN" | "MANIFEST_UNVERIFIED" | "TAG_INVALID" | "NAME_INVALID",
    message: string,
    detail: Record<string, string> = {},
  ) {
    const jsonBody = JSON.stringify({
      errors: [
        {
          code,
          message,
          detail,
        },
      ],
    });
    super(jsonBody, {
      status: 400,
      headers: {
        "content-type": "application/json;charset=UTF-8",
      },
    });
  }
}

export class ServerError extends Response {
  constructor(message: string, errorCode = 500) {
    super(JSON.stringify({ errors: [{ code: "SERVER_ERROR", message, detail: null }] }), {
      status: errorCode,
      headers: { "content-type": "application/json;charset=UTF-8" },
    });
  }
}
