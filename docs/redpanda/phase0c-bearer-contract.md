# Phase 0c Bearer payload contract

How the auth Worker (Phase 0c) mints Bearer tokens that this registry validates. Source of truth for everyone implementing the auth side; the four features added in PRs [#1](https://github.com/redpanda-data/serverless-container-registry/pull/1) (algorithm), [#2](https://github.com/redpanda-data/serverless-container-registry/pull/2) (revocation), [#3](https://github.com/redpanda-data/serverless-container-registry/pull/3) (cache headers), and [#4](https://github.com/redpanda-data/serverless-container-registry/pull/4) (scope claims) implement the registry side of this contract.

Jira: [DEVPROD-4150](https://redpandadata.atlassian.net/browse/DEVPROD-4150) (Phase 0b — registry) and [DEVPROD-4151](https://redpandadata.atlassian.net/browse/DEVPROD-4151) (Phase 0c — auth Worker). Foundation in [DEVPROD-4149](https://redpandadata.atlassian.net/browse/DEVPROD-4149) (Phase 0a — keys, KV, DNS).

## Flow

```
                       docker pull registry.pkg.redpanda.com/cloudv2-production/oxla:v1
                                       │
                                       ▼
                       ┌────────────────────────────────────┐
                       │  registry (this Worker, Phase 0b)  │
                       │  401 + WWW-Authenticate: Bearer    │
                       │    realm=https://auth.pkg…/token   │
                       │    service=registry.pkg…           │
                       │    scope="repository:cloudv2-…:pull"│
                       └─────────────────┬──────────────────┘
                                         │
                                         ▼
                 GET /token?service=…&scope=…  (with cluster JWT as Bearer)
                                         │
                       ┌─────────────────▼──────────────────┐
                       │  auth Worker (Phase 0c)            │
                       │  1. validate cluster JWT (AWS KMS  │
                       │     RS256 — alias/dp-cluster-jwt-  │
                       │     signer)                        │
                       │  2. check KV `dp-auth-revocations` │
                       │     for the cluster JWT's jti      │
                       │  3. enforce scope policy: requested│
                       │     scope ⊆ cluster's allowed prefix│
                       │  4. mint short-lived registry      │
                       │     Bearer (this contract)         │
                       └─────────────────┬──────────────────┘
                                         │
                                         ▼
                       ┌────────────────────────────────────┐
                       │  client retries pull with Bearer   │
                       │  registry validates → 200 + stream │
                       └────────────────────────────────────┘
```

## Signing

|                                   |                                                                                                                                                 |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Algorithm                         | **RS256** (RSASSA-PKCS1-v1_5 with SHA-256)                                                                                                      |
| Key                               | `tls_private_key.rp_registry_bearer_signer` (RSA-2048), provisioned in Phase 0a                                                                 |
| Public key delivery               | Phase 0a TF output `rp_registry_bearer_signer_public_key_pem` (SPKI PEM) → derived JWK → base64 → registry env `JWT_REGISTRY_TOKENS_PUBLIC_KEY` |
| Algorithm wire-up on the registry | `JWT_REGISTRY_TOKENS_ALGORITHM=RS256` (PR #1)                                                                                                   |

## Claims

All times are seconds since epoch (RFC 7519).

| Claim          | Type               | Required | Notes                                                                                                                                                                                                    |
| -------------- | ------------------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `iss`          | string             | yes      | `https://auth.pkg.redpanda.com/`                                                                                                                                                                         |
| `aud`          | string             | yes      | `https://registry.pkg.redpanda.com/` (registry URL; matches the `service` from `WWW-Authenticate`)                                                                                                       |
| `sub`          | string             | yes      | Subject identifier. Format: `cluster:<cluster_id>`                                                                                                                                                       |
| `iat`          | int                | yes      | Issued at                                                                                                                                                                                                |
| `exp`          | int                | yes      | `iat + 900` (15 min). See [Lifetime](#lifetime).                                                                                                                                                         |
| `nbf`          | int                | no       | If set, must equal `iat`                                                                                                                                                                                 |
| `jti`          | string             | **yes**  | UUIDv4 or ULID. Required so revocation via KV is possible (PR #2).                                                                                                                                       |
| `username`     | string             | yes      | Literal `"v0"`. Upstream-shape compatibility — present for the existing `RegistryAuthProtocolTokenPayload` consumer in `src/token.ts`.                                                                   |
| `account_id`   | string             | yes      | Same value as `<cluster_id>` in `sub`. Upstream-shape compatibility.                                                                                                                                     |
| `capabilities` | string[]           | yes      | Coarse grant. Either `["pull"]` (pull-only cluster) or `["pull","push"]` (CI cluster). Distinct from `scope`.                                                                                            |
| `scope`        | string \| string[] | yes      | Fine-grained per-repository grant in Docker registry [token-scope syntax](https://distribution.github.io/distribution/spec/auth/scope/): `repository:<name>:<actions>`. See [Scope rules](#scope-rules). |

## Scope rules

The auth Worker MUST emit a `scope` claim that:

1. Matches the `scope` query parameter the client sent to `/token`, after the auth Worker's policy check passes.
2. Uses exact repository names — **no wildcards or prefixes**. PR #4 implements exact-name matching; a glob/prefix extension is a possible follow-up but is not in scope today.
3. May contain multiple `repository:<name>:<actions>` tokens, space-separated within a single string OR as an array of strings. The registry accepts both.
4. Restricts actions to those the cluster actually possesses (intersect requested scope with cluster's allowed actions). The registry enforces additionally via `capabilities`, so even an over-broad `scope` cannot grant more than the coarse capability.

**Example** — a cluster authorised to pull from the `cloudv2-production/*` namespace requesting `oxla:v1`:

```json
{
  "iss": "https://auth.pkg.redpanda.com/",
  "aud": "https://registry.pkg.redpanda.com/",
  "sub": "cluster:01HV7K9QXY5KFNT7M3PQ4Z2WJB",
  "iat": 1716412800,
  "exp": 1716413700,
  "jti": "8e3d1d9c-3e6c-4d59-bb86-1de0b3a6e4f7",
  "username": "v0",
  "account_id": "01HV7K9QXY5KFNT7M3PQ4Z2WJB",
  "capabilities": ["pull"],
  "scope": "repository:cloudv2-production/oxla:pull"
}
```

If the same pull warmed up a multi-repo prefetch and the auth Worker chose to issue one Bearer covering both:

```json
"scope": "repository:cloudv2-production/oxla:pull repository:cloudv2-production/connectors:pull"
```

## Lifetime

15 minutes. Rationale:

- Long enough that the auth round-trip is a once-per-pull-burst cost, not per-request.
- Short enough that natural expiry is a tolerable bound for revocation when KV propagation lags (~60 s typical, ~15 min p99 worst case — at p99 the token has already expired).
- The cluster JWT (separate, AWS-KMS-signed) is the long-lived 24 h credential. Bearer tokens are derived per-pull-burst and are not stored client-side beyond their expiry.

## Revocation

`jti` is required on every Bearer. The registry checks `dp-auth-revocations` KV (PR #2) on every JWT-authenticated request. To revoke:

1. Auth Worker writes the `jti` as a key in `dp-auth-revocations` KV with a TTL equal to the remaining time before `exp`. Value content is irrelevant — presence == revoked.
2. KV propagation: median ~60 s globally, p99 ~minutes; bounded by the Bearer's 15-min `exp` either way.
3. Operators can also revoke the cluster JWT (long-lived) by writing its `jti` to the same namespace; the auth Worker MUST consult this on every token mint.

## What the registry does NOT validate

Documented so the auth Worker side knows what to enforce upstream:

- `iss`: not checked by the registry. The auth Worker is the trust root; signature verification with the configured public key is sufficient.
- `nbf`: not checked. Optional only.
- `sub`: opaque to the registry. Used only for audit/observability.
- Cluster JWT chain: the registry never sees the cluster JWT — only the registry Bearer that the auth Worker minted from it.

## Test vectors

Once the auth Worker exists, end-to-end tests live in the auth Worker's repo. For the registry side, see `test/index.test.ts` for unit coverage of `verifyPayload` with and without `scope` (PR #4).
