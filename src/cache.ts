/**
 * Cache-Control + Workers Cache API helpers for the registry's read paths.
 *
 * Why this exists: by default, the Worker runtime does not populate
 * Cloudflare's edge cache for dynamic Worker responses. Pulls therefore
 * traverse Worker -> R2 on every request, which is correct but adds
 * 50-200 ms of R2 latency per blob fetch. For a registry whose blob URLs
 * are content-addressed (sha256 digest in path), edge caching is safe and
 * removes that latency on warm paths.
 *
 * The OCI Distribution spec encourages:
 *   - short cache TTL for tag/manifest endpoints (tag content can change)
 *   - long, immutable cache TTL for blob endpoints (digest fully identifies bytes)
 *
 * This module centralises those values + the cache.default.match/put logic.
 */
export const MANIFEST_CACHE_MAX_AGE_SECONDS = 60;
export const BLOB_CACHE_MAX_AGE_SECONDS = 31536000; // 1 year

/**
 * Workers Cache API per-entry size cap. Cloudflare documents 512 MiB as the
 * maximum cacheable object size on the standard plan; blobs above this fall
 * back to direct R2 streaming with the long Cache-Control still set, so the
 * client may cache locally even though the edge will not.
 */
export const BLOB_CACHE_PER_ENTRY_BYTE_LIMIT = 512 * 1024 * 1024;

/**
 * Build the `ETag` value from an OCI digest. Wrapping in quotes is required
 * by RFC 7232 strong-validator syntax; the digest itself is already an
 * opaque content identifier.
 */
export function etagFromDigest(digest: string): string {
  return `"${digest}"`;
}

/** Build cache headers for manifest responses (short TTL, tag may move). */
export function manifestCacheHeaders(digest: string): Record<string, string> {
  return {
    "Cache-Control": `public, max-age=${MANIFEST_CACHE_MAX_AGE_SECONDS}`,
    "ETag": etagFromDigest(digest),
  };
}

/** Build cache headers for blob responses (long TTL, content-addressed). */
export function blobCacheHeaders(digest: string): Record<string, string> {
  return {
    "Cache-Control": `public, max-age=${BLOB_CACHE_MAX_AGE_SECONDS}, immutable`,
    "ETag": etagFromDigest(digest),
  };
}

/**
 * If the client sent `If-None-Match` and the digest matches, return a 304
 * response with the cache headers re-set. Otherwise returns null and the
 * caller should serve the full response.
 *
 * Saves a Worker -> R2 byte transfer when the client already has the bytes
 * (warm `docker pull`).
 */
export function maybeNotModified(
  request: Request,
  digest: string,
  headersFn: (digest: string) => Record<string, string>,
): Response | null {
  const ifNoneMatch = request.headers.get("If-None-Match");
  if (ifNoneMatch && ifNoneMatch === etagFromDigest(digest)) {
    return new Response(null, { status: 304, headers: headersFn(digest) });
  }
  return null;
}

/**
 * Build the Workers Cache API key for a given request.
 *
 * **GET-only.** The returned key hardcodes `method: "GET"` so it cannot be
 * used from a HEAD handler — `caches.default.match` would happily return the
 * cached GET body, which a HEAD response must not include. If a future HEAD
 * caller wants to consult the same cache, it needs its own helper that
 * strips the body off the cached Response, not this one.
 *
 * We deliberately normalise to the request URL only (no Authorization in the
 * key): the registry's auth gate runs before the route handler and blobs are
 * content-addressed, so sharing one cached entry across authorised callers is
 * correct and required to actually get HIT behaviour. Honouring this is also
 * why blob responses must NOT set `Vary: Authorization`.
 */
export function cacheKeyForRequest(request: Request): Request {
  return new Request(request.url, { method: "GET" });
}

/**
 * Try to serve from Workers Cache. Returns null on miss.
 *
 * GET-only — see {@link cacheKeyForRequest}. Calling this from a HEAD handler
 * would serve the cached GET body as the HEAD response, which is wrong.
 */
export async function tryServeFromEdgeCache(request: Request): Promise<Response | null> {
  const cached = await caches.default.match(cacheKeyForRequest(request));
  return cached ?? null;
}

/**
 * Push a response into Workers Cache asynchronously. Caller must pass a
 * cloneable response (i.e. clone() the streamed one before returning it to
 * the user). Honours BLOB_CACHE_PER_ENTRY_BYTE_LIMIT — entries above the
 * cap are skipped (we still set Cache-Control on the user-facing response
 * so client-side caches can store them).
 */
export function populateEdgeCache(request: Request, response: Response, size: number, context: ExecutionContext): void {
  if (size > BLOB_CACHE_PER_ENTRY_BYTE_LIMIT) {
    return;
  }
  context.waitUntil(caches.default.put(cacheKeyForRequest(request), response));
}
