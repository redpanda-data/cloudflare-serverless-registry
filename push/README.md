# Push chunked images to serverless-registry

This is a pretty simple tool that allows you to push docker images to serverless-registry
when the layers are too big.

## How to run

```bash
bun install
```

Then:

```bash
docker tag my-image:latest $IMAGE_URI
echo $PASSWORD | USERNAME_REGISTRY=<your-configured-username> bun run index.ts $IMAGE_URI
```

## How does it work

It exports the image using `docker save`, then pushes each layer to the registry.

Authentication starts as HTTP Basic (`Authorization: Basic base64(<username>:<password>)`). If the registry challenges a
request with `WWW-Authenticate: Bearer realm="...",service="..."` (Docker Registry v2
token-auth — this is what `registry.pkg.redpanda.com` does), the tool exchanges that
Basic credential for a scoped Bearer token at the challenge's realm and uses `Bearer`
for every request after, refreshing the token proactively before it expires. Against
registries that never send a Bearer challenge (e.g. the local `INSECURE_HTTP_PUSH`
prototype), it just keeps using Basic — no behavior change there.

For `registry.pkg.redpanda.com`, the username is always the literal `v0` and the
password is a cluster JWT minted via `go run ./tools/scripts/registry-auth mint ...`
from a `cloudv2` checkout (see that repo for the full command) — the username is
ignored by the registry, only the JWT-as-password matters.

It's able to chunk layers depending on the header `oci-chunk-max-length` returned by the registry when the client
creates an upload.

## Interesting output folders

- Every \*.tar in the push folder is the exported image from docker, which is extracted into `.cache`.
- Then it's compressed to gzip and saved into `.cache`. Files that end in `-ptr` have a digest in the content that
  refers to another layer in the folder.

There is a few more workarounds in the code like having to use node-fetch as Bun overrides the Content-Length
header from the caller.

This pushing tool is just a workaround on the Worker limitation in request body.

## Pushing locally

To push to a localhost registry you need to set the environment variable INSECURE_HTTP_PUSH=true.

## Other options?

If the reader is interested, there is more options or alternatives to have a faster pushing chunk tool:

1. We could redesign this tool to run with the Docker overlay storage. The biggest con is having to run a
   privileged docker container that uses https://github.com/justincormack/nsenter1 to access the Docker storage.

2. Create a localhost proxy that understands V2 registry protocol, and chunks things accordingly. The con is that
   docker has issues pushing to localhost registries.

3. Use podman like described in this [very informative Github comment](https://github.com/cloudflare/serverless-registry/issues/42#issuecomment-2366997382).

## Improvements

1. Use zstd instead.
2. Have a better unit test suite.
