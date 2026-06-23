import { prettifyError, ZodError } from "zod";

/**
 * Decode base64 that may be either standard (`+`/`/`) or URL-safe (`-`/`_`),
 * with or without `=` padding, into a one-byte-per-char binary string. `atob`
 * only accepts standard, correctly-padded base64, so normalize first — this
 * accepts both alphabets (RFC 7617 Basic credentials use standard base64;
 * some JWK / token encodings are URL-safe and unpadded). Throws on
 * structurally invalid input (callers are expected to try/catch).
 */
export function decodeBase64Loose(input: string): string {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const remainder = normalized.length % 4;
  if (remainder === 1) throw new Error("invalid base64 length");
  const padded = remainder === 0 ? normalized : normalized + "=".repeat(4 - remainder);
  return atob(padded);
}

export async function readableToBlob(
  reader: ReadableStreamDefaultReader,
  ...multiwriters: WritableStreamDefaultWriter[]
): Promise<Blob> {
  const blobs = [];
  while (true) {
    const value = await reader.read();
    if (value.done) break;
    blobs.push(value.value);
    const promises = [];
    for (const writer of multiwriters) {
      promises.push(writer.write(value.value));
    }

    await Promise.all(promises);
  }

  return new Blob(blobs);
}

export async function readerToBlob(readaleStream: ReadableStream, ...multiwriters: WritableStreamDefaultWriter[]) {
  const reader = readaleStream.getReader();
  const blobs = [];
  while (true) {
    const value = await reader.read();
    if (value.done) break;
    blobs.push(value.value);
    const promises = [];
    for (const writer of multiwriters) {
      promises.push(writer.write(value.value));
    }

    await Promise.all(promises);
  }

  return new Blob(blobs);
}

export async function consumeReadable(reader: ReadableStreamDefaultReader) {
  while (true) {
    const value = await reader.read();
    if (value.done) break;
  }
}

export function errorString(err: unknown): string {
  if (err instanceof ZodError) {
    return `zod error:\n${prettifyError(err)}`;
  }

  if (err instanceof Error) {
    return `error ${err.name}: ${err.message}: ${err.cause}: ${err.stack}`;
  }

  return "unknown error: " + JSON.stringify(err);
}

export async function wrap<T, E = unknown>(fn: Promise<T>): Promise<[T, null] | [null, E]> {
  return fn.then((data) => [data, null] as [T, null]).catch((err) => [null, err as unknown as E] as [null, E]);
}

export function jsonHeaders(): { "content-type": "application/json" } {
  return { "content-type": "application/json" };
}
