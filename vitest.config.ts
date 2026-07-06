import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./test/wrangler.test.jsonc", environment: "dev" },
    }),
  ],
  test: {
    silent: "passed-only",
    // push/ is a standalone Bun package with its own test runner (`bun test`,
    // run from push/); its *.test.ts files import "bun:test", which this
    // Workers-pool vitest run can't resolve.
    exclude: [...configDefaults.exclude, "push/**"],
  },
});
