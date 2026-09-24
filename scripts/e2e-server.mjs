// Playwright web server: build the production bundles, then serve dist/ from the same Node process.
// One process (no `npm run` or `&&` shell chain) so stopping it never leaves an orphaned server behind.
// E2E_SKIP_BUILD=1 reuses an existing dist/ (CI builds it in an earlier step).
import { existsSync } from "node:fs";
import path from "node:path";
import { ROOT } from "./app-harness.mjs";

if (process.env.E2E_SKIP_BUILD === "1") {
  if (!existsSync(path.join(ROOT, "dist", "1-security-twin", "app.js"))) {
    console.error("E2E_SKIP_BUILD=1 but dist/ has no build. Run `npm run build` first.");
    process.exit(1);
  }
} else {
  await import("./build.mjs");
}
await import("./serve.mjs");
