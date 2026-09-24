// Playwright web server: build the production bundles, then serve dist/ from the same Node process.
// One process (no `npm run` or `&&` shell chain) so stopping it never leaves an orphaned server behind.
await import("./build.mjs");
await import("./serve.mjs");
