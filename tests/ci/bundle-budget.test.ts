import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { BUDGETS, checkBundles } from "../../scripts/check-bundle.mjs";

let dir: string | undefined;
afterEach(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
  dir = undefined;
});

/** A fake dist/ with a Step 1 entry of `entryKiB` that optionally lazy-imports a graph chunk. */
function fakeDist({ entryKiB = 10, lazyChunk = true } = {}) {
  dir = mkdtempSync(path.join(tmpdir(), "sx-dist-"));
  mkdirSync(path.join(dir, "1-security-twin/chunks"), { recursive: true });
  mkdirSync(path.join(dir, "2-test-lab"), { recursive: true });
  const importLine = lazyChunk ? 'import("./chunks/mount-ABC.js");' : "";
  writeFileSync(path.join(dir, "1-security-twin/app.js"), importLine + "x".repeat(entryKiB * 1024));
  writeFileSync(path.join(dir, "1-security-twin/chunks/mount-ABC.js"), "graph");
  writeFileSync(path.join(dir, "2-test-lab/app.js"), "y");
  return dir;
}

describe("bundle budget", () => {
  it("passes a small entry with one lazily imported chunk", () => {
    expect(checkBundles(fakeDist()).problems).toEqual([]);
  });

  it("fails when the Step 1 entry exceeds its budget", () => {
    const over = BUDGETS["1-security-twin/app.js"]! + 1;
    expect(checkBundles(fakeDist({ entryKiB: over })).problems.join("\n")).toMatch(/1-security-twin\/app\.js is .* over its \d+ KiB budget/);
  });

  it("fails when the graph is no longer lazy-loaded", () => {
    expect(checkBundles(fakeDist({ lazyChunk: false })).problems.join("\n")).toMatch(/exactly one lazily imported graph chunk.*found 0/);
  });

  it("fails when there is no build", () => {
    expect(checkBundles(path.join(tmpdir(), "sx-no-such-dist")).problems).toEqual(["dist/ not found: run `npm run build` first"]);
  });
});
