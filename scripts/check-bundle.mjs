// Bundle budget for the production build (run after `npm run build`). Keeps the Step 1 page fast: its entry must stay
// small and the Security Twin graph (React + React Flow) must remain a lazily loaded chunk.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { ROOT } from "./app-harness.mjs";

/** Budgets in KiB (minified, uncompressed). Measured 2026-09-25: Step 1 entry 186.0, Step 2 48.6. */
export const BUDGETS = { "1-security-twin/app.js": 256, "2-test-lab/app.js": 96 };

const DIST = path.join(ROOT, "dist");
const kib = (file) => statSync(file).size / 1024;

export function checkBundles(dist = DIST) {
  const problems = [];
  const report = [];
  if (!existsSync(dist)) return { problems: ["dist/ not found: run `npm run build` first"], report };
  for (const [rel, budget] of Object.entries(BUDGETS)) {
    const file = path.join(dist, rel);
    if (!existsSync(file)) {
      problems.push(`${rel} is missing`);
      continue;
    }
    const size = kib(file);
    report.push(`${rel}: ${size.toFixed(1)} KiB (budget ${budget} KiB)`);
    if (size > budget) problems.push(`${rel} is ${size.toFixed(1)} KiB, over its ${budget} KiB budget`);
  }
  const entry = path.join(dist, "1-security-twin/app.js");
  const chunksDir = path.join(dist, "1-security-twin/chunks");
  if (existsSync(entry)) {
    const js = readFileSync(entry, "utf8");
    const chunks = existsSync(chunksDir) ? readdirSync(chunksDir).filter((f) => f.endsWith(".js")) : [];
    const lazy = chunks.filter((c) => js.includes(`import("./chunks/${c}")`));
    if (lazy.length !== 1) problems.push(`expected exactly one lazily imported graph chunk in the Step 1 entry, found ${lazy.length}`);
    for (const c of lazy) report.push(`1-security-twin/chunks/${c}: ${kib(path.join(chunksDir, c)).toFixed(1)} KiB (loaded on demand)`);
  }
  return { problems, report };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { problems, report } = checkBundles();
  for (const line of report) console.log(line);
  if (problems.length) {
    for (const p of problems) console.error(`bundle budget: ${p}`);
    process.exit(1);
  }
  console.log("bundle budget: ok");
}
