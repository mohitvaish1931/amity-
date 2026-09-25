// Guards the CI configuration itself: it must run the same pipeline as `npm run check`,
// reproducibly, with pinned actions and without secrets.
import { describe, expect, it } from "vitest";
import { parse } from "yaml";
import { readRepoFile } from "../helpers";

interface Step {
  name?: string;
  id?: string;
  if?: string;
  uses?: string;
  run?: string;
  with?: Record<string, unknown>;
  env?: Record<string, string>;
}

const raw = readRepoFile(".github/workflows/ci.yml");
const wf = parse(raw) as {
  on: Record<string, unknown>;
  permissions: Record<string, string>;
  jobs: Record<string, { "runs-on": string; "timeout-minutes": number; steps: Step[] }>;
};
const steps = Object.values(wf.jobs)[0]!.steps;
const pkg = JSON.parse(readRepoFile("package.json")) as { engines: { node: string }; scripts: Record<string, string> };

describe("GitHub Actions workflow", () => {
  it("runs on push and pull_request with read-only permissions", () => {
    expect(Object.keys(wf.on).sort()).toEqual(["pull_request", "push"]);
    expect(wf.permissions).toEqual({ contents: "read" });
    expect(Object.values(wf.jobs)[0]!["timeout-minutes"]).toBeGreaterThan(0);
  });

  it("installs with npm ci and never npm install", () => {
    const runs = steps.map((s) => s.run ?? "").join("\n");
    expect(runs).toMatch(/^npm ci$/m);
    expect(runs).not.toMatch(/npm (install|i)\b/);
  });

  it("runs typecheck → lint → test → build in order, each gated only on a successful install", () => {
    const order = ["install", "typecheck", "lint", "test", "build"];
    expect(steps.filter((s) => s.id && order.includes(s.id)).map((s) => s.id)).toEqual(order);
    const byId = Object.fromEntries(steps.filter((s) => s.id).map((s) => [s.id!, s]));
    expect(byId.typecheck!.run).toBe("npm run typecheck");
    expect(byId.lint!.run).toBe("npm run lint");
    expect(byId.test!.run).toBe("npm run test:ci");
    expect(byId.build!.run).toBe("npm run build");
    for (const id of ["typecheck", "lint", "test", "build"]) {
      expect(byId[id]!.if).toBe("${{ !cancelled() && steps.install.outcome == 'success' }}");
    }
  });

  it("checks the bundle budget right after a successful build", () => {
    const order = ["build", "budget", "pwinstall"];
    expect(steps.filter((s) => s.id && order.includes(s.id)).map((s) => s.id)).toEqual(order);
    const budget = steps.find((s) => s.id === "budget")!;
    expect(budget.run).toBe("npm run check:bundle");
    expect(budget.if).toBe("${{ !cancelled() && steps.build.outcome == 'success' }}");
    expect(steps.find((s) => s.name === "Summary")!.run).toContain("| Bundle budget |");
  });

  it("runs Playwright E2E on the CI production build, after installing Chromium with its system dependencies", () => {
    const order = ["build", "pwinstall", "e2e"];
    expect(steps.filter((s) => s.id && order.includes(s.id)).map((s) => s.id)).toEqual(order);
    const byId = Object.fromEntries(steps.filter((s) => s.id).map((s) => [s.id!, s]));
    expect(byId.pwinstall!.run).toBe("npx playwright install --with-deps chromium");
    expect(byId.pwinstall!.if).toBe("${{ !cancelled() && steps.build.outcome == 'success' }}");
    expect(byId.e2e!.run).toBe("npm run test:e2e");
    expect(byId.e2e!.if).toBe("${{ !cancelled() && steps.build.outcome == 'success' && steps.pwinstall.outcome == 'success' }}");
    // Reuse the build from the Build step (no second build) and run on Playwright's own Chromium.
    expect(byId.e2e!.env).toEqual({ E2E_SKIP_BUILD: "1", PW_CHANNELS: "chromium" });
    expect(readRepoFile("scripts/e2e-server.mjs")).toMatch(/E2E_SKIP_BUILD === "1"/);
  });

  it("uploads the Playwright report and traces only when E2E fails", () => {
    const upload = steps.find((s) => s.name === "Upload Playwright report")!;
    expect(upload.if).toBe("${{ !cancelled() && steps.e2e.outcome == 'failure' }}");
    expect(String(upload.with!.path)).toMatch(/playwright-report\/[\s\S]*test-results\//);
    const config = readRepoFile("playwright.config.ts");
    expect(config).toMatch(/process\.env\.CI[\s\S]*"html"[\s\S]*"junit"/);
    expect(config).toMatch(/reuseExistingServer: false/);
    const ignore = readRepoFile(".gitignore");
    expect(ignore).toMatch(/^playwright-report\/$/m);
    expect(ignore).toMatch(/^test-results\/$/m);
    expect(steps.find((s) => s.name === "Summary")!.env).toMatchObject({ E2E: "${{ steps.e2e.outcome }}" });
  });

  it("pins every action to a full commit SHA", () => {
    const uses = steps.filter((s) => s.uses).map((s) => s.uses!);
    expect(uses.length).toBeGreaterThan(0);
    for (const u of uses) expect(u).toMatch(/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/);
    expect(raw).toMatch(/actions\/checkout@[0-9a-f]{40} # v\d+/);
  });

  it("does not use or embed secrets", () => {
    expect(raw).not.toMatch(/secrets\./);
    expect(raw).not.toMatch(/(api[_-]?key|token|password|passwd|bearer)\s*[:=]/i);
    const checkout = steps.find((s) => s.uses?.startsWith("actions/checkout@"))!;
    expect(checkout.with).toMatchObject({ "persist-credentials": false });
  });

  it("takes the Node version from .nvmrc, consistent with package.json engines", () => {
    const setup = steps.find((s) => s.uses?.startsWith("actions/setup-node@"))!;
    expect(setup.with).toMatchObject({ "node-version-file": ".nvmrc", cache: "npm" });
    const nvmrc = readRepoFile(".nvmrc").trim();
    const engineMajor = /(\d+)\./.exec(pkg.engines.node)![1];
    expect(nvmrc).toBe(engineMajor);
  });

  it("keeps the test report and writes a result summary even on failure", () => {
    const upload = steps.find((s) => s.uses?.startsWith("actions/upload-artifact@"))!;
    expect(upload.with).toMatchObject({ path: "reports/" });
    expect(pkg.scripts["test:ci"]).toContain("--outputFile.junit=reports/junit.xml");
    expect(readRepoFile(".gitignore")).toMatch(/^reports\/$/m);
    const summary = steps.find((s) => s.name === "Summary")!;
    expect(summary.if).toBe("${{ always() }}");
    expect(summary.run).toContain("GITHUB_STEP_SUMMARY");
  });
});

describe("package scripts", () => {
  it("npm run check chains the same stages as CI, without duplicating their commands", () => {
    expect(pkg.scripts.check).toBe("npm run typecheck && npm run lint && npm run test && npm run build && npm run check:bundle");
    expect(pkg.scripts["check:bundle"]).toBe("node scripts/check-bundle.mjs");
    expect(pkg.scripts["test:ci"]).toMatch(/^vitest run /);
    expect(pkg.scripts.test).toBe("vitest run");
  });
});

describe(".gitattributes", () => {
  it("normalizes text to LF and leaves binaries alone", () => {
    const attrs = readRepoFile(".gitattributes");
    expect(attrs).toMatch(/^\* text=auto eol=lf$/m);
    expect(attrs).toMatch(/^\*\.png binary$/m);
  });
});
