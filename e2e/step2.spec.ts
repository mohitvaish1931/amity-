// End-to-end tests for Step 2 (Test Lab) on the production build. Purely local: the only requests allowed are the
// app's own assets; the one live-mode test aborts its requests inside the browser (page.route), so nothing is sent.
import { expect, test, type Page } from "@playwright/test";

const APP = "/2-test-lab/";

function watch(page: Page) {
  const consoleErrors: string[] = [];
  const requests: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error") consoleErrors.push(m.text());
  });
  page.on("pageerror", (e) => consoleErrors.push(e.message));
  page.on("request", (r) => requests.push(r.url()));
  return { consoleErrors, requests };
}
const appAssets = (requests: string[], origin: string) => requests.filter((u) => !u.startsWith("data:") && !u.startsWith(`${origin}${APP}`));

async function planDemo(page: Page, mode: "mock" | "live" = "mock") {
  await page.goto(APP);
  await page.getByRole("button", { name: "Load Demo Model" }).click();
  await expect(page.locator("#modelStatus")).toContainText("Demo model loaded");
  await page.getByLabel("Executor:").selectOption(mode);
  await page.getByRole("button", { name: "[ PLAN TESTS ]" }).click();
  await expect(page.locator("#modelStatus")).toContainText("Planned 22 test cases");
}
const bar = (page: Page) => page.getByRole("region", { name: "Target and run status" });

test.describe("Step 2: plan and inspect", () => {
  test("plans the demo model, and test cases are selectable by keyboard", async ({ page, baseURL }) => {
    const seen = watch(page);
    await planDemo(page);
    const cards = page.locator("#tests .test");
    await expect(cards).toHaveCount(22);
    await expect(bar(page)).toContainText("0/22 tests run");
    // keyboard: focus the third card and press Enter
    const third = cards.nth(2);
    const id = await third.getAttribute("data-t");
    await third.focus();
    await page.keyboard.press("Enter");
    const selected = page.locator(`#tests .test[data-t="${id}"]`);
    await expect(selected).toHaveAttribute("aria-pressed", "true");
    await expect(selected).toBeFocused();
    await expect(page.locator("#preview")).toContainText(`Preview ${id}`);
    await expect(page.locator("#preview")).toContainText("EXPECTED:");
    expect(seen.consoleErrors).toEqual([]);
    expect(appAssets(seen.requests, new URL(baseURL!).origin)).toEqual([]);
  });
});

test.describe("Step 2: mock runs are simulations", () => {
  test("a mock run labels every result and finding SIMULATED and never CONFIRMED", async ({ page, baseURL }) => {
    const seen = watch(page);
    await planDemo(page);
    await page.getByRole("button", { name: "RUN ALL" }).click();
    await expect(bar(page)).toContainText("22/22 tests run", { timeout: 20_000 });
    await expect(page.getByRole("button", { name: "RUN ALL" })).toBeEnabled();
    const findings = page.locator("#findings");
    await expect(findings.locator(".test").first()).toBeVisible();
    await expect(findings).toContainText("SIMULATED");
    await expect(findings).not.toContainText("CONFIRMED");
    await expect(findings).not.toContainText(/\d+%/);
    expect(await page.locator("#results .b-SIMULATED").count()).toBeGreaterThan(0);
    await expect(bar(page)).toContainText("Mock (simulated, vulnerable)");
    expect(seen.consoleErrors).toEqual([]);
    expect(appAssets(seen.requests, new URL(baseURL!).origin)).toEqual([]);
  });
});

test.describe("Step 2: target guardrails", () => {
  for (const [url, reason] of [
    ["https://api.github.com", "Public internet host"],
    ["http://169.254.169.254", "metadata"],
    ["not a url", "Not a valid http(s) URL"],
  ] as const) {
    test(`refuses ${url} as a target`, async ({ page }) => {
      await planDemo(page, "live");
      await page.getByLabel("Sandbox Base URL (from model, editable)").fill(url);
      await expect(page.getByTestId("target-refused")).toContainText(reason);
      await expect(page.getByRole("button", { name: "Register sandbox target" })).toHaveCount(0);
      await expect(bar(page)).toContainText("NOT REGISTERED");
    });
  }

  test("a live run against an unregistered URL sends nothing", async ({ page, baseURL }) => {
    const seen = watch(page);
    await planDemo(page, "live");
    await page.getByLabel("Sandbox Base URL (from model, editable)").fill("https://api.github.com");
    await page.getByRole("button", { name: "RUN ALL" }).click();
    await expect(bar(page)).toContainText("22/22 tests run", { timeout: 20_000 });
    await expect(page.locator("#results")).toContainText("not a registered target");
    await expect(page.locator("#results")).not.toContainText(/VIOLATION|CONFIRMED/);
    expect(appAssets(seen.requests, new URL(baseURL!).origin)).toEqual([]);
  });

  test("a registered loopback target receives the live requests; an unreachable sandbox is an error, not a finding", async ({ page, baseURL }) => {
    const TARGET = "http://127.0.0.1:59999";
    const attempted: string[] = [];
    // Abort inside the browser: the request is attempted (and recorded) but never leaves the machine.
    await page.route(`${TARGET}/**`, async (route) => {
      attempted.push(route.request().url());
      await route.abort("connectionrefused");
    });
    const seen = watch(page);
    await planDemo(page, "live");
    await page.getByLabel("Sandbox Base URL (from model, editable)").fill(TARGET);
    await page.getByLabel(/I confirm I am authorized/).check();
    await page.getByRole("button", { name: "Register sandbox target" }).click();
    await expect(page.getByTestId("target-registered")).toContainText("not independently verified");
    await expect(bar(page)).toContainText("SANDBOX · AUTHORIZED BY CONFIGURATION");
    await expect(page.getByTestId("target-url")).toHaveText(TARGET);
    // Demo identities have no credentials, so identity cases are blocked; anonymous probes are attempted.
    await page.getByRole("button", { name: "RUN ALL" }).click();
    await expect(bar(page)).toContainText("22/22 tests run", { timeout: 20_000 });
    expect(attempted.length).toBeGreaterThan(0);
    for (const u of attempted) expect(new URL(u).origin).toBe(TARGET);
    const others = appAssets(seen.requests, new URL(baseURL!).origin).filter((u) => !u.startsWith(`${TARGET}/`));
    expect(others).toEqual([]);
    await expect(page.locator("#results")).toContainText("ERROR");
    await expect(page.locator("#results")).not.toContainText(/VIOLATION|CONFIRMED/);
    await expect(page.locator("#findings .test")).toHaveCount(0);
  });
});
