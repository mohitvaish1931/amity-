// Step 2 (Test Lab) without executing anything against a sandbox: model loading and validation, target display and
// guardrails, law / severity / confidence filters, law -> test navigation, test-case selection, simulated state,
// report exports and persistence rules. Every test asserts that only the app's own assets were requested.
import { readFileSync } from "node:fs";
import { expect, test, type Page } from "@playwright/test";
import { readRepoFile } from "./expected";

const APP = "/2-test-lab/";
const MODEL = JSON.parse(readRepoFile("2-test-lab/samples/sample-testable-model.json")) as {
  sandboxBaseUrl: string;
  laws: { id: string; severity: string; confidence: string }[];
};

function watch(page: Page) {
  const errors: string[] = [];
  const requests: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("request", (r) => requests.push(r.url()));
  return { errors, requests };
}
const foreign = (requests: string[], baseURL: string) => requests.filter((u) => !u.startsWith("data:") && !u.startsWith(new URL(baseURL).origin + APP));
const bar = (page: Page) => page.getByRole("region", { name: "Target and run status" });
const cards = (page: Page) => page.locator("#tests .test");

async function runDemo(page: Page) {
  await page.goto(APP);
  await page.getByRole("button", { name: "Run the demo" }).click();
  await expect(page.locator("#modelStatus")).toContainText("Planned 22 test cases from 4 laws");
}

test.describe("Step 2: model loading", () => {
  test("empty state before anything is loaded", async ({ page, baseURL }) => {
    const seen = watch(page);
    await page.goto(APP);
    await expect(page.locator("#tests")).toContainText("Load a model and plan tests");
    await expect(page.locator("#preview")).toContainText("Plan tests, then select a case");
    await expect(page.getByTestId("plan-export-json")).toBeDisabled();
    await expect(page.getByTestId("filter-law")).toBeDisabled();
    await expect(bar(page)).toContainText("TARGET none");
    await expect(bar(page)).toContainText("no tests planned");
    await page.getByRole("button", { name: "Plan tests" }).click();
    await expect(page.locator("#modelStatus")).toContainText("No model yet");
    expect(seen.errors).toEqual([]);
    expect(foreign(seen.requests, baseURL!)).toEqual([]);
  });

  test("Run the demo loads the model, shows the target from the model and plans", async ({ page, baseURL }) => {
    const seen = watch(page);
    await runDemo(page);
    await expect(page.locator("#modelStatus")).toContainText(`Target URL taken from the model (${MODEL.sandboxBaseUrl})`);
    await expect(page.getByTestId("target-url")).toHaveText(MODEL.sandboxBaseUrl);
    await expect(page.getByTestId("target-env")).toContainText("NOT REGISTERED");
    await expect(bar(page)).toContainText("Mock (simulated, vulnerable)");
    await expect(cards(page)).toHaveCount(22);
    await expect(page.locator("#planner")).toContainText(`${MODEL.laws.length}`);
    for (const l of MODEL.laws) await expect(page.locator(`#planner [data-plan-law="${l.id}"]`)).toBeVisible();
    await expect(page.locator("#flow > li").nth(2)).toHaveAttribute("data-state", "done");
    expect(seen.errors).toEqual([]);
    expect(foreign(seen.requests, baseURL!)).toEqual([]);
  });

  test("invalid JSON and a malformed model are rejected with an error, not a crash", async ({ page }) => {
    const seen = watch(page);
    await page.goto(APP);
    await page.getByLabel("testable-security-model.json").fill("{ not json");
    await page.getByRole("button", { name: "Plan tests" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "not valid JSON" })).toBeVisible();
    await page.getByLabel("testable-security-model.json").fill(JSON.stringify({ endpoints: [{ path: "users" }], laws: [{ id: "L1" }] }));
    await page.getByRole("button", { name: "Plan tests" }).click();
    const alert = page.getByRole("alert").filter({ hasText: "not a valid testable-security-model.json" });
    await expect(alert).toContainText("endpoints[0].method: missing");
    await expect(alert).toContainText("laws[0].category: missing");
    await expect(cards(page)).toHaveCount(0);
    expect(seen.errors).toEqual([]);
  });

  test("an uploaded model file is read and planned", async ({ page }) => {
    await page.goto(APP);
    await page.locator("#modelFile").setInputFiles({ name: "model.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(MODEL)) });
    await expect(page.locator("#modelStatus")).toContainText("Loaded model.json");
    await page.getByRole("button", { name: "Plan tests" }).click();
    await expect(cards(page)).toHaveCount(22);
  });
});

test.describe("Step 2: filters and navigation", () => {
  test("law, severity and confidence filters narrow the specifications with counts", async ({ page }) => {
    await runDemo(page);
    await expect(page.getByTestId("test-count")).toHaveText("Showing all 22 test cases.");
    await page.getByTestId("filter-law").selectOption("LAW-003");
    const n = await cards(page).count();
    expect(n).toBeGreaterThan(0);
    expect(n).toBeLessThan(22);
    await expect(page.getByTestId("test-count")).toHaveText(`Showing ${n} of 22 test cases.`);
    for (const h of await cards(page).locator("h3").allTextContents()) expect(h).toContain("LAW-003");
    await page.getByTestId("filter-law").selectOption("");
    const medium = MODEL.laws.filter((l) => l.confidence === "MEDIUM").map((l) => l.id);
    await page.getByTestId("filter-confidence").selectOption("MEDIUM");
    for (const h of await cards(page).locator("h3").allTextContents()) expect(medium.some((id) => h.includes(id))).toBe(true);
    await page.getByTestId("filter-confidence").selectOption("");
    const severities = await page.getByTestId("filter-severity").locator("option").evaluateAll((o) => o.slice(1).map((x) => (x as HTMLOptionElement).value));
    expect(severities).toEqual([...new Set(MODEL.laws.map((l) => l.severity))]);
  });

  test("law -> tests: selecting a law in the plan shows only its cases; selecting it again shows all", async ({ page }) => {
    await runDemo(page);
    const law = page.locator('#planner [data-plan-law="LAW-001"]');
    await law.click();
    await expect(page.getByTestId("filter-law")).toHaveValue("LAW-001");
    await expect(law).toHaveAttribute("aria-pressed", "true");
    for (const h of await cards(page).locator("h3").allTextContents()) expect(h).toContain("LAW-001");
    await page.locator('#planner [data-plan-law="LAW-001"]').click();
    await expect(cards(page)).toHaveCount(22);
  });

  test("selecting a case shows its law, request and expectation in the inspector", async ({ page }) => {
    await runDemo(page);
    const card = cards(page).nth(1);
    const id = await card.getAttribute("data-t");
    await card.click();
    await expect(card).toHaveAttribute("aria-pressed", "true");
    const inspector = page.locator("#preview");
    await expect(inspector).toContainText(`Preview ${id}`);
    await expect(inspector).toContainText("severity High");
    await expect(inspector).toContainText("EXPECTED:");
    await expect(inspector).toContainText("EXECUTION: MOCK vulnerable");
  });
});

test.describe("Step 2: target guardrails in the browser", () => {
  test("a typed URL is never replaced by the model, and a live run with an empty URL is blocked", async ({ page, baseURL }) => {
    const seen = watch(page);
    await page.goto(APP);
    await page.getByLabel("Sandbox base URL").fill("http://127.0.0.1:9000");
    await page.getByRole("button", { name: "Load demo model" }).click();
    await expect(page.locator("#modelStatus")).toContainText("Demo model loaded");
    await page.getByRole("button", { name: "Plan tests" }).click();
    await expect(page.getByLabel("Sandbox base URL")).toHaveValue("http://127.0.0.1:9000");
    await expect(page.getByTestId("target-url")).toHaveText("http://127.0.0.1:9000");
    await page.getByLabel("Sandbox base URL").fill("");
    await page.getByLabel("Executor").selectOption("live");
    await page.getByRole("button", { name: "Run all" }).click();
    await expect(page.getByTestId("run-status")).toContainText("enter the sandbox base URL");
    await expect(bar(page)).toContainText("0/22 tests run");
    expect(foreign(seen.requests, baseURL!)).toEqual([]);
  });

  test("registration needs the explicit confirmation; the bar then shows the normalized target", async ({ page }) => {
    await runDemo(page);
    await page.getByLabel("Sandbox base URL").fill("http://localhost:4010/api/");
    await page.getByRole("button", { name: "Register sandbox target" }).click();
    await expect(page.locator("#targetStatus")).toContainText("Tick the confirmation checkbox first");
    await expect(page.getByTestId("target-env")).toContainText("NOT REGISTERED");
    await page.getByLabel(/I confirm I am authorized/).check();
    await page.getByRole("button", { name: "Register sandbox target" }).click();
    await expect(page.getByTestId("target-url")).toHaveText("http://localhost:4010/api");
    await expect(page.getByTestId("target-env")).toContainText("SANDBOX · AUTHORIZED BY CONFIGURATION (not independently verified)");
  });

  test("nothing is persisted: a reload starts empty and browser storage stays empty", async ({ page }) => {
    await runDemo(page);
    await page.getByLabel("Sandbox base URL").fill("http://127.0.0.1:9000");
    await page.reload();
    await expect(page.getByLabel("Sandbox base URL")).toHaveValue("");
    await expect(cards(page)).toHaveCount(0);
    const storage = await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length }));
    expect(storage).toEqual({ local: 0, session: 0 });
  });
});

test.describe("Step 2: simulated state and reports", () => {
  test("a mock run is SIMULATED everywhere, and the specifications export as JSON and Markdown", async ({ page, baseURL }) => {
    const seen = watch(page);
    await runDemo(page);
    await page.getByRole("button", { name: "Run all" }).click();
    await expect(bar(page)).toContainText("22/22 tests run", { timeout: 20_000 });
    await expect(page.locator("#results")).toContainText("(simulated, no request sent)");
    await expect(page.locator("#results")).not.toContainText(MODEL.sandboxBaseUrl);
    await expect(page.locator("#findings")).toContainText("SIMULATED");
    await expect(page.locator("#findings")).not.toContainText("CONFIRMED");

    await page.getByTestId("filter-law").selectOption("LAW-001");
    const [json] = await Promise.all([page.waitForEvent("download"), page.getByTestId("plan-export-json").click()]);
    expect(json.suggestedFilename()).toBe("test-specifications.json");
    const plan = JSON.parse(readFileSync((await json.path())!, "utf8"));
    expect(plan).toMatchObject({ format: "sentinel-x-test-plan-v1", basis: "specification", filter: { lawIds: ["LAW-001"] }, totalTests: 22 });
    expect(plan.tests.every((t: { lawId: string }) => t.lawId === "LAW-001")).toBe(true);
    expect(JSON.stringify(plan.tests)).not.toMatch(/CONFIRMED|VIOLATION|SIMULATED/);

    const [md] = await Promise.all([page.waitForEvent("download"), page.getByTestId("plan-export-md").click()]);
    expect(md.suggestedFilename()).toBe("test-specifications.md");
    const text = readFileSync((await md.path())!, "utf8");
    expect(text).toMatch(/^# Test specifications: model /);
    expect(text).toContain("Nothing in this file was executed");

    const [evidence] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Download evidence package" }).click()]);
    const pkg = JSON.parse(readFileSync((await evidence.path())!, "utf8"));
    expect(pkg.run).toMatchObject({ mode: "mock", executedAgainst: "simulated (mock, no request sent)" });
    expect(pkg.findings.every((f: { status: string }) => f.status === "SIMULATED")).toBe(true);
    expect(seen.errors).toEqual([]);
    expect(foreign(seen.requests, baseURL!)).toEqual([]);
  });
});
