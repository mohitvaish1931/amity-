// The judge's path: Run the demo in Step 1 -> Security Twin -> Constitution -> law -> graph / test specification ->
// Open in Test Lab -> planned test specifications -> report. Plus keyboard access to the main controls.
import { expect, test, type Page } from "@playwright/test";
import { demoInput, expectedFor } from "./expected";

function watch(page: Page) {
  const errors: string[] = [];
  const requests: string[] = [];
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("request", (r) => requests.push(r.url()));
  return { errors, requests };
}
const local = (requests: string[], baseURL: string) => requests.filter((u) => !u.startsWith("data:") && !u.startsWith(new URL(baseURL).origin + "/"));

test("demo flow: one click to the twin, law -> graph / spec, then hand-off to the Test Lab", async ({ page, baseURL }) => {
  const seen = watch(page);
  const { spec, config } = demoInput();
  const expected = expectedFor(spec, config);
  await page.goto("/1-security-twin/");
  await expect(page.locator("#flow > li").first()).toHaveAttribute("data-state", "current");
  await page.getByRole("button", { name: "Run the demo" }).click();
  await expect(page.getByTestId("twin-node").first()).toBeVisible();
  await expect(page.getByTestId("law-card")).toHaveCount(expected.constitution.laws.length);
  // progress and counts come from the model
  await expect(page.locator("#flow .flow-detail").nth(1)).toHaveText(`${expected.model.endpoints.length} endpoints · ${expected.model.resources.length} resources`);
  await expect(page.locator("#flow .flow-detail").nth(3)).toHaveText(`${expected.constitution.laws.length} laws`);
  await expect(page.locator("#flow > li").nth(4)).toHaveAttribute("data-state", "current");

  // law -> graph
  const first = expected.constitution.laws[0]!;
  const card = page.locator(`[data-testid="law-card"][data-law="${first.id}"]`);
  await card.locator("summary").first().click();
  await card.getByTestId("law-focus").click();
  await expect(page.locator(".twin-node.is-highlight").first()).toBeVisible();
  // law -> test specification
  await card.getByTestId("law-spec").click();
  await expect(page.locator("#lawTests .law.is-focused")).toHaveCount(1);
  await expect(page.locator("#lawTests .law.is-focused")).toContainText(first.id);

  // hand-off
  await expect(page.locator("#handoff")).toBeVisible();
  await page.getByRole("button", { name: "Open in Test Lab" }).click();
  await expect(page).toHaveURL(/\/2-test-lab\/$/);
  await expect(page.locator("#modelStatus")).toContainText("Model received from the Security Twin and planned");
  await expect(page.locator("#tests .test").first()).toBeVisible();
  const planned = await page.locator("#tests .test").count();
  await expect(page.locator("#modelStatus")).toContainText(`${planned} test cases`);
  expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
  // a reload neither replays the hand-off nor reports it missing
  await page.reload();
  await expect(page.locator("#modelStatus")).toBeEmpty();
  expect(seen.errors).toEqual([]);
  expect(local(seen.requests, baseURL!)).toEqual([]);
});

test.describe("keyboard", () => {
  test("Step 1: skip link, then the demo can be run and a law opened with the keyboard only", async ({ page }) => {
    await page.goto("/1-security-twin/");
    await page.keyboard.press("Tab");
    await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.locator("#main")).toBeFocused();
    await page.getByRole("button", { name: "Run the demo" }).focus();
    await page.keyboard.press("Enter");
    await expect(page.getByTestId("twin-node").first()).toBeVisible();
    const summary = page.getByTestId("law-card").first().locator("summary").first();
    await summary.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByTestId("law-card").first()).toHaveAttribute("open", "");
    await page.getByTestId("law-card").first().getByTestId("law-spec").focus();
    await page.keyboard.press("Space");
    await expect(page.locator("#lawTests .law.is-focused")).toHaveCount(1);
  });

  test("Step 2: filters, law buttons and test cards work from the keyboard", async ({ page }) => {
    await page.goto("/2-test-lab/");
    await page.getByRole("button", { name: "Run the demo" }).focus();
    await page.keyboard.press("Enter");
    await expect(page.locator("#tests .test")).toHaveCount(22);
    await page.locator('#planner [data-plan-law="LAW-003"]').focus();
    await page.keyboard.press("Enter");
    await expect(page.getByTestId("filter-law")).toHaveValue("LAW-003");
    const first = page.locator("#tests .test").first();
    await first.focus();
    await page.keyboard.press("Space");
    await expect(first).toHaveAttribute("aria-pressed", "true");
    await page.getByTestId("filter-law").focus();
    await page.keyboard.press("Home");
    await expect(page.getByTestId("filter-law")).toHaveValue("");
    await expect(page.locator("#tests .test")).toHaveCount(22);
  });

  test("every interactive element has an accessible name on both pages after the demo", async ({ page }) => {
    for (const [url, done] of [["/1-security-twin/", '[data-testid="twin-node"]'], ["/2-test-lab/", "#tests .test"]] as const) {
      await page.goto(url);
      await page.getByRole("button", { name: "Run the demo" }).click();
      await expect(page.locator(done).first()).toBeVisible();
      const unnamed = await page.evaluate(() => {
        const out: string[] = [];
        for (const el of document.querySelectorAll<HTMLElement>("button, a[href], input:not([type=hidden]), select, textarea, [role=button], summary")) {
          if (el.closest("[hidden]")) continue;
          const labelled = el.getAttribute("aria-label") || el.getAttribute("aria-labelledby") || (el.id && document.querySelector(`label[for="${el.id}"]`)) || el.closest("label") || el.textContent!.trim() || el.getAttribute("title");
          if (!labelled) out.push(el.outerHTML.slice(0, 80));
        }
        return out;
      });
      expect(unnamed, url).toEqual([]);
    }
  });
});
