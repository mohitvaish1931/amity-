// Responsive layout and keyboard focus in real browsers, in populated states (where overflow bugs appear).
import { expect, test, type Page } from "@playwright/test";

const VIEWPORTS = [
  { width: 390, height: 844 },
  { width: 1280, height: 720 },
  { width: 1366, height: 768 },
  { width: 1920, height: 1080 },
];
const overflowX = (page: Page) => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);

for (const vp of VIEWPORTS) {
  test.describe(`${vp.width}×${vp.height}`, () => {
    test.use({ viewport: vp });

    test("Step 1 has no horizontal page scroll after building the demo", async ({ page }) => {
      await page.goto("/1-security-twin/");
      await page.getByRole("button", { name: "Load Demo Swagger + Config" }).click();
      await expect(page.locator("#buildStatus")).toContainText("Demo spec and configuration loaded");
      await page.getByRole("button", { name: "[ BUILD SECURITY TWIN ]" }).click();
      await expect(page.getByTestId("twin-node").first()).toBeVisible();
      expect(await overflowX(page)).toBe(0);
    });

    test("Step 2 has no horizontal page scroll after a mock run", async ({ page }) => {
      await page.goto("/2-test-lab/");
      await page.getByRole("button", { name: "Load Demo Model" }).click();
      await expect(page.locator("#modelStatus")).toContainText("Demo model loaded");
      await page.getByRole("button", { name: "[ PLAN TESTS ]" }).click();
      await page.getByRole("button", { name: "RUN ALL" }).click();
      await expect(page.getByRole("region", { name: "Target and run status" })).toContainText("22/22 tests run", { timeout: 20_000 });
      expect(await overflowX(page)).toBe(0);
    });
  });
}

test.describe("keyboard focus", () => {
  test("focused controls show a visible outline", async ({ page }) => {
    await page.goto("/1-security-twin/");
    await page.keyboard.press("Tab");
    const style = await page.evaluate(() => {
      const el = document.activeElement as HTMLElement;
      const s = getComputedStyle(el);
      return { tag: el.tagName, outlineStyle: s.outlineStyle, outlineWidth: parseFloat(s.outlineWidth) };
    });
    expect(style.tag).toBe("BUTTON");
    expect(style.outlineStyle).not.toBe("none");
    expect(style.outlineWidth).toBeGreaterThanOrEqual(2);
  });

  test("the Step 2 workspace puts tests, execution and inspector side by side on wide screens", async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await page.goto("/2-test-lab/");
    const cols = await page.evaluate(() => getComputedStyle(document.querySelector(".workspace")!).gridTemplateColumns.split(" ").length);
    expect(cols).toBe(3);
    await page.setViewportSize({ width: 1024, height: 768 });
    const stacked = await page.evaluate(() => getComputedStyle(document.querySelector(".workspace")!).gridTemplateColumns.split(" ").length);
    expect(stacked).toBe(1);
  });
});
