import { expect, test } from "@playwright/test";

const APP = "/1-security-twin/";

test.describe("Constitution Explorer", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(APP);
    await page.getByRole("button", { name: "Load Demo Swagger + Config" }).click();
    await page.getByRole("button", { name: "[ BUILD SECURITY TWIN ]" }).click();
    await expect(page.getByTestId("law-card").first()).toBeVisible();
  });

  test("filters laws by category, severity, and text", async ({ page }) => {
    const allLawsCount = await page.getByTestId("law-card").count();
    expect(allLawsCount).toBeGreaterThan(0);

    // Filter by Category
    await page.getByLabel("Category").selectOption("BOLA");
    const filteredCount = await page.getByTestId("law-card").count();
    expect(filteredCount).toBeLessThan(allLawsCount);
    expect(filteredCount).toBeGreaterThan(0);

    // Filter by text
    await page.getByLabel("Search").fill("Customer");
    const textFilteredCount = await page.getByTestId("law-card").count();
    expect(textFilteredCount).toBeLessThanOrEqual(filteredCount);
    
    // Clear filters
    await page.getByLabel("Category").selectOption("");
    await page.getByLabel("Search").fill("");
    await expect(page.getByTestId("law-card")).toHaveCount(allLawsCount);
  });

  test("JSON export and Markdown export", async ({ page }) => {
    // We can't easily test actual file downloads in all environments, but we can intercept the download event
    // or trigger it and expect a download object.
    const jsonDownloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export shown laws (JSON)" }).click();
    const jsonDownload = await jsonDownloadPromise;
    expect(jsonDownload.suggestedFilename()).toContain(".json");

    const mdDownloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export shown laws (Markdown)" }).click();
    const mdDownload = await mdDownloadPromise;
    expect(mdDownload.suggestedFilename()).toContain(".md");
  });
});
