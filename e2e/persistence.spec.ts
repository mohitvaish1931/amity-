// Opt-in persistence across a real page reload in the browser.
import { expect, test } from "@playwright/test";

test("remembered inputs survive a reload, and clearing forgets them", async ({ page }) => {
  await page.goto("/1-security-twin/");
  await page.getByRole("button", { name: "Load Demo Swagger + Config" }).click();
  await expect(page.locator("#buildStatus")).toContainText("Demo spec and configuration loaded");
  await page.getByRole("button", { name: "[ BUILD SECURITY TWIN ]" }).click();
  await expect(page.getByTestId("law-card").first()).toBeVisible();
  // Nothing is stored before opting in.
  expect(await page.evaluate(() => localStorage.length)).toBe(0);

  await page.getByLabel(/Remember the spec and configuration in this browser/).check();
  await expect(page.locator("#persistStatus")).toContainText("Saved in this browser");
  const spec = await page.locator("#swaggerText").inputValue();

  await page.reload();
  await expect(page.locator("#persistStatus")).toContainText("Restored the spec and configuration");
  await expect(page.getByLabel(/Remember the spec and configuration in this browser/)).toBeChecked();
  expect(await page.locator("#swaggerText").inputValue()).toBe(spec);
  await page.getByRole("button", { name: "[ BUILD SECURITY TWIN ]" }).click();
  await expect(page.getByTestId("law-card")).toHaveCount(7);

  await page.getByRole("button", { name: "Clear saved data" }).click();
  await expect(page.locator("#persistStatus")).toContainText("Saved data removed");
  await page.reload();
  expect(await page.evaluate(() => localStorage.length)).toBe(0);
  await expect(page.locator("#swaggerText")).toHaveValue("");
  await expect(page.getByLabel(/Remember the spec and configuration in this browser/)).not.toBeChecked();
});
