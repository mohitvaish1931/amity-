// The printable Security Constitution report in a real browser: print media shows only the report, and the browser
// produces a real PDF from it (the same engine as "Save as PDF").
import { expect, test } from "@playwright/test";

test("the report prints alone and renders to a multi-page PDF", async ({ page }, testInfo) => {
  // Replace the blocking print dialog; the test drives printing through page.pdf() instead.
  await page.addInitScript(() => {
    (window as unknown as { __printed: number }).__printed = 0;
    window.print = () => {
      (window as unknown as { __printed: number }).__printed++;
    };
  });
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => {
    if (m.type() === "error") errors.push(m.text());
  });

  await page.goto("/1-security-twin/");
  await page.getByRole("button", { name: "Load demo spec + config" }).click();
  await expect(page.locator("#buildStatus")).toContainText("Demo spec and configuration loaded");
  await page.getByRole("button", { name: "Build Security Twin" }).click();
  await expect(page.getByTestId("law-card").first()).toBeVisible();

  await page.getByRole("button", { name: "Report: print / save as PDF" }).click();
  await expect.poll(() => page.evaluate(() => (window as unknown as { __printed: number }).__printed)).toBe(1);
  await expect(page.locator("#reportStatus")).toContainText('Choose "Save as PDF"');

  // On screen the report stays hidden; in print media it is the only visible content.
  await expect(page.getByTestId("constitution-report")).toBeHidden();
  await page.emulateMedia({ media: "print" });
  await expect(page.getByTestId("constitution-report")).toBeVisible();
  await expect(page.locator(".wrap")).toBeHidden();
  await expect(page.getByTestId("report-basis")).toContainText("Specification-derived");
  const lawCount = await page.getByTestId("law-card").count();
  await expect(page.locator("#printReport .report-law")).toHaveCount(lawCount);
  await expect(page.locator("#printReport h2")).toHaveText([
    "1. Executive summary",
    "2. Security Constitution",
    "3. Law details",
    "4. Remediation guidance",
    "5. Limitations",
  ]);

  const pdf = await page.pdf({ format: "A4", printBackground: true });
  expect(pdf.subarray(0, 5).toString("latin1")).toBe("%PDF-");
  const pages = (pdf.toString("latin1").match(/\/Type\s*\/Page[^s]/g) ?? []).length;
  expect(pages).toBeGreaterThan(1);
  await testInfo.attach("security-constitution-report.pdf", { body: pdf, contentType: "application/pdf" });
  expect(errors).toEqual([]);
});
