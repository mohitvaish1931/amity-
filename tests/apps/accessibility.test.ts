// Automated accessibility checks on the real bundles, in several UI states (no extra dependency):
// named controls and buttons, unique ids, scoped table headers, and keyboard-operable interactive elements.
import { afterEach, describe, expect, it } from "vitest";
import { loadApp, type LoadedApp } from "../../scripts/app-harness.mjs";

let app: LoadedApp | undefined;
afterEach(() => {
  app?.close();
  app = undefined;
});

function accessibleName(doc: Document, el: Element): string {
  const aria = el.getAttribute("aria-label");
  if (aria?.trim()) return aria.trim();
  const by = el.getAttribute("aria-labelledby");
  if (by) return by.split(/\s+/).map((id) => doc.getElementById(id)?.textContent ?? "").join(" ").trim();
  if (el.id) {
    const label = [...doc.querySelectorAll("label[for]")].find((l) => l.getAttribute("for") === el.id);
    if (label?.textContent?.trim()) return label.textContent.trim();
  }
  const wrapping = el.closest("label");
  if (wrapping?.textContent?.trim()) return wrapping.textContent.trim();
  // Buttons (native or role=button) are named by their content.
  if (el.tagName === "BUTTON" || el.getAttribute("role") === "button") return el.textContent?.trim() ?? "";
  return "";
}

/** Returns a list of problems; empty means the checks passed. */
function audit(a: LoadedApp): string[] {
  const doc = a.document;
  const problems: string[] = [];
  const describe = (el: Element) => `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}${el.className ? `.${String(el.className).split(" ")[0]}` : ""}`;
  for (const el of doc.querySelectorAll("input, select, textarea")) {
    if ((el as HTMLInputElement).type === "hidden") continue;
    if (!accessibleName(doc, el)) problems.push(`unnamed control ${describe(el)}`);
  }
  for (const el of doc.querySelectorAll("button, [role=button]")) if (!accessibleName(doc, el)) problems.push(`unnamed button ${describe(el)}`);
  for (const el of doc.querySelectorAll("[role=button]:not(button)")) if (el.getAttribute("tabindex") !== "0") problems.push(`role=button not focusable ${describe(el)}`);
  for (const el of doc.querySelectorAll("th")) if (!el.getAttribute("scope")) problems.push(`th without scope: ${el.textContent}`);
  const ids = [...doc.querySelectorAll("[id]")].map((e) => e.id);
  for (const id of new Set(ids.filter((id, i) => ids.indexOf(id) !== i))) problems.push(`duplicate id ${id}`);
  for (const el of doc.querySelectorAll("*")) for (const n of el.getAttributeNames()) if (n.startsWith("on")) problems.push(`inline handler ${n} on ${describe(el)}`);
  if (!doc.documentElement.getAttribute("lang")) problems.push("missing lang");
  return problems;
}

describe("Step 1 accessibility", () => {
  it("passes in the initial, built and filtered states", async () => {
    app = await loadApp("1-security-twin");
    expect(audit(app)).toEqual([]);
    app.click("demoBtn");
    await app.settle();
    app.click("buildBtn");
    await app.settle();
    expect(audit(app)).toEqual([]);
    const sel = app.$("lawCategory") as unknown as HTMLSelectElement;
    sel.value = sel.options[1]!.value;
    sel.dispatchEvent(new app.window.Event("change"));
    expect(audit(app)).toEqual([]);
  });

  it("the upload control is a real button", async () => {
    app = await loadApp("1-security-twin");
    expect(app.$("uploadBtn").tagName).toBe("BUTTON");
  });
});

describe("Step 2 accessibility", () => {
  it("passes in the initial, planned and run states", async () => {
    app = await loadApp("2-test-lab");
    expect(audit(app)).toEqual([]);
    app.click("demoModelBtn");
    await app.settle();
    app.click("planBtn");
    expect(audit(app)).toEqual([]);
    app.click("runAllBtn");
    await app.waitFor(() => app!.document.querySelectorAll("#findings .test").length > 0, { timeout: 15000 });
    expect(audit(app)).toEqual([]);
  });

  it("test cards can be selected from the keyboard and keep focus", async () => {
    app = await loadApp("2-test-lab");
    app.click("demoModelBtn");
    await app.settle();
    app.click("planBtn");
    const second = app.document.querySelectorAll<HTMLElement>("#tests .test")[1]!;
    const id = second.dataset.t!;
    second.dispatchEvent(new app.window.KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    const selected = [...app.document.querySelectorAll<HTMLElement>("#tests .test")].find((d) => d.dataset.t === id)!;
    expect(selected.getAttribute("aria-pressed")).toBe("true");
    expect(app.document.activeElement).toBe(selected);
    expect(app.$("preview").textContent).toContain(`Preview ${id}`);
    const third = app.document.querySelectorAll<HTMLElement>("#tests .test")[2]!;
    third.dispatchEvent(new app.window.KeyboardEvent("keydown", { key: " ", bubbles: true }));
    const thirdId = third.dataset.t;
    expect([...app.document.querySelectorAll<HTMLElement>("#tests .test")].find((d) => d.dataset.t === thirdId)!.getAttribute("aria-pressed")).toBe("true");
  });
});
