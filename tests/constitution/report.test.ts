import { JSDOM } from "jsdom";
import { describe, expect, it } from "vitest";
import { CATEGORY_ORDER, REMEDIATION, REPORT_LIMITATIONS, renderConstitutionReport, type ReportInput } from "../../src/constitution";
import type { SecurityConstitution } from "../../src/contracts";
import { setHtml } from "../../src/ui/safe-html";
import { marketplace } from "./helpers";

function input(c: SecurityConstitution, over: Partial<ReportInput> = {}): ReportInput {
  return {
    specTitle: "Marketplace",
    specVersion: "3.0.3",
    generatedAt: "2026-09-25T00:00:00.000Z",
    target: { label: "Sandbox target configured", detail: "Authorization status unknown." },
    summary: { endpoints: 9, resources: 3, fields: 20, sensitiveFields: 4, identities: 5, roles: ["Merchant", "Buyer"] },
    readiness: [
      { label: "Endpoints parsed", ok: true, detail: "9" },
      { label: "Privileged role", ok: false, detail: "none" },
    ],
    laws: c.laws,
    totalLaws: c.laws.length,
    filter: {},
    notes: c.notes,
    warnings: [],
    ...over,
  };
}
/** Renders into a real DOM so assertions see text and structure, not raw markup. */
function dom(r: ReturnType<typeof renderConstitutionReport>) {
  const doc = new JSDOM("<div id=r></div>").window.document;
  setHtml(doc.getElementById("r")!, r);
  return doc.getElementById("r")!;
}

describe("renderConstitutionReport", () => {
  const c = marketplace();

  it("has every required section and states that it is specification-derived", () => {
    const el = dom(renderConstitutionReport(input(c)));
    const headings = [...el.querySelectorAll("h2")].map((h) => h.textContent);
    expect(headings).toEqual(["1. Executive summary", "2. Security Constitution", "3. Law details", "4. Remediation guidance", "5. Limitations"]);
    expect(el.querySelector('[data-testid="report-basis"]')!.textContent).toMatch(/Specification-derived\. No test was executed/);
    expect(el.textContent).toContain("Marketplace (3.0.3)");
    expect(el.textContent).toContain("2026-09-25T00:00:00.000Z");
    expect(el.textContent).toContain("Authorization is not verified by Sentinel X");
    expect(el.textContent).toContain("Readiness for testing: 1/2 checks");
    // The status word CONFIRMED never appears (the disclaimer says "not confirmed" in lower case).
    expect(el.textContent).not.toMatch(/\bCONFIRMED\b/);
  });

  it("lists every law in the table and in the details, with rule, scope, confidence and provenance", () => {
    const el = dom(renderConstitutionReport(input(c)));
    expect(el.querySelectorAll(".report-table tbody tr")).toHaveLength(c.laws.length);
    for (const l of c.laws) {
      const card = el.querySelector(`.report-law[data-law="${l.id}"]`)!;
      expect(card.textContent).toContain(l.invariant);
      expect(card.textContent).toContain(`${l.confidenceRationale.score}% of signals`);
      for (const p of l.provenance) expect(card.textContent).toContain(p.ref);
      expect(card.textContent).toContain("specification only, not executed");
    }
  });

  it("gives remediation guidance only for categories present, naming the laws it applies to", () => {
    const el = dom(renderConstitutionReport(input(c)));
    const section = [...el.querySelectorAll("section")].find((s) => s.querySelector("h2")!.textContent === "4. Remediation guidance")!;
    const present = CATEGORY_ORDER.filter((k) => c.laws.some((l) => l.category === k));
    expect(section.querySelectorAll("h3")).toHaveLength(present.length);
    for (const k of present) for (const g of REMEDIATION[k]) expect(section.textContent).toContain(g);
    for (const k of CATEGORY_ORDER.filter((x) => !present.includes(x))) for (const g of REMEDIATION[k]) expect(section.textContent).not.toContain(g);
  });

  it("highlights only high-severity laws with high-confidence evidence", () => {
    const el = dom(renderConstitutionReport(input(c)));
    const expected = c.laws.filter((l) => (l.severity === "High" || l.severity === "Critical") && l.confidence === "HIGH");
    const list = [...el.querySelectorAll("section")][0]!.querySelectorAll("ul")[0]!;
    if (expected.length) expect([...list.querySelectorAll("li b")].map((b) => b.textContent)).toEqual(expected.map((l) => l.id));
  });

  it("records the filter and handles an empty selection", () => {
    const el = dom(renderConstitutionReport(input(c, { laws: [], filter: { severities: ["Critical"] } })));
    expect(el.textContent).toContain(`0 of ${c.laws.length} (filter: severity Critical)`);
    expect(el.textContent).toContain("No laws match the filter.");
    expect(el.textContent).toContain("No laws in this report.");
  });

  it("always lists the limitations, model notes and warnings", () => {
    const el = dom(renderConstitutionReport(input(c, { notes: ["note A"], warnings: ["warning B"] })));
    for (const t of REPORT_LIMITATIONS) expect(el.textContent).toContain(t);
    expect(el.textContent).toContain("note A");
    expect(el.textContent).toContain("warning B");
  });

  it("ends each test strategy with exactly one period without altering the steps' words", () => {
    const c2 = structuredClone(c);
    c2.laws[0]!.testStrategy.steps = ["Send it without credentials", "Check the status."];
    const el = dom(renderConstitutionReport(input(c2, { laws: c2.laws })));
    const card = el.querySelector(`.report-law[data-law="${c2.laws[0]!.id}"]`)!;
    expect(card.textContent).toContain("Send it without credentials → Check the status. Expected:");
    expect(el.textContent).not.toMatch(/\.\. Expected/);
  });

  it("escapes spec-supplied text", () => {
    const evil = structuredClone(c);
    evil.laws[0]!.statement = '<img src=x onerror="alert(1)">';
    const el = dom(renderConstitutionReport(input(evil, { specTitle: "<script>x</script>", laws: evil.laws })));
    expect(el.querySelector("img, script")).toBeNull();
    expect(el.textContent).toContain('<img src=x onerror="alert(1)">');
  });
});
