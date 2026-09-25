// Constitution Explorer in the real Step 1 bundle: data-driven filter options, filtering, and exports of what is shown.
import { afterEach, describe, expect, it } from "vitest";
import { loadApp, type LoadedApp } from "../../scripts/app-harness.mjs";
import type { ConstitutionExport } from "../../src/constitution";

let app: LoadedApp | undefined;
afterEach(() => {
  app?.close();
  app = undefined;
});

async function built() {
  const a = await loadApp("1-security-twin");
  a.click("demoBtn");
  await a.settle();
  a.click("buildBtn");
  await a.settle();
  return a;
}

/** Captures downloads (Blob + file name) instead of letting jsdom try to navigate. */
function captureDownloads(a: LoadedApp) {
  const files: { name: string; type: string; text: Promise<string> }[] = [];
  const blobs = new Map<string, Blob>();
  let n = 0;
  a.window.URL.createObjectURL = (b: Blob) => {
    const url = `blob:test/${n++}`;
    blobs.set(url, b);
    return url;
  };
  a.window.URL.revokeObjectURL = () => {};
  a.window.HTMLAnchorElement.prototype.click = function (this: HTMLAnchorElement) {
    const blob = blobs.get(this.href)!;
    const text = new Promise<string>((resolve) => {
      const r = new a.window.FileReader();
      r.onload = () => resolve(String(r.result));
      r.readAsText(blob);
    });
    files.push({ name: this.download, type: blob.type, text });
  };
  return files;
}

const cards = (a: LoadedApp) => [...a.document.querySelectorAll<HTMLDetailsElement>("#laws details.const-law")];
const visible = (a: LoadedApp) => cards(a).filter((d) => !d.hidden).map((d) => d.dataset.law);
const select = (a: LoadedApp, id: string, value: string) => {
  const el = a.$(id) as unknown as HTMLSelectElement;
  el.value = value;
  el.dispatchEvent(new a.window.Event("change"));
};

describe("Constitution Explorer", () => {
  it("is disabled before a constitution exists", async () => {
    app = await loadApp("1-security-twin");
    for (const id of ["lawCategory", "lawSeverity", "lawConfidence", "lawSearch", "lawExportJson", "lawExportMd"]) {
      expect((app.$(id) as unknown as HTMLButtonElement).disabled, id).toBe(true);
    }
  });

  it("offers only the categories, severities and confidence levels present, with counts", async () => {
    app = await built();
    const laws = JSON.parse(app.$("out3").textContent!).laws as { category: string; severity: string; confidence: string }[];
    for (const [id, key] of [["lawCategory", "category"], ["lawSeverity", "severity"], ["lawConfidence", "confidence"]] as const) {
      const opts = [...(app.$(id) as unknown as HTMLSelectElement).options].slice(1);
      expect(opts.map((o) => o.value).sort()).toEqual([...new Set(laws.map((l) => l[key]))].sort());
      for (const o of opts) expect(o.textContent).toMatch(new RegExp(`\\(${laws.filter((l) => l[key] === o.value).length}\\)$`));
    }
    expect(app.$("lawCount").textContent).toBe(`Showing all ${laws.length} laws.`);
  });

  it("filters cards by category and text, and reports when nothing matches", async () => {
    app = await built();
    const laws = JSON.parse(app.$("out3").textContent!).laws as { id: string; category: string }[];
    const cat = laws[0]!.category;
    select(app, "lawCategory", cat);
    expect(visible(app)).toEqual(laws.filter((l) => l.category === cat).map((l) => l.id));
    expect(app.$("lawCount").textContent).toMatch(new RegExp(`^Showing ${laws.filter((l) => l.category === cat).length} of ${laws.length} laws`));
    select(app, "lawCategory", "");
    app.setValue("lawSearch", "zz-no-match");
    app.$("lawSearch").dispatchEvent(new app.window.Event("input"));
    expect(visible(app)).toEqual([]);
    expect(app.$("lawCount").textContent).toMatch(/no law matches the filter/);
  });

  it("keeps the filter across a rebuild when the value still exists", async () => {
    app = await built();
    const sev = (app.$("lawSeverity") as unknown as HTMLSelectElement).options[1]!.value;
    select(app, "lawSeverity", sev);
    const before = visible(app);
    app.click("applyConfig");
    expect((app.$("lawSeverity") as unknown as HTMLSelectElement).value).toBe(sev);
    expect(visible(app)).toEqual(before);
  });

  it("exports exactly the shown laws as JSON and Markdown, labelled specification-derived", async () => {
    app = await built();
    const files = captureDownloads(app);
    const laws = JSON.parse(app.$("out3").textContent!).laws as { id: string; category: string }[];
    const cat = laws[0]!.category;
    select(app, "lawCategory", cat);
    app.click("lawExportJson");
    app.click("lawExportMd");
    expect(files.map((f) => [f.name, f.type])).toEqual([
      ["security-constitution.json", "application/json"],
      ["security-constitution.md", "text/markdown"],
    ]);
    const json = JSON.parse(await files[0]!.text) as ConstitutionExport;
    expect(json.basis).toBe("specification");
    expect(json.filter).toEqual({ categories: [cat] });
    expect(json.laws.map((l) => l.id)).toEqual(visible(app));
    expect(json.totalLaws).toBe(laws.length);
    expect(json.source.specTitle).toBe(JSON.parse(app.$("swaggerText").value).info.title);
    const md = await files[1]!.text;
    for (const id of visible(app)) expect(md).toContain(`## ${id}: `);
    for (const l of laws.filter((x) => x.category !== cat)) expect(md).not.toContain(`## ${l.id}: `);
  });
});

describe("Printable report (Save as PDF)", () => {
  it("renders the report for exactly the shown laws, marks the page for printing and opens the print dialog", async () => {
    app = await built();
    let printed = 0;
    app.window.print = () => {
      printed++;
    };
    const laws = JSON.parse(app.$("out3").textContent!).laws as { id: string; category: string }[];
    select(app, "lawCategory", laws[0]!.category);
    app.click("lawPrintPdf");
    expect(printed).toBe(1);
    expect(app.document.body.classList.contains("printing")).toBe(true);
    const report = app.$("printReport");
    expect(report.hasAttribute("hidden")).toBe(true); // hidden on screen; print CSS shows it
    const inReport = [...report.querySelectorAll(".report-law")].map((d) => (d as HTMLElement).dataset.law);
    expect(inReport).toEqual(visible(app));
    expect(report.querySelector('[data-testid="report-basis"]')!.textContent).toMatch(/Specification-derived/);
    expect(report.textContent).toContain(JSON.parse(app.$("swaggerText").value).info.title);
    expect(report.textContent).toMatch(/Readiness for testing: 6\/6 checks/);
    expect(app.$("reportStatus").textContent).toMatch(/Report ready \(\d+ of 7 laws\)\. Choose "Save as PDF"/);
    app.window.dispatchEvent(new app.window.Event("afterprint"));
    expect(app.document.body.classList.contains("printing")).toBe(false);
  });

  it("reports when printing is not available instead of failing silently", async () => {
    app = await built();
    app.window.print = () => {
      throw new Error("blocked");
    };
    app.click("lawPrintPdf");
    expect(app.$("reportStatus").dataset.status).toBe("error");
    expect(app.$("reportStatus").textContent).toMatch(/Printing is not available here \(blocked\)/);
  });
});
