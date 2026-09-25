// Demo flow in the real bundles: progress stepper from real state, one-click demo, law -> test specification navigation,
// Step 1 -> Step 2 hand-off, Step 2 filters, and test-specification exports. Nothing here executes a request.
import { afterEach, describe, expect, it } from "vitest";
import { loadApp, type LoadedApp } from "../../scripts/app-harness.mjs";
import { readRepoFile } from "../helpers";

let app: LoadedApp | undefined;
afterEach(() => {
  app?.close();
  app = undefined;
});

const flow = (a: LoadedApp) => [...a.document.querySelectorAll<HTMLLIElement>("#flow > li")].map((li) => li.dataset.state);
const select = (a: LoadedApp, id: string, value: string) => {
  const el = a.$(id) as unknown as HTMLSelectElement;
  el.value = value;
  el.dispatchEvent(new a.window.Event("change"));
};
const shownTests = (a: LoadedApp) => [...a.document.querySelectorAll<HTMLElement>("#tests .test")].map((d) => d.dataset.t);

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

describe("Step 1 flow", () => {
  it("the stepper follows real state: load, then build", async () => {
    app = await loadApp("1-security-twin");
    expect(flow(app)).toEqual(["current", "todo", "todo", "todo", "todo"]);
    app.click("demoBtn");
    await app.settle();
    expect(flow(app)).toEqual(["done", "current", "todo", "todo", "todo"]);
    app.click("buildBtn");
    expect(flow(app)).toEqual(["done", "done", "done", "done", "current"]);
    const detail = [...app.document.querySelectorAll("#flow .flow-detail")].map((d) => d.textContent);
    const out = JSON.parse(app.$("out4").textContent!);
    expect(detail[1]).toBe(`${out.endpoints.length} endpoints · ${Object.keys(out.resources).length} resources`);
    expect(detail[3]).toBe(`${out.constitution.laws.length} laws`);
  });

  it("Run the demo loads and builds in one step", async () => {
    app = await loadApp("1-security-twin");
    app.click("demoRunBtn");
    await app.waitFor(() => app!.$("out4").textContent !== "—");
    expect(app.$("buildStatus").textContent).toMatch(/Built from the spec/);
    expect((app.$("handoff") as HTMLElement).hidden).toBe(false);
    expect(app.$("handoffSummary").textContent).toMatch(/nothing has been executed/);
  });

  it("an invalid spec leaves the flow at the load step with an error, not a silent failure", async () => {
    app = await loadApp("1-security-twin");
    app.click("demoBtn");
    await app.settle();
    app.setValue("swaggerText", "{ not json");
    app.click("buildBtn");
    expect(app.$("buildStatus").getAttribute("role")).toBe("alert");
    expect(flow(app)[1]).toBe("current");
    expect((app.$("handoff") as HTMLElement).hidden).toBe(true);
  });

  it("law -> test specification: each constitution law points at the Step 2 law that covers it", async () => {
    app = await loadApp("1-security-twin");
    app.click("demoRunBtn");
    await app.waitFor(() => app!.$("out4").textContent !== "—");
    const model = JSON.parse(app.$("out4").textContent!);
    for (const legacy of model.laws as { id: string; constitutionLawIds: string[] }[]) {
      for (const lawId of legacy.constitutionLawIds) {
        (app.document.querySelector(`[data-spec-law="${lawId}"]`) as HTMLButtonElement).click();
        const focused = [...app.document.querySelectorAll<HTMLElement>("#lawTests .is-focused")].map((c) => c.dataset.spec);
        expect(focused).toEqual([legacy.id]);
      }
    }
  });

  it("hands the model to the Test Lab through this tab's sessionStorage only", async () => {
    app = await loadApp("1-security-twin");
    app.click("demoRunBtn");
    await app.waitFor(() => app!.$("out4").textContent !== "—");
    app.click("handoffBtn");
    const stored = app.window.sessionStorage.getItem("sentinel-x:handoff:model");
    expect(JSON.parse(stored!)).toEqual(JSON.parse(app.$("out4").textContent!));
    expect(app.window.localStorage.length).toBe(0);
  });

  it("the exported model always carries the target URL on screen, even when edited after the build", async () => {
    app = await loadApp("1-security-twin");
    app.click("demoRunBtn");
    await app.waitFor(() => app!.$("out4").textContent !== "—");
    app.setValue("baseUrl", "http://127.0.0.1:9000");
    app.$("baseUrl").dispatchEvent(new app.window.Event("input"));
    expect(JSON.parse(app.$("out4").textContent!).sandboxBaseUrl).toBe("http://127.0.0.1:9000");
    expect(app.$("topStatus").textContent).toMatch(/Sandbox target configured: http:\/\/127\.0\.0\.1:9000/);
    expect(app.$("topStatus").textContent).not.toMatch(/authorized|confirmed/i);
  });
});

describe("Step 1 never exports or remembers a URL with credentials", () => {
  it("leaves the URL out of the model and the saved workspace, and says so", async () => {
    app = await loadApp("1-security-twin");
    app.click("demoBtn");
    await app.settle();
    app.setValue("baseUrl", "http://admin:hunter2@127.0.0.1:9000");
    (app.$("rememberChk") as unknown as HTMLInputElement).checked = true;
    app.click("buildBtn");
    const model = JSON.parse(app.$("out4").textContent!);
    expect(model.sandboxBaseUrl).toBe("");
    expect(app.$("out4").textContent).not.toContain("hunter2");
    const saved = app.window.localStorage.getItem("sentinel-x:step1:workspace:v1")!;
    expect(saved).not.toContain("hunter2");
    expect(app.$("persistStatus").textContent).toMatch(/sandbox URL was not saved: it contains a user name or password/);
    expect(app.$("baseUrl").value).toBe("http://admin:hunter2@127.0.0.1:9000"); // the field itself is never rewritten
  });
});

describe("Step 2 receives the hand-off", () => {
  it("plans the handed-over model once and removes it from storage", async () => {
    const model = readRepoFile("2-test-lab/samples/sample-testable-model.json");
    app = await loadApp("2-test-lab", {
      beforeRun: (w) => {
        w.sessionStorage.setItem("sentinel-x:handoff:model", model);
        w.location.hash = "#from-security-twin";
      },
    });
    expect(app.window.sessionStorage.getItem("sentinel-x:handoff:model")).toBeNull();
    expect(app.$("modelStatus").textContent).toMatch(/Model received from the Security Twin and planned: 22 test cases from 4 laws\. Nothing has been executed\./);
    expect(app.document.querySelectorAll("#tests .test")).toHaveLength(22);
  });

  it("reports a missing hand-off instead of showing an empty page silently", async () => {
    app = await loadApp("2-test-lab", { beforeRun: (w) => (w.location.hash = "#from-security-twin") });
    expect(app.$("modelStatus").textContent).toMatch(/No model arrived from the Security Twin/);
    expect(app.$("modelStatus").getAttribute("role")).toBe("alert");
  });

  it("a malformed handed-over model is rejected with details", async () => {
    app = await loadApp("2-test-lab", { beforeRun: (w) => w.sessionStorage.setItem("sentinel-x:handoff:model", JSON.stringify({ endpoints: [{}], laws: [] })) });
    expect(app.$("modelStatus").textContent).toMatch(/Invalid model: this is not a valid testable-security-model\.json\./);
    expect(app.$("modelStatus").querySelector(".status-details")!.textContent).toMatch(/endpoints\[0\]\.method: missing/);
    expect(app.document.querySelectorAll("#tests .test")).toHaveLength(0);
  });
});

describe("Step 2 test specifications", () => {
  async function planned() {
    const a = await loadApp("2-test-lab");
    a.click("demoPlanBtn");
    await a.waitFor(() => a.document.querySelectorAll("#tests .test").length > 0);
    return a;
  }

  it("the stepper follows real state in the Test Lab", async () => {
    app = await loadApp("2-test-lab");
    expect(flow(app)[0]).toBe("current");
    app.close();
    app = await planned();
    expect(flow(app)).toEqual(["done", "done", "done", "current", "todo"]);
  });

  it("filters by law, severity and confidence with options and counts from the plan", async () => {
    app = await planned();
    const model = JSON.parse(readRepoFile("2-test-lab/samples/sample-testable-model.json"));
    const lawOptions = [...(app.$("testLaw") as unknown as HTMLSelectElement).options].slice(1).map((o) => o.value);
    expect(lawOptions).toEqual(model.laws.map((l: { id: string }) => l.id));
    expect(app.$("testCount").textContent).toBe("Showing all 22 test cases.");
    select(app, "testLaw", "LAW-003");
    const ids = shownTests(app);
    expect(ids.length).toBeGreaterThan(0);
    expect(ids.length).toBeLessThan(22);
    expect(app.$("testCount").textContent).toBe(`Showing ${ids.length} of 22 test cases.`);
    for (const d of app.document.querySelectorAll("#tests .test h3")) expect(d.textContent).toContain("LAW-003");
    select(app, "testLaw", "");
    select(app, "testConfidence", "MEDIUM");
    const medium = model.laws.filter((l: { confidence: string }) => l.confidence === "MEDIUM").map((l: { id: string }) => l.id);
    for (const d of app.document.querySelectorAll("#tests .test h3")) expect(medium.some((id: string) => d.textContent!.includes(id))).toBe(true);
    const severities = [...(app.$("testSeverity") as unknown as HTMLSelectElement).options].slice(1).map((o) => o.value);
    expect(severities).toEqual([...new Set(model.laws.map((l: { severity: string }) => l.severity))]);
  });

  it("law -> test navigation: a law in the plan filters the list to its cases, and toggles back", async () => {
    app = await planned();
    const btn = () => app!.document.querySelector<HTMLButtonElement>('[data-plan-law="LAW-001"]')!;
    btn().click();
    expect((app.$("testLaw") as unknown as HTMLSelectElement).value).toBe("LAW-001");
    expect(btn().getAttribute("aria-pressed")).toBe("true");
    expect(shownTests(app).length).toBeLessThan(22);
    btn().click();
    expect((app.$("testLaw") as unknown as HTMLSelectElement).value).toBe("");
    expect(shownTests(app)).toHaveLength(22);
  });

  it("exports the shown specifications as JSON and Markdown, without results or credentials", async () => {
    app = await planned();
    const files = captureDownloads(app);
    const cred = app.document.querySelector<HTMLInputElement>("#authBox input[data-cred]")!;
    cred.value = "SECRET-TOKEN-123";
    cred.dispatchEvent(new app.window.Event("change"));
    select(app, "testLaw", "LAW-001");
    app.click("runAllBtn");
    await app.waitFor(() => /22\/22 tests run/.test(app!.$("targetBar").textContent!), { timeout: 15000 });
    app.click("planExportJson");
    app.click("planExportMd");
    expect(files.map((f) => [f.name, f.type])).toEqual([["test-specifications.json", "application/json"], ["test-specifications.md", "text/markdown"]]);
    const json = JSON.parse(await files[0]!.text);
    expect(json).toMatchObject({ format: "sentinel-x-test-plan-v1", basis: "specification", filter: { lawIds: ["LAW-001"] }, totalTests: 22 });
    expect(json.tests.every((t: { lawId: string }) => t.lawId === "LAW-001")).toBe(true);
    // Specifications only: no result, finding or verdict fields, even after a run (the disclaimer mentions SIMULATED by design).
    expect(Object.keys(json)).not.toContain("results");
    expect(Object.keys(json)).not.toContain("findings");
    expect(JSON.stringify(json.tests)).not.toMatch(/CONFIRMED|VIOLATION|SIMULATED|PASS|"status"/);
    const md = await files[1]!.text;
    const body = md.split("\n").filter((l) => !l.startsWith("> ")).join("\n");
    expect(body).not.toMatch(/CONFIRMED|VIOLATION|SIMULATED|\bPASS\b/);
    for (const text of [await files[0]!.text, md]) expect(text).not.toContain("SECRET-TOKEN-123");
    expect(app.$("planStatus").textContent).toMatch(/Exported \d+ of 22 test specifications as Markdown/);
  });

  it("export buttons are disabled with nothing planned, and the empty states say what to do", async () => {
    app = await loadApp("2-test-lab");
    expect((app.$("planExportJson") as unknown as HTMLButtonElement).disabled).toBe(true);
    expect(app.$("tests").textContent).toMatch(/Load a model and plan tests/);
    expect(app.$("preview").textContent).toMatch(/Plan tests, then select a case/);
    app.click("planBtn");
    expect(app.$("modelStatus").textContent).toMatch(/No model yet/);
    app.setValue("modelText", "[1,2");
    app.click("planBtn");
    expect(app.$("modelStatus").textContent).toMatch(/Invalid model: the text is not valid JSON/);
    expect(app.$("modelStatus").getAttribute("role")).toBe("alert");
  });
});
