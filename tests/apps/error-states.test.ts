// Loading / success / empty / error / retry states in the real app bundles. Nothing may fail silently.
import { afterEach, describe, expect, it } from "vitest";
import { loadApp, type LoadedApp } from "../../scripts/app-harness.mjs";

let app: LoadedApp | undefined;
afterEach(() => {
  app?.close();
  app = undefined;
});

/** Makes requests for `file` fail `times` times (like a missing file or a dropped connection), then succeed. */
function failFile(a: LoadedApp, file: string, times: number) {
  const real = a.window.fetch;
  let left = times;
  a.window.fetch = (async (url: string, init?: RequestInit) => {
    if (String(url).endsWith(file) && left-- > 0) return { ok: false, status: 404, text: async () => "not found" } as Response;
    return real(url, init);
  }) as typeof fetch;
}
const status = (a: LoadedApp, id: string) => ({ kind: a.$(id).dataset.status, role: a.$(id).getAttribute("role"), text: a.$(id).textContent! });

describe("Step 1 states", () => {
  it("reports a failed demo load with a retry that recovers", async () => {
    app = await loadApp("1-security-twin");
    failFile(app, "samples/sample-config.json", 1);
    app.click("demoBtn");
    await app.settle();
    expect(status(app, "buildStatus")).toMatchObject({ kind: "error", role: "alert" });
    expect(status(app, "buildStatus").text).toMatch(/Could not load the demo: samples\/sample-config\.json returned HTTP 404/);
    expect(app.$("identitiesEditor").value).toBe(""); // nothing half-loaded
    app.$("buildStatus").querySelector<HTMLButtonElement>(".status-retry")!.click();
    await app.settle();
    expect(status(app, "buildStatus")).toMatchObject({ kind: "success" });
    expect(app.$("identitiesEditor").value).not.toBe("");
  });

  it("explains an empty build, a bad configuration and a successful build", async () => {
    app = await loadApp("1-security-twin");
    app.click("buildBtn");
    expect(status(app, "buildStatus")).toMatchObject({ kind: "empty" });
    app.click("demoBtn");
    await app.settle();
    app.setValue("identitiesEditor", "[{");
    app.click("buildBtn");
    expect(status(app, "buildStatus")).toMatchObject({ kind: "error", role: "alert" });
    expect(status(app, "buildStatus").text).toMatch(/Invalid configuration/);
    app.click("demoBtn");
    await app.settle();
    app.click("buildBtn");
    const laws = JSON.parse(app.$("out3").textContent!).laws.length;
    expect(status(app, "buildStatus").text).toMatch(new RegExp(`Built from the spec: 5 endpoints, \\d+ resources, ${laws} laws`));
  });

  it("says when a later invalid spec leaves the previous build on screen", async () => {
    app = await loadApp("1-security-twin");
    app.click("demoBtn");
    await app.settle();
    app.click("buildBtn");
    app.setValue("swaggerText", "openapi: [");
    app.click("buildBtn");
    expect(status(app, "buildStatus").text).toMatch(/not rebuilt\. The results below are from the previous successful build/);
  });

  it("asks for a build before applying configuration", async () => {
    app = await loadApp("1-security-twin");
    app.click("demoBtn");
    await app.settle();
    app.click("applyConfig");
    expect(status(app, "applyStatus")).toMatchObject({ kind: "empty" });
  });

  it("reports a denied clipboard instead of claiming the copy worked", async () => {
    app = await loadApp("1-security-twin");
    Object.defineProperty(app.window.navigator, "clipboard", { value: { writeText: async () => Promise.reject(new Error("denied")) }, configurable: true });
    app.click("copy4");
    await app.settle();
    expect(status(app, "exportStatus")).toMatchObject({ kind: "error" });
    expect(status(app, "exportStatus").text).toMatch(/Copy failed \(denied\)/);
  });
});

describe("Step 2 states", () => {
  it("reports a failed demo model load with a retry that recovers", async () => {
    app = await loadApp("2-test-lab");
    failFile(app, "samples/sample-testable-model.json", 1);
    app.click("demoModelBtn");
    await app.settle();
    expect(status(app, "modelStatus")).toMatchObject({ kind: "error", role: "alert" });
    app.$("modelStatus").querySelector<HTMLButtonElement>(".status-retry")!.click();
    await app.settle();
    expect(status(app, "modelStatus")).toMatchObject({ kind: "success" });
  });

  it("explains an empty or invalid model and confirms a plan", async () => {
    app = await loadApp("2-test-lab");
    app.click("planBtn");
    expect(status(app, "modelStatus")).toMatchObject({ kind: "empty" });
    app.setValue("modelText", '{"endpoints": []}');
    app.click("planBtn");
    expect(status(app, "modelStatus").text).toMatch(/Invalid model: Not a testable-security-model/);
    app.setValue("modelText", "{");
    app.click("planBtn");
    expect(status(app, "modelStatus")).toMatchObject({ kind: "error" });
    app.click("demoModelBtn");
    await app.settle();
    app.click("planBtn");
    expect(status(app, "modelStatus").text).toMatch(/Planned 22 test cases from \d+ laws/);
  });

  it("guides the optional LLM features without blocking dialogs", async () => {
    app = await loadApp("2-test-lab");
    app.click("llmSuggestBtn");
    expect(status(app, "llmStatus")).toMatchObject({ kind: "info" });
    expect(app.alerts).toEqual([]);
  });
});
