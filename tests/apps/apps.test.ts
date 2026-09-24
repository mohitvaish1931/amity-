import { afterEach, describe, expect, it } from "vitest";
import { loadApp, type LoadedApp } from "../../scripts/app-harness.mjs";
import { generateSampleModel } from "../../scripts/regen-sample.mjs";
import { fixture, readRepoFile } from "../helpers";

let app: LoadedApp | undefined;
afterEach(() => {
  app?.close();
  app = undefined;
});

describe("Step 1 app (1-security-twin) still works end to end", () => {
  it("builds the demo twin, laws and export from the real bundle", async () => {
    app = await loadApp("1-security-twin");
    app.click("demoBtn");
    await app.settle();
    app.click("buildBtn");
    expect(app.alerts).toEqual([]);
    expect(app.$("invCount").textContent).toBe("5 endpoints");
    expect(app.document.querySelectorAll("#discovery tr").length).toBe(6); // header + 5
    expect(app.document.querySelectorAll("#laws .law").length).toBe(4);
    const model = JSON.parse(app.$("out4").textContent!);
    expect(model.version).toBe("part1-v5-typed");
    expect(model.endpoints.map((e: { resource: string }) => e.resource)).toEqual(["User", "Order", "Order", "Invoice", "Refund"]);
  });

  it("accepts YAML specs", async () => {
    app = await loadApp("1-security-twin");
    app.click("demoBtn");
    await app.settle();
    app.setValue("swaggerText", fixture("e-recursive.yaml"));
    app.click("buildBtn");
    expect(app.alerts).toEqual([]);
    expect(app.$("invCount").textContent).toBe("2 endpoints");
    expect(app.$("discovery").textContent).toContain("/folders/{folderId}");
  });

  it("reports malformed specs instead of crashing", async () => {
    app = await loadApp("1-security-twin");
    app.click("demoBtn");
    await app.settle();
    app.setValue("swaggerText", '{"openapi": "3.0.0", "paths": ');
    app.click("buildBtn");
    expect(app.alerts.join("\n")).toMatch(/Invalid spec:\nInvalid JSON/);
  });

  it("applies sensitivity overrides without duplicating warnings on rebuild", async () => {
    app = await loadApp("1-security-twin");
    app.click("demoBtn");
    await app.settle();
    app.setValue("swaggerText", JSON.stringify({ openapi: "3.0.0", paths: { "/gadgets/{gadgetId}": { get: { responses: {} } } } }));
    app.click("buildBtn");
    const warningsBefore = app.$("discovery").querySelector(".note")!.textContent;
    app.click("applyConfig");
    app.click("applyConfig");
    expect(app.$("discovery").querySelector(".note")!.textContent).toBe(warningsBefore);

    const select = app.document.querySelector<HTMLSelectElement>('#sensTable select[data-f="gadgetId"]')!;
    select.value = "SENSITIVE";
    app.click("applySens");
    expect(app.$("sensTable").textContent).toContain("manual override by analyst");
  });
});

describe("Step 2 app (2-test-lab) still plans from the Step 1 model", () => {
  it("loads the demo model and plans all cases", async () => {
    app = await loadApp("2-test-lab");
    app.click("demoModelBtn");
    await app.settle();
    app.click("planBtn");
    expect(app.alerts).toEqual([]);
    expect(app.$("modelInfo").textContent).toMatch(/part1-v5-typed · 5 endpoints · 4 laws · 3 identities/);
    expect(app.document.querySelectorAll("#tests .test").length).toBe(22);
    expect(app.document.querySelectorAll("#authBox input[data-cred]").length).toBe(3);
  });
});

describe("demo sample model", () => {
  it("2-test-lab/samples/sample-testable-model.json matches what Step 1 generates today", async () => {
    const committed = readRepoFile("2-test-lab/samples/sample-testable-model.json").replace(/\r\n/g, "\n");
    expect(committed).toBe(await generateSampleModel());
  });
});
