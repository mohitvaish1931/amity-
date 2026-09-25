// App-level regression tests for the sandbox authorization label (Step 1) and multi-parameter paths (Step 2).
import { afterEach, describe, expect, it } from "vitest";
import { loadApp, type LoadedApp } from "../../scripts/app-harness.mjs";
import { readRepoFile } from "../helpers";

let app: LoadedApp | undefined;
afterEach(() => {
  app?.close();
  app = undefined;
});

const typeUrl = (a: LoadedApp, value: string) => {
  const input = a.$("baseUrl");
  input.value = value;
  input.dispatchEvent(new a.window.Event("input", { bubbles: true }));
};

describe("Step 1 target authorization state", () => {
  it("renders from state, never from a hardcoded 'Authorized Sandbox' label", async () => {
    app = await loadApp("1-security-twin");
    const box = app.$("targetAuthState");
    // No built-in target: nothing is configured until the user (or the loaded spec) provides a URL.
    expect(app.$("baseUrl").value).toBe("");
    expect(box.dataset.state).toBe("UNKNOWN");
    expect(box.textContent).toMatch(/No sandbox target configured/);
    // Loading the demo takes the URL from the spec's servers: configuration, not authorization.
    app.click("demoBtn");
    await app.settle();
    expect(app.$("baseUrl").value).toBe(JSON.parse(readRepoFile("1-security-twin/samples/sample-swagger.json")).servers[0].url);
    expect(box.dataset.state).toBe("CONFIGURED");
    expect(box.textContent).toMatch(/Sandbox target configured/);
    expect(box.textContent).toMatch(/Authorization status unknown/);
    expect(app.document.body.textContent).not.toMatch(/Authorized Sandbox|Authorization confirmed/i);
  });

  it("does not overwrite a URL the user already entered when loading the demo", async () => {
    app = await loadApp("1-security-twin");
    typeUrl(app, "http://127.0.0.1:9000");
    app.click("demoBtn");
    await app.settle();
    expect(app.$("baseUrl").value).toBe("http://127.0.0.1:9000");
  });

  it("follows the URL field", async () => {
    app = await loadApp("1-security-twin");
    typeUrl(app, "");
    expect(app.$("targetAuthState").dataset.state).toBe("UNKNOWN");
    expect(app.$("targetAuthState").textContent).toMatch(/No sandbox target configured/);
    typeUrl(app, "ftp://nope.example.test");
    expect(app.$("targetAuthState").textContent).toMatch(/Target URL is not valid/);
    typeUrl(app, "http://127.0.0.1:9000");
    expect(app.$("targetAuthState").dataset.state).toBe("CONFIGURED");
  });

  it("shows the same state on the dashboard and in the exported model", async () => {
    app = await loadApp("1-security-twin");
    app.click("demoBtn");
    await app.settle();
    app.click("buildBtn");
    expect(app.$("dashboard").textContent).toMatch(/target: Sandbox target configured/);
    const model = JSON.parse(app.$("out4").textContent!);
    expect(model.targetAuthorization).toMatchObject({ state: "CONFIGURED", label: "Sandbox target configured" });
  });

  it("has no static authorization claim left in the page source", () => {
    const page = readRepoFile("1-security-twin/index.html");
    expect(page).not.toMatch(/Authorized Sandbox|🟢/);
  });
});

describe("Step 2 sandbox policy messaging", () => {
  const CLAIM = /AUTHORIZED SANDBOX ONLY|Authorized Sandbox|Authorization (is )?confirmed|authorization verified|🟢/i;

  it("states the policy without claiming authorization, before and after planning", async () => {
    app = await loadApp("2-test-lab");
    expect(app.document.querySelector(".sandbox-banner")!.textContent).toMatch(/^Policy · test only sandbox targets you are authorized to test/);
    expect(app.document.body.textContent).not.toMatch(CLAIM);
    app.click("demoModelBtn");
    await app.settle();
    app.click("planBtn");
    expect(app.document.body.textContent).not.toMatch(CLAIM);
  });

  it("has no static authorization claim left in the page source", () => {
    expect(readRepoFile("2-test-lab/index.html")).not.toMatch(CLAIM);
  });
});

describe("Step 2 multi-parameter paths", () => {
  function modelWith(endpoints: object[]) {
    const m = JSON.parse(readRepoFile("2-test-lab/samples/sample-testable-model.json"));
    m.endpoints.push(...endpoints);
    return JSON.stringify(m);
  }

  it("never plans a request path that still contains a {parameter}", async () => {
    app = await loadApp("2-test-lab");
    app.setValue(
      "modelText",
      modelWith([
        { id: "EP-006", method: "GET", path: "/orgs/{orgId}/orders/{orderId}", auth: true, resource: "Order", action: "Read" },
        { id: "EP-007", method: "POST", path: "/admin/users/{userId}/lock", auth: true, resource: "User", action: "AdminAction" },
      ]),
    );
    app.click("planBtn");
    expect(app.alerts).toEqual([]);
    const paths = [...app.document.querySelectorAll("#tests .test code:nth-of-type(2)")].map((c) => c.textContent!);
    expect(paths.length).toBeGreaterThan(0);
    expect(paths.filter((p) => p.includes("{"))).toEqual([]);
  });

  it("skips endpoints whose extra path parameters have no values, and says why", async () => {
    app = await loadApp("2-test-lab");
    app.setValue("modelText", modelWith([{ id: "EP-006", method: "GET", path: "/orgs/{orgId}/orders/{orderId}", auth: true, resource: "Order", action: "Read" }]));
    app.click("planBtn");
    const note = app.$("planner").querySelector(".note")!.textContent!;
    expect(note).toMatch(/BOLA: skipped GET \/orgs\/\{orgId\}\/orders\/\{orderId\} \(Missing value for path parameter "orgId"/);
    expect(note).toMatch(/DATA: skipped GET \/orgs\/\{orgId\}\/orders\/\{orderId\}/);
    // The anonymous probe still covers it, with every parameter filled by the placeholder.
    const text = app.$("tests").textContent!;
    expect(text).toContain("/orgs/1/orders/1");
    // The matrix explains instead of showing a broken path.
    expect(app.$("matrix").textContent).toMatch(/not planned — missing path parameter values/);
  });

  it("keeps the demo plan unchanged (22 cases, single-parameter paths filled as before)", async () => {
    app = await loadApp("2-test-lab");
    app.click("demoModelBtn");
    await app.settle();
    app.click("planBtn");
    expect(app.document.querySelectorAll("#tests .test")).toHaveLength(22);
    expect(app.$("planner").querySelector(".note")).toBeNull();
    expect(app.$("tests").textContent).toContain("/orders/102/invoice");
  });
});
