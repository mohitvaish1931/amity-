// Application-level rendering test: the real Step 1 bundle in jsdom, driven like a user.
import { afterEach, describe, expect, it } from "vitest";
import { loadApp, type LoadedApp } from "../../scripts/app-harness.mjs";

let app: LoadedApp | undefined;
afterEach(() => {
  app?.close();
  app = undefined;
});

async function builtDemo(): Promise<LoadedApp> {
  const a = await loadApp("1-security-twin");
  a.click("demoBtn");
  await a.settle();
  a.click("buildBtn");
  await a.settle();
  return a;
}

const q = (a: LoadedApp, sel: string) => [...a.document.querySelectorAll<HTMLElement>(sel)];
const change = async (a: LoadedApp, el: HTMLSelectElement, value: string) => {
  el.value = value;
  el.dispatchEvent(new a.window.Event("change", { bubbles: true }));
  await a.settle();
};

describe("Security Twin graph in Step 1", () => {
  it("shows an empty state before a model exists", async () => {
    app = await loadApp("1-security-twin");
    expect(app.$("twinGraph").textContent).toMatch(/Click BUILD SECURITY TWIN/);
    expect(q(app, ".react-flow")).toHaveLength(0);
  });

  it("renders one node per model entity from the demo spec and config", async () => {
    app = await builtDemo();
    expect(app.errors).toEqual([]);
    const count = (t: string) => q(app!, `.twin-node.twin-${t}`).length;
    expect({ identity: count("identity"), role: count("role"), endpoint: count("endpoint"), resource: count("resource"), law: count("law") }).toEqual({
      identity: 3,
      role: 2,
      endpoint: 5,
      resource: 4,
      law: 7,
    });
    expect(count("field")).toBeGreaterThan(0);
    expect(q(app, ".react-flow__edge").length).toBeGreaterThan(0);
    expect(app.document.querySelector('[data-testid="twin-counts"]')!.textContent).toMatch(/3 identities · 2 roles · 5 endpoints · 4 resources · \d+ fields · 7 security laws · \d+ relationships/);
  });

  it("uses only model data: endpoint and resource labels match the parsed spec", async () => {
    app = await builtDemo();
    const labels = q(app, ".twin-endpoint .twin-label").map((e) => e.textContent);
    expect(labels.sort()).toEqual(["/admin/refund", "/orders", "/orders/{id}", "/orders/{id}/invoice", "/users/{id}"]);
    expect(q(app, ".twin-resource .twin-label").map((e) => e.textContent).sort()).toEqual(["Invoice", "Order", "Refund", "User"]);
  });

  it("opens the detail panel with relationships and laws when a node is clicked", async () => {
    app = await builtDemo();
    const order = q(app, ".react-flow__node").find((n) => n.querySelector(".twin-resource .twin-label")?.textContent === "Order")!;
    order.click();
    await app.settle();
    const panel = app.document.querySelector('[data-testid="twin-panel"]')!;
    expect(panel.querySelector("h4")!.textContent).toBe("Order");
    expect(panel.textContent).toMatch(/ownershipField\s*customerId/);
    expect(panel.textContent).toMatch(/OWNS ← /);
    expect(panel.textContent).toMatch(/LAW-001/);
    // Navigating from the panel selects the related node.
    const lawLink = [...panel.querySelectorAll<HTMLButtonElement>("button.twin-link")].find((b) => b.textContent === "LAW-001")!;
    lawLink.click();
    await app.settle();
    expect(app.document.querySelector('[data-testid="twin-panel"] h4')!.textContent).toBe("LAW-001");
  });

  it("shows edge provenance when an edge is clicked", async () => {
    app = await builtDemo();
    const edge = q(app, ".react-flow__edge").find((e) => e.classList.contains("rel-owns"))!;
    expect(edge).toBeDefined();
    edge.dispatchEvent(new app.window.MouseEvent("click", { bubbles: true }));
    await app.settle();
    const panel = app.document.querySelector('[data-testid="twin-panel"]')!;
    expect(panel.textContent).toMatch(/Relationship/);
    expect(panel.textContent).toMatch(/OWNS/);
    expect(panel.textContent).toMatch(/configuration ownership map/);
  });

  it("switches field visibility and highlights a law's scope", async () => {
    app = await builtDemo();
    const keyFields = q(app, ".twin-field").length;
    const fieldMode = app.document.querySelector<HTMLSelectElement>('[data-testid="twin-field-mode"]')!;
    await change(app, fieldMode, "all");
    expect(q(app, ".twin-field").length).toBeGreaterThan(keyFields);
    await change(app, fieldMode, "none");
    expect(q(app, ".twin-field")).toHaveLength(0);

    const lawFilter = app.document.querySelector<HTMLSelectElement>('[data-testid="twin-law-filter"]')!;
    expect([...lawFilter.options].map((o) => o.value)).toEqual(["", "LAW-001", "LAW-002", "LAW-003", "LAW-004", "LAW-005", "LAW-006", "LAW-007"]);
    await change(app, lawFilter, "LAW-003"); // the administrative-endpoint law
    const highlighted = q(app, ".twin-node.is-highlight").map((n) => n.querySelector(".twin-label")!.textContent);
    expect(highlighted.sort()).toEqual(["/admin/refund", "Admin", "Administrator", "Customer", "LAW-003", "Refund", "User A", "User B"]);
    expect(q(app, ".twin-node.is-dim").length).toBeGreaterThan(0);
  });

  it("keeps working through fit view, reset layout and a rebuild", async () => {
    app = await builtDemo();
    app.document.querySelector<HTMLButtonElement>('[data-testid="twin-fit"]')!.click();
    app.document.querySelector<HTMLButtonElement>('[data-testid="twin-reset"]')!.click();
    await app.settle();
    app.click("applyConfig");
    await app.settle();
    expect(q(app, ".twin-node.twin-endpoint")).toHaveLength(5);
    expect(app.errors).toEqual([]);
    expect(app.document.querySelector('[data-testid="twin-error"]')).toBeNull();
  });

  it("renders arbitrary models, not just the demo", async () => {
    app = await loadApp("1-security-twin");
    app.setValue("swaggerText", JSON.stringify({
      openapi: "3.0.0",
      paths: { "/tenants/{tenantId}/projects/{projectId}": { get: { responses: { "200": { description: "", content: { "application/json": { schema: { $ref: "#/components/schemas/Project" } } } } } } } },
      components: { schemas: { Project: { type: "object", properties: { id: { type: "string" }, ownerId: { type: "string" }, apiToken: { type: "string" } } } } },
    }));
    app.setValue("identitiesEditor", JSON.stringify([{ id: "p1", name: "Person One", role: "Member" }]));
    app.setValue("permissionsEditor", "{}");
    app.setValue("ownershipEditor", JSON.stringify({ "prj-1": "p1" }));
    app.click("buildBtn");
    await app.settle();
    expect(app.alerts).toEqual([]);
    expect(q(app, ".twin-resource .twin-label").map((e) => e.textContent)).toEqual(["Project"]);
    expect(q(app, ".twin-field .twin-label").map((e) => e.textContent).sort()).toEqual(["apiToken", "ownerId"]);
    expect(q(app, ".react-flow__edge.rel-owns")).toHaveLength(1);
  });
});
