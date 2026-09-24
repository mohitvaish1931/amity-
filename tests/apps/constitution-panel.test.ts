// Application-level tests for the Constitution panel and law explorer (real Step 1 bundle in jsdom).
import { afterEach, describe, expect, it } from "vitest";
import { loadApp, type LoadedApp } from "../../scripts/app-harness.mjs";
import { readRepoFile } from "../helpers";

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
const cards = (a: LoadedApp) => [...a.document.querySelectorAll<HTMLDetailsElement>("#laws details.const-law")];
const card = (a: LoadedApp, id: string) => cards(a).find((d) => d.dataset.law === id)!;

describe("Constitution panel", () => {
  it("lists every law with id, category, severity, confidence and statement", async () => {
    app = await builtDemo();
    expect(app.alerts).toEqual([]);
    expect(cards(app).map((d) => d.dataset.law)).toEqual(["LAW-001", "LAW-002", "LAW-003", "LAW-004", "LAW-005", "LAW-006", "LAW-007"]);
    const summary = card(app, "LAW-001").querySelector("summary")!.textContent!;
    expect(summary).toMatch(/LAW-001/);
    expect(summary).toMatch(/Object authorization/);
    expect(summary).toMatch(/High/);
    expect(summary).toMatch(/HIGH · 100% of signals/);
    expect(summary).toMatch(/Customer may access only Order objects they own \(ownership field Order\.customerId\)\./);
    expect(app.$("laws").textContent).toMatch(/7 laws · 2 object authorization · 1 function authorization · 3 data exposure · 1 authentication/);
  });

  it("shows machine rule, scope, provenance, confidence rationale and test strategy", async () => {
    app = await builtDemo();
    const body = card(app, "LAW-001").textContent!;
    expect(body).toMatch(/Machine rule/);
    expect(body).toContain("o.customerId = c");
    expect(body).toMatch(/Endpoints:\s*EP-002 GET \/orders\/\{id\} · EP-004 GET \/orders\/\{id\}\/invoice/);
    expect(body).toMatch(/Identities:\s*User A \(customer_001\) · User B \(customer_002\)/);
    expect(body).toContain("schema:Order.customerId");
    expect(body).toContain("permission:Customer.View Foreign Order=false");
    expect(body).toMatch(/HIGH: ownership field \+ objects of ≥2 owners \+ authentication required/);
    expect(body).toMatch(/✅ ownership field Order\.customerId/);
    expect(body).toMatch(/cross-owner-object-access · specification only, not executed/);
    expect(card(app, "LAW-002").textContent).toMatch(/❌ no ownership field in the schema/);
  });

  it("highlights a law's scope in the graph from the panel", async () => {
    app = await builtDemo();
    const button = card(app, "LAW-004").querySelector<HTMLButtonElement>("[data-focus-law]")!;
    button.click();
    await app.settle();
    expect(card(app, "LAW-004").classList.contains("is-focused")).toBe(true);
    expect(card(app, "LAW-001").classList.contains("is-focused")).toBe(false);
    const highlighted = [...app.document.querySelectorAll(".twin-node.is-highlight .twin-label")].map((n) => n.textContent).sort();
    // LAW-004: Invoice data exposure, entitlement inherited from Order.customerId; applies to non-privileged callers (Customer)
    expect(highlighted).toEqual(["/orders/{id}/invoice", "Customer", "Invoice", "LAW-004", "Order", "customerId", "paymentMetadata"]);
    expect(app.document.querySelector<HTMLSelectElement>('[data-testid="twin-law-filter"]')!.value).toBe("LAW-004");
    expect(app.errors).toEqual([]);
  });

  it("derives different laws from a different model (no demo hardcoding)", async () => {
    app = await loadApp("1-security-twin");
    app.setValue("swaggerText", readRepoFile("tests/fixtures/constitution/marketplace.json"));
    app.setValue("identitiesEditor", JSON.stringify([
      { id: "m1", name: "Merchant One", role: "Merchant" },
      { id: "m2", name: "Merchant Two", role: "Merchant" },
      { id: "ops1", name: "Ops", role: "Administrator" },
    ]));
    app.setValue("permissionsEditor", JSON.stringify({ Merchant: { "Delete Listing": false }, Administrator: { "Manage Payouts": true } }));
    app.setValue("ownershipEditor", JSON.stringify({ "L-1": "m1", "L-2": "m2" }));
    app.click("buildBtn");
    await app.settle();
    expect(app.alerts).toEqual([]);
    const statements = cards(app).map((d) => d.querySelector(".const-statement")!.textContent);
    expect(statements).toContain("Merchant may access only Listing objects they own (ownership field Listing.ownerId).");
    expect(statements).toContain("Only Administrator may invoke POST /admin/payouts; Merchant must be denied.");
    expect(statements.join(" ")).not.toMatch(/Order|Customer|Refund/);
  });

  it("exports the full constitution next to the Step 2 contract", async () => {
    app = await builtDemo();
    const model = JSON.parse(app.$("out4").textContent!);
    expect(model.constitution.version).toBe("constitution-v1");
    expect(model.constitution.laws).toHaveLength(7);
    expect(model.laws.map((l: { category: string }) => l.category)).toEqual(["BOLA", "ADMIN", "DATA", "AUTHN"]);
    expect(JSON.parse(app.$("out3").textContent!).laws).toHaveLength(7);
  });
});
