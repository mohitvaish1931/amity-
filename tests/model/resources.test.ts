import { describe, expect, it } from "vitest";
import type { ApiModel } from "../../src/contracts";
import { buildApiModel, inferAction, resourceName, schemaBaseName, singularize } from "../../src/model";
import { findEndpoint, modelFixture, readRepoFile, specOf } from "../helpers";

const resource = (m: ApiModel, name: string) => {
  const r = m.resources.find((x) => x.name === name);
  if (!r) throw new Error(`resource ${name} missing; have ${m.resources.map((x) => x.name).join(", ")}`);
  return r;
};

describe("naming helpers", () => {
  it.each([
    ["orders", "order"],
    ["addresses", "address"],
    ["categories", "category"],
    ["boxes", "box"],
    ["status", "status"],
    ["analysis", "analysis"],
    ["people", "person"],
  ])("singularize(%s) = %s", (plural, single) => expect(singularize(plural)).toBe(single));

  it("builds singular PascalCase resource names", () => {
    expect(resourceName("line-items")).toBe("LineItem");
    expect(resourceName("purchase_orders")).toBe("PurchaseOrder");
  });

  it("strips request/response affixes from schema names", () => {
    expect(schemaBaseName("CreatePurchaseRequest")).toBe("Purchase");
    expect(schemaBaseName("OrderListResponse")).toBe("Order");
    expect(schemaBaseName("Invoices")).toBe("Invoice");
    expect(schemaBaseName("Error")).toBeNull();
    expect(schemaBaseName("Response")).toBeNull();
  });
});

describe("action inference", () => {
  it.each([
    ["GET", "/items", "List"],
    ["GET", "/items/{id}", "Read"],
    ["POST", "/items", "Create"],
    ["PUT", "/items/{id}", "Update"],
    ["PATCH", "/items/{id}", "Update"],
    ["DELETE", "/items/{id}", "Delete"],
    ["POST", "/admin/refund", "AdminAction"],
    ["GET", "/v1/administration/users", "AdminAction"],
    ["OPTIONS", "/items", "Other"],
  ])("%s %s -> %s", (method, path, action) => expect(inferAction(method, path)).toBe(action));

  it("treats a singular segment after an id as a single object, a plural one as a list", () => {
    expect(inferAction("GET", "/orders/{id}/invoice")).toBe("Read");
    expect(inferAction("GET", "/orders/{id}/items")).toBe("List");
  });

  it("lets the response schema decide when it is known", () => {
    expect(inferAction("GET", "/reports/latest", false)).toBe("Read");
    expect(inferAction("GET", "/orders/{id}", true)).toBe("List");
  });
});

describe("resource inference", () => {
  it("uses the last static path segment, not the first (multi-param paths, fixture F)", () => {
    const m = modelFixture("f-multi-path-params.json");
    const task = findEndpoint(m.endpoints, "GET", "/tenants/{tenantId}/projects/{projectId}/tasks/{taskId}");
    expect(task.resource).toBe("Task");
    expect(task.resourceEvidence.map((e) => e.source)).toEqual(["schema", "path", "operationId"]);
    expect(task.resourceConfidence).toBe(1);
  });

  it("treats a trailing verb after an id as an action on the parent resource", () => {
    const m = modelFixture("f-multi-path-params.json");
    expect(findEndpoint(m.endpoints, "POST", "/orders/{orderId}/cancel").resource).toBe("Order");
  });

  it("combines path, schema, operationId and tag evidence (fixture M)", () => {
    const m = modelFixture("m-composition-31.json");
    const pet = findEndpoint(m.endpoints, "GET", "/pets/{petId}");
    expect(pet.resource).toBe("Pet");
    expect(pet.resourceEvidence).toEqual([
      { source: "path", value: "Pet", weight: 3 },
      { source: "operationId", value: "Pet", weight: 2 },
      { source: "tag", value: "Pet", weight: 1 },
    ]);
  });

  it("maps request schemas with affixes to the resource (fixture J)", () => {
    const m = modelFixture("j-request-body-ref.json");
    expect(m.endpoints[0]!.resource).toBe("Purchase");
    expect(resource(m, "Purchase").schemaNames).toEqual(["CreatePurchaseRequest"]);
  });

  it("does not hardcode any domain vocabulary", () => {
    const text = JSON.stringify({
      openapi: "3.0.0",
      paths: {
        "/sellers/{sellerId}/listings/{listingId}": {
          get: { responses: { "200": { description: "ok", content: { "application/json": { schema: { $ref: "#/components/schemas/Listing" } } } } } },
        },
      },
      components: {
        schemas: { Listing: { type: "object", properties: { id: { type: "string" }, sellerId: { type: "string" }, merchantSecret: { type: "string" } } } },
      },
    });
    const m = buildApiModel(specOf(text));
    expect(m.endpoints[0]!.resource).toBe("Listing");
    const listing = resource(m, "Listing");
    expect(listing.fields.find((f) => f.name === "merchantSecret")?.sensitivity).toBe("SENSITIVE");
  });
});

describe("resources, ownership and relationships", () => {
  it("detects ownership fields generically and ignores a resource's own id", () => {
    const m = modelFixture("f-multi-path-params.json");
    const task = resource(m, "Task");
    expect(task.ownershipField).toBe("assigneeUserId");
    expect(task.identifierFields).toEqual(["id", "tenantId", "assigneeUserId"]);

    const users = buildApiModel(
      specOf(JSON.stringify({
        openapi: "3.0.0",
        paths: { "/users/{id}": { get: { responses: { "200": { description: "", content: { "application/json": { schema: { $ref: "#/components/schemas/User" } } } } } } } },
        components: { schemas: { User: { type: "object", properties: { id: { type: "string" }, userId: { type: "string" } } } } },
      })),
    );
    expect(resource(users, "User").ownershipField).toBeNull();
  });

  it("never picks an internal reference as the ownership field", () => {
    const m = buildApiModel(
      specOf(JSON.stringify({
        openapi: "3.0.0",
        paths: { "/tickets/{id}": { get: { responses: { "200": { description: "", content: { "application/json": { schema: { $ref: "#/components/schemas/Ticket" } } } } } } } },
        components: { schemas: { Ticket: { type: "object", properties: { internalUserId: { type: "string" }, accountId: { type: "string" } } } } },
      })),
    );
    expect(resource(m, "Ticket").ownershipField).toBe("accountId");
  });

  it("classifies nested and array fields, not only top-level ones (fixtures C, D)", () => {
    const account = resource(modelFixture("c-nested.json"), "Account");
    const sens = Object.fromEntries(account.fields.map((f) => [f.path, f.sensitivity]));
    expect(sens["holder.email"]).toBe("PERSONAL");
    expect(sens["holder.apiToken"]).toBe("SENSITIVE");
    expect(sens["holder.mailing.street"]).toBe("PERSONAL");

    const project = resource(modelFixture("d-arrays.json"), "Project");
    expect(project.fields.find((f) => f.path === "members[].ssn")?.sensitivity).toBe("SENSITIVE");
  });

  it("records references and which endpoints return or accept a schema", () => {
    const account = resource(modelFixture("c-nested.json"), "Account");
    expect(account.relations).toEqual(
      expect.arrayContaining([
        { from: "Account", to: "PostalAddress", kind: "references", via: "holder.mailing" },
        { from: "Account", to: "EP-001", kind: "returned-by", via: "EP-001" },
      ]),
    );
  });

  it("falls back to the path parameter as identifier when no schema exists, with a warning", () => {
    const m = buildApiModel(specOf(JSON.stringify({ openapi: "3.0.0", paths: { "/gadgets/{gadgetId}": { get: { responses: {} } } } })));
    expect(resource(m, "Gadget").fields.map((f) => f.name)).toEqual(["gadgetId"]);
    expect(m.warnings.join("\n")).toMatch(/Resource Gadget: no schema fields/);
  });
});

describe("demo spec (1-security-twin/samples/sample-swagger.json)", () => {
  const m = buildApiModel(specOf(readRepoFile("1-security-twin/samples/sample-swagger.json")));

  it("infers one resource per operation from path + schema evidence", () => {
    expect(m.endpoints.map((e) => `${e.method} ${e.path} -> ${e.resource}/${e.action}`)).toEqual([
      "GET /users/{id} -> User/Read",
      "GET /orders/{id} -> Order/Read",
      "POST /orders -> Order/Create",
      "GET /orders/{id}/invoice -> Invoice/Read",
      "POST /admin/refund -> Refund/AdminAction",
    ]);
  });

  it("finds the ownership field and keeps identifier references public", () => {
    const order = resource(m, "Order");
    expect(order.ownershipField).toBe("customerId");
    expect(order.fields.find((f) => f.name === "customerId")?.sensitivity).toBe("PUBLIC");
    expect(order.fields.find((f) => f.name === "paymentMetadata")?.sensitivity).toBe("SENSITIVE");
  });

  it("reads fields of the inline admin request body", () => {
    expect(resource(m, "Refund").fields.map((f) => f.name)).toEqual(["orderId"]);
  });
});
