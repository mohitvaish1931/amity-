import { describe, expect, it } from "vitest";
import { findEndpoint, specFixture } from "../helpers";

describe("normalization: OpenAPI 3 (fixture A)", () => {
  const spec = specFixture("a-simple-oas3.json");

  it("reads info and substitutes server variables", () => {
    expect(spec.title).toBe("Fixture A: simple OpenAPI 3");
    expect(spec.apiVersion).toBe("1.2.0");
    expect(spec.servers).toEqual(["https://sandbox.example.test/v1"]);
  });

  it("assigns stable endpoint ids in document order", () => {
    expect(spec.endpoints.map((e) => `${e.id} ${e.method} ${e.path}`)).toEqual([
      "EP-001 GET /items",
      "EP-002 GET /items/{itemId}",
      "EP-003 DELETE /items/{itemId}",
    ]);
  });

  it("keeps query and header parameters with their schemas", () => {
    const list = findEndpoint(spec.endpoints, "GET", "/items");
    const limit = list.parameters.find((p) => p.name === "limit")!;
    expect(limit).toMatchObject({ in: "query", required: false });
    expect(limit.schema.type).toBe("integer");
    const header = list.parameters.find((p) => p.name === "X-Request-Id")!;
    expect(header).toMatchObject({ in: "header", required: true });
  });

  it("describes array responses with their item schema", () => {
    const list = findEndpoint(spec.endpoints, "GET", "/items");
    const content = list.responses.find((r) => r.status === "200")!.contents[0]!;
    expect(content.contentType).toBe("application/json");
    expect(content.schema).toMatchObject({ type: "array", isArray: true, itemRefName: "Item" });
    expect(content.schema!.fields.map((f) => f.path)).toEqual(["id", "title", "status"]);
  });

  it("records every response status, including ones without content", () => {
    const get = findEndpoint(spec.endpoints, "GET", "/items/{itemId}");
    expect(get.responses.map((r) => r.status)).toEqual(["200", "404"]);
    expect(get.responses[1]!.contents).toEqual([]);
  });
});

describe("normalization: Swagger 2.0 (fixture B)", () => {
  const spec = specFixture("b-swagger2.json");

  it("builds server URLs from schemes + host + basePath", () => {
    expect(spec.servers).toEqual(["https://api.sandbox.test/v2", "http://api.sandbox.test/v2"]);
  });

  it("turns an in:body parameter into a requestBody using root-level consumes", () => {
    const create = findEndpoint(spec.endpoints, "POST", "/widgets");
    expect(create.parameters).toEqual([]);
    expect(create.requestBody?.required).toBe(true);
    expect(create.requestBody?.contents.map((c) => c.contentType)).toEqual(["application/json"]);
    expect(create.requestBody?.contents[0]!.schema?.refName).toBe("Widget");
  });

  it("uses root-level produces for response content types", () => {
    const create = findEndpoint(spec.endpoints, "POST", "/widgets");
    const created = create.responses.find((r) => r.status === "201")!;
    expect(created.contents.map((c) => c.contentType)).toEqual(["application/json"]);
    expect(created.contents[0]!.schema?.refName).toBe("Widget");
  });

  it("resolves path-level parameter $refs and keeps inline Swagger 2 types", () => {
    const get = findEndpoint(spec.endpoints, "GET", "/widgets/{widgetId}");
    const id = get.parameters.find((p) => p.name === "widgetId")!;
    expect(id).toMatchObject({ in: "path", required: true });
    expect(id.schema.type).toBe("integer");
    const fields = get.parameters.find((p) => p.name === "fields")!;
    expect(fields.schema).toMatchObject({ type: "array", isArray: true });
  });

  it("turns formData parameters into a multipart requestBody", () => {
    const upload = findEndpoint(spec.endpoints, "POST", "/widgets/{widgetId}/photo");
    expect(upload.requestBody?.contents.map((c) => c.contentType)).toEqual(["multipart/form-data"]);
    const fields = upload.requestBody!.contents[0]!.schema!.fields;
    expect(fields.map((f) => [f.name, f.type, f.required])).toEqual([
      ["file", "file", true],
      ["caption", "string", false],
    ]);
  });

  it("honours x-nullable in Swagger 2 schemas", () => {
    const notes = spec.schemas.Widget!.fields.find((f) => f.name === "notes")!;
    expect(notes.nullable).toBe(true);
  });
});

describe("normalization: multiple path parameters (fixture F)", () => {
  const spec = specFixture("f-multi-path-params.json");
  const task = findEndpoint(spec.endpoints, "GET", "/tenants/{tenantId}/projects/{projectId}/tasks/{taskId}");

  it("merges path-level and operation-level parameters, operation wins on (name, in)", () => {
    expect(task.parameters.map((p) => p.name)).toEqual(["tenantId", "projectId", "taskId"]);
    const project = task.parameters.find((p) => p.name === "projectId")!;
    expect(project.description).toBe("operation-level override");
    expect(project.schema.type).toBe("integer");
  });

  it("resolves $ref parameters", () => {
    expect(task.parameters.find((p) => p.name === "tenantId")).toMatchObject({ in: "path", required: true });
  });

  it("synthesizes undeclared path parameters with a warning", () => {
    const stores = findEndpoint(spec.endpoints, "GET", "/regions/{regionCode}/stores");
    expect(stores.parameters).toEqual([
      expect.objectContaining({ name: "regionCode", in: "path", required: true }),
    ]);
    expect(spec.warnings.join("\n")).toMatch(/\{regionCode\}.*not declared/);
  });
});

describe("normalization: requestBody and responses through $ref (fixtures J, K)", () => {
  it("follows a chain of requestBody $refs and keeps every content type", () => {
    const spec = specFixture("j-request-body-ref.json");
    const post = findEndpoint(spec.endpoints, "POST", "/purchases");
    expect(post.requestBody?.required).toBe(true);
    expect(post.requestBody?.contents.map((c) => c.contentType)).toEqual(["application/json", "application/xml"]);
    const schema = post.requestBody!.contents[0]!.schema!;
    expect(schema.refName).toBe("CreatePurchaseRequest");
    expect(schema.fields.map((f) => [f.name, f.required])).toEqual([
      ["sku", true],
      ["quantity", false],
      ["cardNumber", false],
    ]);
  });

  it("resolves response $refs, including non-JSON media types", () => {
    const spec = specFixture("k-response-ref.json");
    const get = findEndpoint(spec.endpoints, "GET", "/shipments/{shipmentId}");
    const ok = get.responses.find((r) => r.status === "200")!;
    expect(ok.description).toBe("shipment");
    expect(ok.contents[0]!.schema?.refName).toBe("Shipment");
    const missing = get.responses.find((r) => r.status === "404")!;
    expect(missing.contents[0]!.contentType).toBe("application/problem+json");
    expect(missing.contents[0]!.schema?.refName).toBe("Error");
  });
});

describe("normalization: broken references (fixture L)", () => {
  const spec = specFixture("l-malformed-refs.json");
  const warnings = spec.warnings.join("\n");

  it("keeps parsing and reports each problem", () => {
    expect(warnings).toMatch(/Unresolved \$ref "#\/components\/parameters\/DoesNotExist"/);
    expect(warnings).toMatch(/parameter without a valid "name"\/"in" skipped/);
    expect(warnings).toMatch(/External \$ref .* not supported/);
    expect(warnings).toMatch(/Circular \$ref chain/);
    expect(warnings).toMatch(/Path "\/also-broken": path item could not be resolved/);
  });

  it("still produces the resolvable parts of the operation", () => {
    expect(spec.endpoints).toHaveLength(1);
    const ep = spec.endpoints[0]!;
    expect(ep.requestBody).toBeNull();
    expect(ep.parameters).toEqual([expect.objectContaining({ name: "id", in: "path" })]);
    expect(ep.responses.map((r) => r.status)).toEqual(["200"]);
    expect(ep.responses[0]!.contents[0]!.schema).toMatchObject({ refName: "Missing", fields: [] });
  });
});
