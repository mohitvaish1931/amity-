import { describe, expect, it } from "vitest";
import { analyzeSpecText } from "../../src/model";
import { fixture, readRepoFile } from "../helpers";

describe("analyzeSpecText + legacy view used by the browser apps", () => {
  it("returns parse errors instead of throwing", () => {
    const r = analyzeSpecText("{broken");
    expect(r.ok).toBe(false);
  });

  it("maps auth modes to the legacy boolean without losing detail", () => {
    const r = analyzeSpecText(fixture("g-public.json"));
    if (!r.ok) throw new Error(r.errors.join());
    const byPath = Object.fromEntries(r.view.endpoints.map((e) => [e.path, e]));
    expect(byPath["/health"]).toMatchObject({ auth: false, authMode: "public" });
    expect(byPath["/catalog"]).toMatchObject({ auth: false, authMode: "optional" });
    expect(byPath["/cart"]).toMatchObject({ auth: true, authMode: "required", authInferred: false });
  });

  it("exposes schema names, content types and parameters per endpoint", () => {
    const r = analyzeSpecText(fixture("a-simple-oas3.json"));
    if (!r.ok) throw new Error(r.errors.join());
    const list = r.view.endpoints[0]!;
    expect(list).toMatchObject({ respSchemaName: "Item[]", respRef: "Item", respContentTypes: ["application/json"] });
    expect(list.params).toEqual([
      { name: "limit", in: "query", required: false, type: "integer" },
      { name: "X-Request-Id", in: "header", required: true, type: "string" },
    ]);
    expect(r.view.specInfo).toEqual({ version: "OpenAPI 3.0.3", servers: ["https://sandbox.example.test/v1"], title: "Fixture A: simple OpenAPI 3" });
  });

  it("applies analyst sensitivity overrides by Resource.fieldPath", () => {
    const text = readRepoFile("1-security-twin/samples/sample-swagger.json");
    const r = analyzeSpecText(text, { "Order.status": "INTERNAL" });
    if (!r.ok) throw new Error(r.errors.join());
    expect(r.view.resources.Order!.fields.status).toMatchObject({ sensitivity: "INTERNAL", reason: "manual override by analyst" });
    expect(r.view.resources.Order!.ownershipField).toBe("customerId");
  });
});
