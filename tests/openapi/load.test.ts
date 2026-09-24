import { describe, expect, it } from "vitest";
import { parseApiSpec, parseApiSpecObject } from "../../src/openapi";
import { fixture, specFixture } from "../helpers";

describe("spec loading (fixture L: malformed specifications)", () => {
  const bad: [string, string, RegExp][] = [
    ["empty text", "   ", /empty/i],
    ["invalid JSON", '{"openapi": "3.0.0", "paths": {', /Invalid JSON/],
    ["invalid YAML", "openapi: 3.0.0\npaths:\n  /x: [unclosed", /Invalid YAML/],
    ["array root", "[1, 2, 3]", /must be a JSON\/YAML object/],
    ["scalar YAML root", "just a string", /must be a JSON\/YAML object/],
    ["missing version", '{"info": {}, "paths": {}}', /Missing version/],
    ["unsupported OpenAPI version", '{"openapi": "4.0.0", "paths": {}}', /Unsupported OpenAPI version/],
    ["unsupported Swagger version", '{"swagger": "1.2", "paths": {}}', /Unsupported Swagger version/],
    ["paths is not an object", '{"openapi": "3.0.0", "paths": "nope"}', /"paths" must be an object/],
  ];

  it.each(bad)("rejects %s with a clear error", (_label, text, pattern) => {
    const r = parseApiSpec(text);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.join("\n")).toMatch(pattern);
  });

  it("accepts YAML input (fixture E)", () => {
    const r = parseApiSpec(fixture("e-recursive.yaml"));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.spec.format).toBe("openapi-3.0");
      expect(r.spec.endpoints.map((e) => e.path)).toEqual(["/nodes/{nodeId}", "/folders/{folderId}"]);
    }
  });

  it("detects each supported format", () => {
    expect(specFixture("a-simple-oas3.json").format).toBe("openapi-3.0");
    expect(specFixture("m-composition-31.json").format).toBe("openapi-3.1");
    expect(specFixture("b-swagger2.json").format).toBe("swagger-2.0");
  });

  it("warns instead of failing when paths is missing", () => {
    const r = parseApiSpecObject({ openapi: "3.1.0", info: { title: "t", version: "1" } });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.spec.endpoints).toEqual([]);
      expect(r.spec.warnings.join("\n")).toMatch(/No paths object/);
    }
  });

  it("never throws on hostile structures", () => {
    const hostile = [
      { openapi: "3.0.0", paths: { "/a": { get: { parameters: "x", responses: 5, requestBody: [] } } } },
      { openapi: "3.0.0", paths: { "/a": { get: null, post: { security: "admin" } } } },
      { swagger: "2.0", paths: { "/a": { get: { parameters: [null, 1, { in: "body" }] } } }, definitions: 7 },
      { openapi: "3.0.0", paths: {}, components: { schemas: { A: { $ref: "#/components/schemas/A" } } } },
    ];
    for (const doc of hostile) expect(() => parseApiSpecObject(doc)).not.toThrow();
  });
});
