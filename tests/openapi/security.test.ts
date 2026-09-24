import { describe, expect, it } from "vitest";
import { findEndpoint, specFixture, specOf } from "../helpers";

describe("public endpoints (fixture G)", () => {
  const spec = specFixture("g-public.json");

  it("security: [] at operation level is explicitly public", () => {
    const auth = findEndpoint(spec.endpoints, "GET", "/health").auth;
    expect(auth).toMatchObject({ mode: "public", source: "operation", alternatives: [] });
  });

  it("security: [{}] makes authentication optional, not required", () => {
    const auth = findEndpoint(spec.endpoints, "GET", "/catalog").auth;
    expect(auth.mode).toBe("optional");
    expect(auth.alternatives.map((a) => a.schemes.map((s) => s.name))).toEqual([[], ["session"]]);
    expect(auth.detail).toMatch(/anonymous OR session/);
  });

  it("operations without security inherit the root requirement", () => {
    const auth = findEndpoint(spec.endpoints, "GET", "/cart").auth;
    expect(auth).toMatchObject({ mode: "required", source: "root" });
    expect(auth.alternatives[0]!.schemes[0]).toMatchObject({ name: "session", type: "apiKey", in: "cookie", paramName: "sid" });
  });
});

describe("authenticated endpoints (fixture H)", () => {
  const spec = specFixture("h-authenticated.json");

  it("inherits root bearer auth and normalizes the scheme name", () => {
    const auth = findEndpoint(spec.endpoints, "GET", "/profile").auth;
    expect(auth.mode).toBe("required");
    expect(auth.alternatives[0]!.schemes[0]).toMatchObject({ name: "bearer", type: "http", scheme: "bearer", known: true });
  });

  it("keeps AND within a requirement and OR across requirements, with scopes", () => {
    const auth = findEndpoint(spec.endpoints, "GET", "/reports").auth;
    expect(auth.mode).toBe("required");
    expect(auth.alternatives.map((a) => a.schemes.map((s) => s.name))).toEqual([["apiKey", "appId"], ["oauth"]]);
    expect(auth.alternatives[1]!.schemes[0]!.scopes).toEqual(["reports:read"]);
    expect(auth.detail).toBe("operation security: (apiKey AND appId) OR oauth[reports:read]");
  });

  it("flags requirements that reference undeclared schemes", () => {
    const auth = findEndpoint(spec.endpoints, "GET", "/legacy").auth;
    expect(auth.alternatives[0]!.schemes[0]).toMatchObject({ name: "ghostScheme", known: false });
    expect(spec.warnings.join("\n")).toMatch(/undeclared scheme "ghostScheme"/);
  });
});

describe("operation-level security override (fixture I)", () => {
  const spec = specFixture("i-security-override.json");

  it("inherits root when the operation declares nothing", () => {
    const auth = findEndpoint(spec.endpoints, "GET", "/things").auth;
    expect(auth.source).toBe("root");
    expect(auth.alternatives[0]!.schemes[0]!.name).toBe("apiKey");
  });

  it("replaces root with the operation requirement", () => {
    const auth = findEndpoint(spec.endpoints, "POST", "/things").auth;
    expect(auth.source).toBe("operation");
    expect(auth.alternatives.map((a) => a.schemes.map((s) => s.name))).toEqual([["bearer"]]);
  });

  it("an operation-level [] overrides a root requirement to public", () => {
    expect(findEndpoint(spec.endpoints, "GET", "/things/public").auth).toMatchObject({ mode: "public", source: "operation" });
  });
});

describe("no security declared anywhere", () => {
  it("is public per spec, and says so", () => {
    const spec = specOf(JSON.stringify({ openapi: "3.0.0", paths: { "/x": { get: { responses: {} } } } }));
    expect(spec.endpoints[0]!.auth).toMatchObject({ mode: "public", source: "none" });
    expect(spec.endpoints[0]!.auth.detail).toMatch(/no security requirement declared/);
  });

  it("declaring schemes without applying them does not make operations protected", () => {
    const spec = specOf(
      JSON.stringify({
        openapi: "3.0.0",
        paths: { "/x": { get: { responses: {} } } },
        components: { securitySchemes: { b: { type: "http", scheme: "bearer" } } },
      }),
    );
    expect(spec.endpoints[0]!.auth.mode).toBe("public");
    expect(spec.securitySchemes.b).toMatchObject({ type: "http", scheme: "bearer" });
  });

  it("ignores a non-array security value with a warning", () => {
    const spec = specOf(JSON.stringify({ openapi: "3.0.0", security: [{ k: [] }], paths: { "/x": { get: { security: "k", responses: {} } } } }));
    expect(spec.endpoints[0]!.auth).toMatchObject({ mode: "required", source: "root" });
    expect(spec.warnings.join("\n")).toMatch(/"security" must be an array/);
  });
});
