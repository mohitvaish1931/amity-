import { describe, expect, it } from "vitest";
import { deriveTargetAuthorization, normalizeTargetUrl } from "../../src/target/authorization";

describe("deriveTargetAuthorization", () => {
  it("is UNKNOWN without a target", () => {
    for (const v of [undefined, null, "", "   "]) {
      expect(deriveTargetAuthorization(v)).toMatchObject({ state: "UNKNOWN", target: null, label: "No sandbox target configured" });
    }
  });

  it("is UNKNOWN for invalid or unsupported URLs", () => {
    for (const v of ["not a url", "ftp://files.example.test", "javascript:alert(1)", "https://user:pass@sandbox.example.test"]) {
      const a = deriveTargetAuthorization(v);
      expect(a.state).toBe("UNKNOWN");
      expect(a.label).toBe("Target URL is not valid");
    }
  });

  it("is only CONFIGURED for a valid URL: configuring is not authorization", () => {
    const a = deriveTargetAuthorization("https://sandbox.example.test/api/");
    expect(a).toMatchObject({ state: "CONFIGURED", target: "https://sandbox.example.test/api", label: "Sandbox target configured" });
    expect(a.detail).toMatch(/Authorization status unknown/);
  });

  it("is CONFIRMED only with a complete record for the same target", () => {
    const record = { targetUrl: "https://sandbox.example.test/api", confirmedBy: "owner@example.test", confirmedAt: "2026-09-24T10:00:00Z", scope: "read-only" };
    expect(deriveTargetAuthorization("https://sandbox.example.test/api/", record)).toMatchObject({ state: "CONFIRMED", label: "Authorization confirmed" });
    expect(deriveTargetAuthorization("https://other.example.test/api", record).state).toBe("CONFIGURED");
    expect(deriveTargetAuthorization("https://sandbox.example.test/api", { ...record, confirmedBy: "" }).state).toBe("CONFIGURED");
    expect(deriveTargetAuthorization("https://sandbox.example.test/api", null).state).toBe("CONFIGURED");
  });

  it("normalizes URLs for comparison", () => {
    expect(normalizeTargetUrl("HTTPS://Sandbox.Example.Test:443/v1//")).toBe("https://sandbox.example.test/v1");
    expect(normalizeTargetUrl("http://127.0.0.1:9000")).toBe("http://127.0.0.1:9000");
  });
});
