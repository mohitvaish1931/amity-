import { describe, expect, it } from "vitest";
import { classifyField } from "../../src/model";

describe("field sensitivity classification", () => {
  const cases: [string, string | undefined, string][] = [
    // credentials / payment / secrets
    ["password", undefined, "SENSITIVE"],
    ["apiToken", undefined, "SENSITIVE"],
    ["api_key", undefined, "SENSITIVE"],
    ["paymentMetadata", undefined, "SENSITIVE"],
    ["cardNumber", undefined, "SENSITIVE"],
    ["ssn", undefined, "SENSITIVE"],
    ["refreshToken", undefined, "SENSITIVE"],
    // personal data
    ["email", undefined, "PERSONAL"],
    ["recipientPhone", undefined, "PERSONAL"],
    ["address", undefined, "PERSONAL"],
    ["username", undefined, "PERSONAL"],
    ["customerName", undefined, "PERSONAL"],
    ["displayName", undefined, "PERSONAL"],
    ["dateOfBirth", undefined, "PERSONAL"],
    // internal
    ["internalUserId", undefined, "INTERNAL"],
    ["createdBy", undefined, "INTERNAL"],
    ["debugInfo", undefined, "INTERNAL"],
    // public, including audit false positives from the previous substring matcher
    ["customerId", undefined, "PUBLIC"],
    ["orderId", undefined, "PUBLIC"],
    ["filename", undefined, "PUBLIC"],
    ["hostname", undefined, "PUBLIC"],
    ["status", undefined, "PUBLIC"],
    ["amount", undefined, "PUBLIC"],
  ];

  it.each(cases)("%s -> %s", (name, resource, expected) => {
    expect(classifyField(name, resource).level).toBe(expected);
  });

  it("treats a bare 'name' as personal only on person-like resources", () => {
    expect(classifyField("name", "Customer").level).toBe("PERSONAL");
    expect(classifyField("name", "UserProfile").level).toBe("PERSONAL");
    expect(classifyField("name", "Product").level).toBe("PUBLIC");
    expect(classifyField("name").level).toBe("PUBLIC");
  });

  it("explains every decision", () => {
    expect(classifyField("apiToken").reason).toMatch(/token/);
    expect(classifyField("customerId").reason).toMatch(/identifier/);
    expect(classifyField("amount").reason).toMatch(/no sensitive pattern/);
  });
});
