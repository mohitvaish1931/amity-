import { describe, expect, it } from "vitest";
import { readdirSync } from "node:fs";
import path from "node:path";
import type { ApiModel, SecurityConstitution } from "../../src/contracts";
import { generateSecurityConstitution, legacyCategoryOf, toLegacyLaws } from "../../src/constitution";
import { buildApiModel } from "../../src/model";
import { ROOT, readRepoFile, specOf } from "../helpers";
import { endpointIds, lawByKey, marketplace, marketplaceConfig, marketplaceModel, marketplaceRoles } from "./helpers";

const model = marketplaceModel();
const c = marketplace();
const ids = (...labels: string[]) => endpointIds(model, ...labels);

describe("1. ownership (object authorization) laws", () => {
  const listing = lawByKey(c, "OBJECT_AUTHORIZATION:Listing");

  it("derives the owner-only rule from the ownership field and the configured owners", () => {
    expect(listing.statement).toBe("Merchant may access only Listing objects they own (ownership field Listing.ownerId).");
    expect(listing.rule).toEqual({
      type: "owner-only-access",
      resource: "Listing",
      ownershipField: "ownerId",
      subjectRoles: ["Merchant"],
      endpoints: ids("GET /listings/{listingId}", "DELETE /listings/{listingId}", "PATCH /listings/{listingId}", "POST /listings/{listingId}/publish", "GET /listings/{listingId}/reviews").sort(),
      operations: ["read", "write"],
    });
    expect(listing.invariant).toContain("o.ownerId = c");
  });

  it("excludes roles whose permissions grant access to other identities' objects", () => {
    expect(listing.appliesTo.roles).toEqual(["Merchant"]);
    expect(listing.provenance).toContainEqual({ kind: "role", ref: "role:Support", detail: "exempt: permission allows access to other identities' objects" });
  });

  it("covers child paths addressed through the resource's identifier", () => {
    expect(listing.appliesTo.endpoints).toContain(ids("GET /listings/{listingId}/reviews")[0]);
  });

  it("does not apply the ownership map to resources without an ownership field", () => {
    const buyer = lawByKey(c, "OBJECT_AUTHORIZATION:Buyer");
    expect(buyer.statement).toMatch(/does not describe who owns a Buyer/);
    expect(buyer.provenance.some((p) => p.kind === "ownership")).toBe(false);
    expect(buyer.rule).toMatchObject({ ownershipField: null });
  });
});

describe("2. role-restricted (function authorization) laws", () => {
  it("restricts administrative endpoints to privileged roles, confirmed by an explicit deny", () => {
    const admin = lawByKey(c, "FUNCTION_AUTHORIZATION:admin:Payout");
    expect(admin.statement).toBe("Only Operator may invoke POST /admin/payouts; Buyer, Merchant and Support must be denied.");
    expect(admin.rule).toEqual({ type: "role-restricted", endpoints: ids("POST /admin/payouts"), allowedRoles: ["Operator"], deniedRoles: ["Buyer", "Merchant", "Support"] });
    expect(admin.provenance.map((p) => p.ref)).toEqual(expect.arrayContaining(["permission:Buyer.Manage Payouts=false", "permission:Operator.Manage Payouts=true"]));
    expect(admin.provenance).toContainEqual({ kind: "role", ref: "role:Operator", detail: "privileged: configured as operations staff" });
  });

  it("turns an explicit deny permission into a law scoped to the matching endpoints only", () => {
    const del = lawByKey(c, "FUNCTION_AUTHORIZATION:Listing:delete");
    expect(del.statement).toBe("Buyer must not delete Listing (DELETE /listings/{listingId}).");
    expect(del.appliesTo.endpoints).toEqual(ids("DELETE /listings/{listingId}"));
  });

  it("keeps unmatched but contested permissions as a LOW permission-matrix law", () => {
    const matrix = lawByKey(c, "FUNCTION_AUTHORIZATION:matrix");
    expect(matrix.rule).toEqual({ type: "permission-matrix", roles: ["Merchant", "Operator"], contestedActions: ["Export reports"] });
    expect(matrix.appliesTo.endpoints).toEqual([]);
    expect(matrix.confidence).toBe("LOW");
  });

  it("without a privileged role, administrative laws are LOW and say so", () => {
    const noPriv = marketplace({ ...marketplaceConfig, roles: marketplaceRoles.map((r) => ({ ...r, privileged: false })) });
    const admin = lawByKey(noPriv, "FUNCTION_AUTHORIZATION:admin:Payout");
    expect(admin.confidence).toBe("LOW");
    expect(admin.statement).toMatch(/must be restricted to a privileged role; none is configured/);
    expect(noPriv.notes).toContain("Administrative endpoints exist but no privileged role is configured.");
  });
});

describe("3. authentication laws", () => {
  it("groups endpoints by their effective security requirement", () => {
    const bearer = lawByKey(c, "AUTHENTICATION:bearer");
    expect(bearer.rule).toMatchObject({ type: "requires-authentication", schemes: ["bearer"] });
    expect(bearer.appliesTo.endpoints).toHaveLength(9);
    expect(bearer.confidence).toBe("HIGH");
  });

  it("rates a requirement naming an undeclared scheme lower", () => {
    const ghost = lawByKey(c, "AUTHENTICATION:ghostKey");
    expect(ghost.confidence).toBe("MEDIUM");
    expect(ghost.provenance).toContainEqual({ kind: "security", ref: "security:ghostKey", detail: "referenced but not declared in the spec" });
  });
});

describe("4. data-exposure law candidates", () => {
  it("scopes each law to one resource, its returning endpoints and its sensitive fields", () => {
    const listing = lawByKey(c, "DATA_EXPOSURE:Listing");
    expect(listing.appliesTo).toMatchObject({ endpoints: ids("GET /listings/{listingId}", "PATCH /listings/{listingId}").sort(), resources: ["Listing"], fields: ["Listing.payoutAccountNumber"] });
    expect(listing.severity).toBe("High");
  });

  it("inherits entitlement from an owned parent the resource is only reachable through", () => {
    const review = lawByKey(c, "DATA_EXPOSURE:Review");
    expect(review.statement).toBe("Review responses must not expose authorEmail to callers who do not own the parent Listing (ownership field Listing.ownerId).");
    expect(review.rule).toMatchObject({ ownershipField: null, inheritedFrom: "Listing.ownerId" });
    expect(review.provenance.map((p) => p.ref)).toEqual(expect.arrayContaining(["relationship:Review→Listing", "schema:Listing.ownerId"]));
  });

  it("marks entitlement as undefined when neither the resource nor a parent is owned", () => {
    const buyer = lawByKey(c, "DATA_EXPOSURE:Buyer");
    expect(buyer.statement).toMatch(/only to callers entitled to that Buyer/);
    expect(buyer.confidence).toBe("LOW");
  });

  it("reflects analyst sensitivity overrides", () => {
    const withOverride = marketplace({ ...marketplaceConfig, sensitivityOverrides: { "Listing.title": "SENSITIVE" } });
    const listing = lawByKey(withOverride, "DATA_EXPOSURE:Listing");
    expect(listing.appliesTo.fields).toContain("Listing.title");
    expect(listing.confidence).toBe("HIGH");
    expect(listing.provenance).toContainEqual({ kind: "sensitivity", ref: "sensitivity:Listing.title=SENSITIVE", detail: "analyst override" });
  });
});

describe("5. public endpoint handling", () => {
  it("flags explicitly public endpoints that return sensitive fields", () => {
    const pub = lawByKey(c, "SECURITY_CONFIGURATION:public");
    expect(pub.appliesTo.endpoints).toEqual(ids("GET /stores/{storeId}/card", "GET /catalog").sort());
    expect(pub.rule).toMatchObject({ mode: "public", exposesSensitiveFields: ["Store.supportEmail"] });
    expect(pub.severity).toBe("High");
  });

  it("keeps optional-auth endpoints separate and uses correct wording", () => {
    const opt = lawByKey(c, "SECURITY_CONFIGURATION:optional");
    expect(opt.statement).toBe("GET /ops/metrics accepts anonymous requests (security: [{}]); this must be intentional and it must not return sensitive data.");
  });

  it("never puts public or optional endpoints in an authentication law", () => {
    const authEps = c.laws.filter((l) => l.category === "AUTHENTICATION").flatMap((l) => l.appliesTo.endpoints);
    for (const id of ids("GET /stores/{storeId}/card", "GET /catalog", "GET /ops/metrics")) expect(authEps).not.toContain(id);
  });

  it("rates intent as LOW when no security is declared anywhere", () => {
    const bare = generateSecurityConstitution(buildApiModel(specOf(JSON.stringify({ openapi: "3.0.0", paths: { "/ping": { get: { responses: {} } } } }))));
    expect(bare.laws.map((l) => [l.key, l.confidence])).toEqual([["SECURITY_CONFIGURATION:undeclared", "LOW"]]);
  });
});

describe("6. operation-level security overrides", () => {
  it("an operation override moves the endpoint out of the root requirement's law", () => {
    const bearer = lawByKey(c, "AUTHENTICATION:bearer");
    expect(bearer.appliesTo.endpoints).not.toContain(ids("GET /legacy/export")[0]);
    expect(lawByKey(c, "AUTHENTICATION:ghostKey").appliesTo.endpoints).toEqual(ids("GET /legacy/export"));
    expect(lawByKey(c, "SECURITY_CONFIGURATION:undeclared-schemes")).toMatchObject({ confidence: "HIGH", rule: { undeclaredSchemes: ["ghostKey"] } });
  });
});

describe("7. unrelated-resource exclusion", () => {
  it("a law never reaches endpoints of another resource that merely shares field names", () => {
    const store = lawByKey(c, "DATA_EXPOSURE:Store");
    const buyerEp = ids("GET /buyers/{buyerId}")[0]!;
    expect(store.appliesTo.endpoints).not.toContain(buyerEp);
    expect(store.appliesTo.fields).toEqual(["Store.supportEmail"]);
    expect(lawByKey(c, "DATA_EXPOSURE:Buyer").appliesTo.fields).toEqual(["Buyer.email", "Buyer.shippingAddress"]);
  });

  it("creating a child under a parent is not a state transition of the child", () => {
    const state = lawByKey(c, "STATE_TRANSITION:Listing.status");
    expect(state.appliesTo.endpoints).toEqual(ids("PATCH /listings/{listingId}", "POST /listings/{listingId}/publish").sort());
    expect(state.appliesTo.endpoints).not.toContain(ids("POST /stores/{storeId}/listings")[0]);
  });
});

/** Every provenance ref must point at something that exists in the model or configuration. */
function assertProvenanceIsReal(con: SecurityConstitution, m: ApiModel, roleNames: string[], permissionKeys: string[]) {
  const endpointLabels = new Set(m.endpoints.map((e) => `${e.method} ${e.path}`));
  const schemaRefs = new Set(m.resources.flatMap((r) => r.fields.map((f) => `${r.name}.${f.path}`)));
  const schemes = new Set(m.endpoints.flatMap((e) => e.auth.alternatives.flatMap((a) => a.schemes.map((s) => s.name))));
  for (const law of con.laws) {
    expect(law.provenance.length).toBeGreaterThan(0);
    for (const p of law.provenance) {
      const [kind, rest] = [p.ref.slice(0, p.ref.indexOf(":")), p.ref.slice(p.ref.indexOf(":") + 1)];
      if (kind === "endpoint") expect(endpointLabels.has(rest)).toBe(true);
      else if (kind === "schema") expect(schemaRefs.has(rest)).toBe(true);
      else if (kind === "sensitivity") expect(schemaRefs.has(rest.split("=")[0]!)).toBe(true);
      else if (kind === "security") expect(schemes.has(rest)).toBe(true);
      else if (kind === "role") expect(roleNames).toContain(rest);
      else if (kind === "permission") expect(permissionKeys).toContain(rest);
      else if (kind === "relationship") expect(rest.split("→").every((r) => m.resources.some((x) => x.name === r))).toBe(true);
      else expect(p.ref).toBe("ownership:config");
    }
  }
}

describe("8. provenance", () => {
  it("every reference exists in the model or the configuration (none invented)", () => {
    const perms = marketplaceRoles.flatMap((r) => Object.entries(r.permissions).map(([k, v]) => `${r.name}.${k}=${v}`));
    assertProvenanceIsReal(c, model, marketplaceRoles.map((r) => r.name), perms);
  });

  it("records the configured owners with their objects", () => {
    expect(lawByKey(c, "OBJECT_AUTHORIZATION:Listing").provenance).toContainEqual({
      kind: "ownership",
      ref: "ownership:config",
      detail: "configured owners: Merchant One (L-1, S-1); Merchant Two (L-2)",
    });
  });
});

describe("9. confidence", () => {
  it("assigns levels from evidence, as documented per category", () => {
    const levels = Object.fromEntries(c.laws.map((l) => [l.key, l.confidence]));
    expect(levels).toEqual({
      "OBJECT_AUTHORIZATION:Listing": "HIGH", // ownership field + 2 owners + auth
      "OBJECT_AUTHORIZATION:Store": "MEDIUM", // ownership field, but GET /stores/{id}/card is public
      "OBJECT_AUTHORIZATION:Buyer": "LOW", // no ownership field
      "FUNCTION_AUTHORIZATION:admin:Payout": "HIGH", // privileged role + explicit deny
      "FUNCTION_AUTHORIZATION:Listing:delete": "MEDIUM", // name-matched permission, never HIGH
      "FUNCTION_AUTHORIZATION:matrix": "LOW",
      "DATA_EXPOSURE:Listing": "MEDIUM", // heuristic sensitivity, not analyst-confirmed
      "DATA_EXPOSURE:Review": "MEDIUM",
      "DATA_EXPOSURE:Store": "MEDIUM",
      "DATA_EXPOSURE:Buyer": "LOW",
      "AUTHENTICATION:bearer": "HIGH",
      "AUTHENTICATION:ghostKey": "MEDIUM",
      "STATE_TRANSITION:Listing.status": "MEDIUM", // never HIGH: no transition table in OpenAPI
      "SECURITY_CONFIGURATION:undeclared-schemes": "HIGH",
      "SECURITY_CONFIGURATION:public": "MEDIUM",
      "SECURITY_CONFIGURATION:optional": "MEDIUM",
    });
  });

  it("explains every rating with signals and the rule that was applied", () => {
    for (const law of c.laws) {
      expect(law.confidenceRationale.level).toBe(law.confidence);
      expect(law.confidenceRationale.rule).toMatch(/HIGH|MEDIUM|LOW/);
      expect(law.confidenceRationale.signals.length).toBeGreaterThan(0);
      const present = law.confidenceRationale.signals.filter((s) => s.present).length;
      expect(law.confidenceRationale.score).toBe(Math.round((present / law.confidenceRationale.signals.length) * 100));
    }
    const store = lawByKey(c, "OBJECT_AUTHORIZATION:Store");
    expect(store.confidenceRationale.signals.find((s) => s.id === "authenticated")).toMatchObject({ present: false });
  });

  it("drops to LOW/MEDIUM when the evidence behind HIGH is removed", () => {
    const noMap = marketplace({ ...marketplaceConfig, ownership: [] });
    expect(lawByKey(noMap, "OBJECT_AUTHORIZATION:Listing").confidence).toBe("MEDIUM");
    const noDeny = marketplace({ ...marketplaceConfig, roles: marketplaceRoles.map((r) => (r.name === "Buyer" ? { ...r, permissions: {} } : r)) });
    expect(lawByKey(noDeny, "FUNCTION_AUTHORIZATION:admin:Payout").confidence).toBe("MEDIUM");
  });
});

describe("10. duplicate-law suppression", () => {
  it("every law key is unique", () => {
    expect(new Set(c.laws.map((l) => l.key)).size).toBe(c.laws.length);
    expect(new Set(c.laws.map((l) => l.id)).size).toBe(c.laws.length);
  });

  it("merges several signals for the same rule into one law with all provenance", () => {
    const roles = marketplaceRoles.map((r) => (r.name === "Support" ? { ...r, permissions: { ...r.permissions, "Delete Listing": false } } : r));
    const merged = marketplace({ ...marketplaceConfig, roles });
    const dels = merged.laws.filter((l) => l.key === "FUNCTION_AUTHORIZATION:Listing:delete");
    expect(dels).toHaveLength(1);
    expect(dels[0]!.rule).toMatchObject({ deniedRoles: ["Buyer", "Support"] });
    expect(dels[0]!.statement).toBe("Buyer and Support must not delete Listing (DELETE /listings/{listingId}).");
    expect(dels[0]!.provenance.map((p) => p.ref)).toEqual(expect.arrayContaining(["permission:Buyer.Delete Listing=false", "permission:Support.Delete Listing=false"]));
  });

  it("one object law per resource even when many endpoints and permissions point at it", () => {
    expect(c.laws.filter((l) => l.key === "OBJECT_AUTHORIZATION:Listing")).toHaveLength(1);
    expect(lawByKey(c, "OBJECT_AUTHORIZATION:Listing").provenance.filter((p) => p.kind === "path")).toHaveLength(5);
  });
});

describe("11. precise scope", () => {
  it("lists exactly the governed endpoints, fields, roles and identities", () => {
    expect(lawByKey(c, "OBJECT_AUTHORIZATION:Listing").appliesTo).toEqual({
      endpoints: ids("GET /listings/{listingId}", "DELETE /listings/{listingId}", "PATCH /listings/{listingId}", "POST /listings/{listingId}/publish", "GET /listings/{listingId}/reviews").sort(),
      resources: ["Listing"],
      fields: ["Listing.ownerId"],
      roles: ["Merchant"],
      identities: ["m1", "m2"],
    });
    expect(lawByKey(c, "FUNCTION_AUTHORIZATION:admin:Payout").appliesTo.identities).toEqual(["b1", "m1", "m2", "ops1", "sup1"]);
    expect(lawByKey(c, "AUTHENTICATION:bearer").appliesTo).toMatchObject({ resources: [], fields: [], roles: [], identities: [] });
  });

  it("notes when the ownership map could belong to several resources", () => {
    expect(lawByKey(c, "OBJECT_AUTHORIZATION:Store").testStrategy.preconditions).toContain("The ownership map is not typed by resource; confirm these objects are Stores.");
  });
});

describe("12. determinism", () => {
  it("produces identical output for identical input", () => {
    expect(marketplace()).toEqual(marketplace());
  });

  it("does not depend on the order of configuration entries", () => {
    const shuffled = marketplace({
      identities: [...marketplaceConfig.identities!].reverse(),
      roles: [...marketplaceRoles].reverse(),
      ownership: [...marketplaceConfig.ownership!].reverse(),
    });
    const strip = (x: SecurityConstitution) => x.laws.map((l) => ({ ...l, provenance: l.provenance.map((p) => p.ref).sort() }));
    expect(strip(shuffled).map((l) => [l.id, l.key, l.confidence, l.appliesTo])).toEqual(strip(c).map((l) => [l.id, l.key, l.confidence, l.appliesTo]));
  });
});

describe("test strategies are specifications only", () => {
  it("every law has a non-executable strategy with steps and an expected outcome", () => {
    for (const law of c.laws) {
      expect(law.testStrategy.executable).toBe(false);
      expect(law.testStrategy.steps.length).toBeGreaterThan(0);
      expect(law.testStrategy.expected.length).toBeGreaterThan(0);
    }
  });

  it("the engine contains no network or request code", () => {
    const dir = path.join(ROOT, "src", "constitution");
    for (const file of readdirSync(dir)) {
      const src = readRepoFile(`src/constitution/${file}`);
      expect(src).not.toMatch(/\bfetch\(|XMLHttpRequest|from "node:http|from "https?"|require\("https?"\)|WebSocket/);
    }
  });
});

describe("demo spec (1-security-twin samples)", () => {
  const demoModel = buildApiModel(specOf(readRepoFile("1-security-twin/samples/sample-swagger.json")));
  const cfg = JSON.parse(readRepoFile("1-security-twin/samples/sample-config.json")) as {
    identities: { id: string; name: string; role: string }[];
    permissions: Record<string, Record<string, boolean>>;
    ownership: Record<string, string>;
  };
  const demo = generateSecurityConstitution(demoModel, {
    identities: cfg.identities,
    roles: Object.keys(cfg.permissions).map((name) => ({ name, permissions: cfg.permissions[name]!, privileged: name === "Administrator", privilegeEvidence: "name heuristic" })),
    ownership: Object.entries(cfg.ownership).map(([objectId, ownerId]) => ({ objectId, ownerId })),
  });

  it("derives 7 laws from the demo model and configuration", () => {
    expect(demo.laws.map((l) => `${l.id} ${l.key} ${l.confidence}`)).toEqual([
      "LAW-001 OBJECT_AUTHORIZATION:Order HIGH",
      "LAW-002 OBJECT_AUTHORIZATION:User LOW",
      "LAW-003 FUNCTION_AUTHORIZATION:admin:Refund HIGH",
      "LAW-004 DATA_EXPOSURE:Invoice MEDIUM",
      "LAW-005 DATA_EXPOSURE:Order MEDIUM",
      "LAW-006 DATA_EXPOSURE:User LOW",
      "LAW-007 AUTHENTICATION:bearerAuth HIGH",
    ]);
    expect(lawByKey(demo, "OBJECT_AUTHORIZATION:Order").statement).toBe("Customer may access only Order objects they own (ownership field Order.customerId).");
  });

  it("keeps the Step 2 contract: one legacy law per category in the historical order", () => {
    const legacy = toLegacyLaws(demo);
    expect(legacy.map((l) => [l.id, l.category, l.constitutionLawIds])).toEqual([
      ["LAW-001", "BOLA", ["LAW-001", "LAW-002"]],
      ["LAW-003", "ADMIN", ["LAW-003"]],
      ["LAW-004", "DATA", ["LAW-004", "LAW-005", "LAW-006"]],
      ["LAW-007", "AUTHN", ["LAW-007"]],
    ]);
    expect(legacy[0]).toMatchObject({ confidence: "HIGH" });
  });

  it("takes each legacy score from the primary law's signals, not from a fixed number per confidence level", () => {
    for (const l of toLegacyLaws(demo)) {
      const primary = demo.laws.find((x) => x.id === l.constitutionLawIds[0])!;
      expect(l.score).toBe(primary.confidenceRationale.score);
    }
  });

  it("maps every category to a legacy category", () => {
    expect(c.laws.map((l) => `${l.category}:${legacyCategoryOf(l)}`)).toEqual(
      expect.arrayContaining(["STATE_TRANSITION:POLICY", "SECURITY_CONFIGURATION:AUTHN", "SECURITY_CONFIGURATION:POLICY", "FUNCTION_AUTHORIZATION:ROLE"]),
    );
  });
});
