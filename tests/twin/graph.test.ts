import { describe, expect, it } from "vitest";
import type { ApiModel, Finding } from "../../src/contracts";
import { buildApiModel } from "../../src/model";
import { buildTwinGraph, describeEdge, describeNode, lawHighlight, nodeId, type TwinGraph, type TwinGraphInput } from "../../src/twin/graph";
import { specOf } from "../helpers";

// A generic marketplace-style API (deliberately unrelated to the demo shop).
const SPEC = {
  openapi: "3.0.3",
  security: [{ bearer: [] }],
  paths: {
    "/stores/{storeId}": {
      get: { parameters: [{ name: "storeId", in: "path", required: true, schema: { type: "string" } }], responses: { "200": { description: "", content: { "application/json": { schema: { $ref: "#/components/schemas/Store" } } } } } },
    },
    "/stores/{storeId}/listings": {
      post: {
        parameters: [{ name: "storeId", in: "path", required: true, schema: { type: "string" } }],
        requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/Listing" } } } },
        responses: { "201": { description: "" } },
      },
    },
    "/listings/{listingId}": {
      get: { parameters: [{ name: "listingId", in: "path", required: true, schema: { type: "string" } }], responses: { "200": { description: "", content: { "application/json": { schema: { $ref: "#/components/schemas/Listing" } } } } } },
    },
    "/admin/audit": { get: { responses: { "200": { description: "" } } } },
    "/health": { get: { security: [], responses: { "200": { description: "" } } } },
  },
  components: {
    securitySchemes: { bearer: { type: "http", scheme: "bearer" } },
    schemas: {
      Store: { type: "object", properties: { id: { type: "string" }, merchantId: { type: "string" }, supportEmail: { type: "string" }, name: { type: "string" } } },
      Listing: {
        type: "object",
        properties: { id: { type: "string" }, storeId: { type: "string" }, ownerId: { type: "string" }, title: { type: "string" }, payoutAccountNumber: { type: "string" } },
      },
    },
  },
};

const model: ApiModel = buildApiModel(specOf(JSON.stringify(SPEC)));
const ep = (method: string, path: string) => model.endpoints.find((e) => e.method === method && e.path === path)!.id;

const baseInput: TwinGraphInput = {
  endpoints: model.endpoints,
  resources: model.resources,
  identities: [
    { id: "m1", name: "Merchant One", role: "Merchant" },
    { id: "m2", name: "Merchant Two", role: "Merchant" },
    { id: "ops", name: "Ops", role: "Operator" },
  ],
  roles: [
    { name: "Merchant", permissions: { "Edit own listing": true, "View audit": false }, privileged: false },
    { name: "Operator", permissions: { "View audit": true }, privileged: true },
    { name: "Auditor", permissions: {}, privileged: false }, // declared but nobody has it
  ],
  ownership: [
    { objectId: "L-1", ownerId: "m1" },
    { objectId: "L-2", ownerId: "m2" },
  ],
  privilegedEndpoints: [ep("GET", "/admin/audit")],
  laws: [
    {
      id: "LAW-001",
      category: "BOLA",
      severity: "High",
      title: "Merchants access only owned listings.",
      confidence: "HIGH",
      score: 90,
      invariant: "owner(o)==caller",
      source: "spec+config",
      appliesTo: { endpoints: [ep("GET", "/listings/{listingId}")], resources: ["Listing"], fields: ["Listing.ownerId"], roles: ["Merchant"] },
    },
  ],
};

const types = (g: TwinGraph, source: string, target: string) => g.edges.find((e) => e.source === source && e.target === target)?.types;

describe("buildTwinGraph: nodes", () => {
  const g = buildTwinGraph(baseInput);
  const byType = (t: string) => g.nodes.filter((n) => n.type === t).map((n) => n.label);

  it("creates one node per model entity, grouped and sorted deterministically", () => {
    expect(byType("identity")).toEqual(["Merchant One", "Merchant Two", "Ops"]);
    expect(byType("role")).toEqual(["Auditor", "Merchant", "Operator"]);
    expect(byType("endpoint")).toEqual(["GET /stores/{storeId}", "POST /stores/{storeId}/listings", "GET /listings/{listingId}", "GET /admin/audit", "GET /health"]);
    expect(byType("resource").sort()).toEqual(["Audit", "Health", "Listing", "Store"]);
    expect(byType("law")).toEqual(["LAW-001"]);
    expect(g.nodes.map((n) => n.type)).toEqual([...g.nodes.map((n) => n.type)].sort((a, b) => ["identity", "role", "endpoint", "resource", "field", "law"].indexOf(a) - ["identity", "role", "endpoint", "resource", "field", "law"].indexOf(b)));
  });

  it("carries real metadata and provenance from the model", () => {
    const listing = g.nodes.find((n) => n.id === nodeId.endpoint(ep("GET", "/listings/{listingId}")))!;
    expect(listing.meta).toMatchObject({ method: "GET", action: "Read", auth: "required", resource: "Listing" });
    expect((listing.meta.resourceEvidence as string[]).some((x) => x.startsWith("schema: Listing"))).toBe(true);
    const res = g.nodes.find((n) => n.id === nodeId.resource("Listing"))!;
    expect(res.meta).toMatchObject({ ownershipField: "ownerId", sensitiveFields: 1 });
    expect(g.nodes.find((n) => n.id === nodeId.law("LAW-001"))!.meta).toMatchObject({ confidence: "HIGH", score: 90, category: "BOLA" });
  });

  it("counts relationships per node", () => {
    const merchant = g.nodes.find((n) => n.id === nodeId.role("Merchant"))!;
    expect(merchant.degree).toBe(3); // two HAS_ROLE + one GOVERNS
  });

  it("preserves disconnected entities", () => {
    const auditor = g.nodes.find((n) => n.id === nodeId.role("Auditor"))!;
    expect(auditor.degree).toBe(0);
  });

  it("shows only key fields by default and reports totals", () => {
    expect(byType("field").sort()).toEqual(["ownerId", "payoutAccountNumber", "supportEmail"]);
    expect(g.stats).toEqual({ fieldsTotal: 9, fieldsShown: 3 }); // Store 4 + Listing 5; Audit/Health have no schema or path param
  });
});

describe("buildTwinGraph: edges", () => {
  const g = buildTwinGraph(baseInput);

  it("links identities to roles and owners to owned resources", () => {
    expect(types(g, nodeId.identity("m1"), nodeId.role("Merchant"))).toEqual(["HAS_ROLE"]);
    expect(types(g, nodeId.identity("m1"), nodeId.resource("Listing"))).toEqual(["OWNS"]);
    expect(g.edges.find((e) => e.source === nodeId.identity("m1") && e.types.includes("OWNS"))!.provenance[0]).toMatch(/L-1.*Listing\.ownerId/);
    expect(g.edges.some((e) => e.source === nodeId.identity("ops") && e.types.includes("OWNS"))).toBe(false);
  });

  it("derives READS/WRITES from the endpoint action and RETURNS from response schemas", () => {
    expect(types(g, nodeId.endpoint(ep("POST", "/stores/{storeId}/listings")), nodeId.resource("Listing"))).toEqual(["WRITES"]);
    expect(types(g, nodeId.endpoint(ep("GET", "/listings/{listingId}")), nodeId.resource("Listing"))).toEqual(["READS", "RETURNS"]);
  });

  it("links resources that reference each other", () => {
    expect(types(g, nodeId.resource("Listing"), nodeId.resource("Store"))).toEqual(["RELATES_TO"]);
  });

  it("marks sensitive fields as EXPOSES and ownership fields as HAS_FIELD", () => {
    expect(types(g, nodeId.resource("Listing"), nodeId.field("Listing", "payoutAccountNumber"))).toEqual(["EXPOSES"]);
    expect(types(g, nodeId.resource("Listing"), nodeId.field("Listing", "ownerId"))).toEqual(["HAS_FIELD"]);
  });

  it("connects privileged endpoints to privileged roles only", () => {
    const audit = nodeId.endpoint(ep("GET", "/admin/audit"));
    expect(types(g, audit, nodeId.role("Operator"))).toEqual(["REQUIRES_ROLE"]);
    expect(types(g, audit, nodeId.role("Merchant"))).toBeUndefined();
  });

  it("maps law scope to GOVERNS edges", () => {
    const law = nodeId.law("LAW-001");
    const governed = g.edges.filter((e) => e.source === law).map((e) => e.target).sort();
    expect(governed).toEqual([nodeId.endpoint(ep("GET", "/listings/{listingId}")), nodeId.field("Listing", "ownerId"), nodeId.resource("Listing"), nodeId.role("Merchant")].sort());
  });

  it("never creates VIOLATES edges without findings", () => {
    expect(g.edges.some((e) => e.types.includes("VIOLATES"))).toBe(false);
  });
});

describe("buildTwinGraph: robustness", () => {
  it("returns an empty graph for an empty model", () => {
    expect(buildTwinGraph({})).toEqual({ nodes: [], edges: [], stats: { fieldsTotal: 0, fieldsShown: 0 } });
  });

  it("merges duplicate relationships and drops edges to unknown entities", () => {
    const g = buildTwinGraph({
      ...baseInput,
      ownership: [...baseInput.ownership!, { objectId: "L-1", ownerId: "m1" }, { objectId: "X", ownerId: "ghost" }],
      laws: [{ id: "LAW-9", appliesTo: { endpoints: [ep("GET", "/health"), ep("GET", "/health"), "EP-999"], resources: ["Nope"], fields: ["Store.missing", "malformed"] } }],
    });
    const law = nodeId.law("LAW-9");
    expect(g.edges.filter((e) => e.source === law).map((e) => e.target)).toEqual([nodeId.endpoint(ep("GET", "/health"))]);
    expect(g.edges.filter((e) => e.source === nodeId.identity("m1") && e.target === nodeId.resource("Listing"))).toHaveLength(1);
    expect(g.nodes.some((n) => n.id.includes("ghost"))).toBe(false);
    expect(new Set(g.edges.map((e) => e.id)).size).toBe(g.edges.length);
  });

  it("tolerates missing optional metadata", () => {
    const bare = { ...model.endpoints[0]!, resourceEvidence: undefined, parameters: undefined, responses: undefined, requestBody: null, tags: undefined, auth: undefined } as unknown as ApiModel["endpoints"][number];
    const g = buildTwinGraph({
      endpoints: [bare],
      identities: [{ id: "x", name: "", role: "" }],
      roles: [{ name: "R" } as never],
      laws: [{ id: "LAW-1" }],
    });
    expect(g.nodes.map((n) => n.id)).toEqual([nodeId.identity("x"), nodeId.role("R"), nodeId.endpoint(bare.id), nodeId.law("LAW-1")]);
    expect(g.nodes.find((n) => n.type === "identity")!.label).toBe("x");
    expect(g.nodes.find((n) => n.type === "law")!.meta).toEqual({});
    expect(g.nodes.find((n) => n.type === "endpoint")!.meta.auth).toBe("unknown");
  });

  it("creates a role node for roles that only appear on identities", () => {
    const g = buildTwinGraph({ identities: [{ id: "a", name: "A", role: "Ghost" }] });
    expect(g.nodes.find((n) => n.id === nodeId.role("Ghost"))!.meta.source).toMatch(/identity configuration only/);
    expect(types(g, nodeId.identity("a"), nodeId.role("Ghost"))).toEqual(["HAS_ROLE"]);
  });

  it("notes ambiguity when the ownership map could apply to several resources", () => {
    const twoOwned = model.resources.map((r) => (r.name === "Store" ? { ...r, ownershipField: "merchantId" } : r));
    const g = buildTwinGraph({ ...baseInput, resources: twoOwned });
    const owns = g.edges.filter((e) => e.source === nodeId.identity("m1") && e.types.includes("OWNS"));
    expect(owns.map((e) => e.target).sort()).toEqual([nodeId.resource("Listing"), nodeId.resource("Store")]);
    expect(owns[0]!.provenance[0]).toMatch(/not typed by resource/);
  });

  it("applies field modes and analyst sensitivity overrides", () => {
    expect(buildTwinGraph({ ...baseInput, fieldMode: "none" }).nodes.some((n) => n.type === "field")).toBe(false);
    const all = buildTwinGraph({ ...baseInput, fieldMode: "all" });
    expect(all.stats.fieldsShown).toBe(all.stats.fieldsTotal);
    const overridden = buildTwinGraph({ ...baseInput, sensitivityOverrides: { "Listing.title": "SENSITIVE", "Listing.payoutAccountNumber": "PUBLIC" } });
    const fields = overridden.nodes.filter((n) => n.type === "field" && n.meta.resource === "Listing").map((n) => n.label).sort();
    expect(fields).toEqual(["ownerId", "title"]);
    expect(overridden.nodes.find((n) => n.id === nodeId.field("Listing", "title"))!.meta.reason).toBe("manual override by analyst");
  });

  it("records law scope fields hidden by the current field filter", () => {
    const g = buildTwinGraph({ ...baseInput, fieldMode: "none" });
    expect(g.nodes.find((n) => n.id === nodeId.law("LAW-001"))!.meta.fieldsHiddenByFilter).toBe(1);
  });
});

describe("findings, laws and queries", () => {
  const finding: Finding = { id: "F-1", state: "OBSERVED", lawId: "LAW-001", category: "BOLA", endpointId: ep("GET", "/listings/{listingId}"), summary: "", evidence: [] };
  const g = buildTwinGraph({ ...baseInput, findings: [finding] });
  const listingEp = nodeId.endpoint(ep("GET", "/listings/{listingId}"));

  it("maps findings to VIOLATES edges with their state", () => {
    const edge = g.edges.find((e) => e.source === listingEp && e.target === nodeId.law("LAW-001"))!;
    expect(edge.types).toEqual(["VIOLATES"]);
    expect(edge.provenance).toEqual(["finding F-1 (OBSERVED)"]);
  });

  it("highlights a law with everything it governs and any violations", () => {
    const h = lawHighlight(g, "LAW-001");
    expect(h.nodes.has(listingEp)).toBe(true);
    expect(h.nodes.has(nodeId.resource("Listing"))).toBe(true);
    expect(h.nodes.has(nodeId.resource("Store"))).toBe(false);
    expect(h.edges.size).toBe(5);
    expect(lawHighlight(g, "LAW-404").nodes.size).toBe(0);
  });

  it("describes a node with its relationships and relevant laws", () => {
    const d = describeNode(g, listingEp)!;
    expect(d.laws.map((l) => l.label)).toEqual(["LAW-001"]); // GOVERNS and VIOLATES point at the same law
    expect(d.outgoing.map((o) => o.other.label).sort()).toEqual(["LAW-001", "Listing"]);
    expect(d.incoming.map((o) => o.other.label)).toEqual(["LAW-001"]);
    expect(describeNode(g, "nope")).toBeNull();
  });

  it("describes an edge with both ends", () => {
    const id = `${listingEp}->${nodeId.resource("Listing")}`;
    expect(describeEdge(g, id)).toMatchObject({ source: { id: listingEp }, target: { id: nodeId.resource("Listing") } });
    expect(describeEdge(g, "nope")).toBeNull();
  });
});
