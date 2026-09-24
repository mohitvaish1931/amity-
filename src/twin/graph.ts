// Pure transformation: typed security model -> graph nodes/edges for the Security Twin view.
// Every node and edge comes from input data; each edge records its provenance.
// No domain names, no demo data, no rendering concerns.
import type { Endpoint, Finding, Identity, Resource, ResourceField, Role, SecurityLaw, Sensitivity } from "../contracts";

export type TwinEntityType = "identity" | "role" | "endpoint" | "resource" | "field" | "law";
export type TwinRelationType =
  | "HAS_ROLE"
  | "OWNS"
  | "REQUIRES_ROLE"
  | "READS"
  | "WRITES"
  | "RETURNS"
  | "RELATES_TO"
  | "HAS_FIELD"
  | "EXPOSES"
  | "GOVERNS"
  | "VIOLATES";
/** "key" = sensitive (PERSONAL/SENSITIVE) and ownership fields only. */
export type FieldMode = "key" | "all" | "none";
export type MetaValue = string | number | boolean | string[];

export interface TwinNode {
  id: string;
  type: TwinEntityType;
  label: string;
  subtitle: string;
  meta: Record<string, MetaValue>;
  /** Number of edges touching this node. */
  degree: number;
}

export interface TwinEdge {
  id: string;
  source: string;
  target: string;
  /** Several relationship types between the same pair are merged into one edge. */
  types: TwinRelationType[];
  provenance: string[];
}

export interface TwinGraph {
  nodes: TwinNode[];
  edges: TwinEdge[];
  stats: { fieldsTotal: number; fieldsShown: number };
}

/** A law as produced by Step 1. Everything except the id is optional so partial/older exports still render. */
export type TwinLaw = Partial<Omit<SecurityLaw, "appliesTo">> & { id: string; appliesTo?: Partial<SecurityLaw["appliesTo"]> };

export interface TwinGraphInput {
  endpoints?: readonly Endpoint[];
  resources?: readonly Resource[];
  identities?: readonly Identity[];
  roles?: readonly Role[];
  laws?: readonly TwinLaw[];
  findings?: readonly Finding[];
  /** Configured object -> owner map (not typed by resource). */
  ownership?: readonly { objectId: string; ownerId: string }[];
  /** Endpoint ids the model assigns to privileged roles only. */
  privilegedEndpoints?: readonly string[];
  /** "Resource.fieldPath" -> analyst override. */
  sensitivityOverrides?: Readonly<Record<string, Sensitivity>>;
  fieldMode?: FieldMode;
}

const TYPE_ORDER: readonly TwinEntityType[] = ["identity", "role", "endpoint", "resource", "field", "law"];

export const nodeId = {
  identity: (id: string) => `identity:${id}`,
  role: (name: string) => `role:${name}`,
  endpoint: (id: string) => `endpoint:${id}`,
  resource: (name: string) => `resource:${name}`,
  field: (resource: string, path: string) => `field:${resource}.${path}`,
  law: (id: string) => `law:${id}`,
};

class GraphBuilder {
  readonly nodes = new Map<string, TwinNode>();
  private readonly edges = new Map<string, TwinEdge>();

  addNode(node: Omit<TwinNode, "degree">): void {
    if (!this.nodes.has(node.id)) this.nodes.set(node.id, { ...node, degree: 0 });
  }

  /** Adds or merges an edge. Edges to unknown nodes and self-loops are dropped. */
  addEdge(source: string, target: string, type: TwinRelationType, provenance: string): void {
    if (source === target || !this.nodes.has(source) || !this.nodes.has(target)) return;
    const id = `${source}->${target}`;
    const existing = this.edges.get(id);
    if (!existing) {
      this.edges.set(id, { id, source, target, types: [type], provenance: [provenance] });
      return;
    }
    if (!existing.types.includes(type)) existing.types.push(type);
    if (!existing.provenance.includes(provenance)) existing.provenance.push(provenance);
  }

  build(stats: TwinGraph["stats"]): TwinGraph {
    const edges = [...this.edges.values()].sort((a, b) => a.id.localeCompare(b.id));
    for (const e of edges) {
      this.nodes.get(e.source)!.degree++;
      this.nodes.get(e.target)!.degree++;
    }
    const nodes = [...this.nodes.values()].sort(
      (a, b) => TYPE_ORDER.indexOf(a.type) - TYPE_ORDER.indexOf(b.type) || a.id.localeCompare(b.id),
    );
    return { nodes, edges, stats };
  }
}

const SENSITIVE_LEVELS: readonly Sensitivity[] = ["PERSONAL", "SENSITIVE"];

function effectiveSensitivity(resource: string, f: ResourceField, overrides: TwinGraphInput["sensitivityOverrides"]): Sensitivity {
  return overrides?.[`${resource}.${f.path}`] ?? f.sensitivity;
}

function readsOrWrites(e: Endpoint): TwinRelationType {
  if (e.action === "Read" || e.action === "List") return "READS";
  if (e.action === "Create" || e.action === "Update" || e.action === "Delete") return "WRITES";
  return e.method === "GET" || e.method === "HEAD" ? "READS" : "WRITES";
}

export function buildTwinGraph(input: TwinGraphInput): TwinGraph {
  const g = new GraphBuilder();
  const endpoints = input.endpoints ?? [];
  const resources = input.resources ?? [];
  const identities = input.identities ?? [];
  const roles = input.roles ?? [];
  const laws = input.laws ?? [];
  const fieldMode = input.fieldMode ?? "key";

  // ---- roles & identities (configuration) ----
  for (const r of roles) {
    const perms = Object.entries(r.permissions ?? {});
    g.addNode({
      id: nodeId.role(r.name),
      type: "role",
      label: r.name,
      subtitle: r.privileged ? "privileged role" : "role",
      meta: {
        source: "configuration",
        privileged: !!r.privileged,
        allowed: perms.filter(([, v]) => v === true).map(([k]) => k),
        denied: perms.filter(([, v]) => v === false).map(([k]) => k),
      },
    });
  }
  for (const i of identities) {
    if (i.role && !g.nodes.has(nodeId.role(i.role))) {
      g.addNode({ id: nodeId.role(i.role), type: "role", label: i.role, subtitle: "role", meta: { source: "identity configuration only (no permissions declared)" } });
    }
    g.addNode({ id: nodeId.identity(i.id), type: "identity", label: i.name || i.id, subtitle: i.role || "no role", meta: { id: i.id, role: i.role || "", source: "configuration" } });
    if (i.role) g.addEdge(nodeId.identity(i.id), nodeId.role(i.role), "HAS_ROLE", "configuration: identity.role");
  }

  // ---- endpoints (spec) ----
  for (const e of endpoints) {
    const meta: Record<string, MetaValue> = {
      method: e.method,
      path: e.path,
      action: e.action,
      auth: e.auth?.mode ?? "unknown",
      authDetail: e.auth?.detail ?? "",
      resource: e.resource,
      resourceConfidence: e.resourceConfidence ?? 0,
      resourceEvidence: (e.resourceEvidence ?? []).map((x) => `${x.source}: ${x.value} (weight ${x.weight})`),
      parameters: (e.parameters ?? []).map((p) => `${p.name} (${p.in}${p.required ? ", required" : ""})`),
      responses: (e.responses ?? []).map((r) => r.status),
      requestContentTypes: e.requestBody?.contents.map((c) => c.contentType) ?? [],
      tags: e.tags ?? [],
    };
    if (e.operationId) meta.operationId = e.operationId;
    if (e.summary) meta.summary = e.summary;
    g.addNode({ id: nodeId.endpoint(e.id), type: "endpoint", label: `${e.method} ${e.path}`, subtitle: `${e.id} · ${e.action}`, meta });
  }

  // ---- resources & fields (spec-derived model) ----
  const overrides = input.sensitivityOverrides;
  let fieldsTotal = 0;
  let fieldsShown = 0;
  const shownFields = new Set<string>();
  for (const r of resources) {
    const levels = (lvl: Sensitivity) => r.fields.filter((f) => effectiveSensitivity(r.name, f, overrides) === lvl).length;
    const referencedSchemas = r.relations.filter((x) => x.kind === "references" && !resources.some((o) => o.name === x.to)).map((x) => `${x.to} via ${x.via}`);
    g.addNode({
      id: nodeId.resource(r.name),
      type: "resource",
      label: r.name,
      subtitle: `${r.endpoints.length} endpoint${r.endpoints.length === 1 ? "" : "s"} · ${r.fields.length} field${r.fields.length === 1 ? "" : "s"}`,
      meta: {
        schemas: r.schemaNames,
        ownershipField: r.ownershipField ?? "none",
        identifierFields: r.identifierFields,
        personalFields: levels("PERSONAL"),
        sensitiveFields: levels("SENSITIVE"),
        referencedSchemas,
        source: "spec (resource inference)",
      },
    });
    for (const f of r.fields) {
      fieldsTotal++;
      const sens = effectiveSensitivity(r.name, f, overrides);
      const isKey = SENSITIVE_LEVELS.includes(sens) || f.path === r.ownershipField;
      if (fieldMode === "none" || (fieldMode === "key" && !isKey)) continue;
      fieldsShown++;
      const id = nodeId.field(r.name, f.path);
      shownFields.add(`${r.name}.${f.path}`);
      const meta: Record<string, MetaValue> = {
        resource: r.name,
        type: f.type,
        sensitivity: sens,
        reason: overrides?.[`${r.name}.${f.path}`] ? "manual override by analyst" : f.sensitivityReason,
        required: f.required,
        nullable: f.nullable,
      };
      if (f.path === r.ownershipField) meta.ownershipField = true;
      if (f.ref) meta.ref = f.ref;
      if (f.variant) meta.variant = f.variant;
      if (f.recursive) meta.recursive = true;
      if (f.enum) meta.enum = f.enum.map(String);
      g.addNode({ id, type: "field", label: f.path, subtitle: `${sens} · ${r.name}`, meta });
      g.addEdge(
        nodeId.resource(r.name),
        id,
        SENSITIVE_LEVELS.includes(sens) ? "EXPOSES" : "HAS_FIELD",
        SENSITIVE_LEVELS.includes(sens) ? `field sensitivity ${sens}` : "ownership field",
      );
    }
  }

  // ---- endpoint <-> resource ----
  const resourceOfSchema = (schema: string) => resources.find((r) => r.schemaNames.includes(schema) || r.name === schema)?.name;
  for (const e of endpoints) {
    g.addEdge(nodeId.endpoint(e.id), nodeId.resource(e.resource), readsOrWrites(e), `action inference (${e.action})`);
  }
  for (const r of resources) {
    for (const rel of r.relations) {
      if (rel.kind === "returned-by") {
        const owner = resourceOfSchema(rel.from);
        if (owner) g.addEdge(nodeId.endpoint(rel.to), nodeId.resource(owner), "RETURNS", `response schema ${rel.from}`);
      } else if (rel.kind === "references") {
        g.addEdge(nodeId.resource(rel.from), nodeId.resource(rel.to), "RELATES_TO", `field ${rel.via}`);
      }
    }
  }

  // ---- ownership (configuration map + ownership field) ----
  const owned = resources.filter((r) => r.ownershipField);
  const objectsByOwner = new Map<string, string[]>();
  for (const o of input.ownership ?? []) objectsByOwner.set(o.ownerId, [...(objectsByOwner.get(o.ownerId) ?? []), String(o.objectId)]);
  for (const [ownerId, objects] of objectsByOwner) {
    for (const r of owned) {
      const note = owned.length > 1 ? "; ownership map is not typed by resource" : "";
      g.addEdge(
        nodeId.identity(ownerId),
        nodeId.resource(r.name),
        "OWNS",
        `configuration ownership map (${objects.length} object${objects.length === 1 ? "" : "s"}: ${objects.join(", ")}) + ownership field ${r.name}.${r.ownershipField}${note}`,
      );
    }
  }

  // ---- privileged endpoints ----
  for (const epId of input.privilegedEndpoints ?? []) {
    for (const r of roles.filter((x) => x.privileged)) {
      g.addEdge(nodeId.endpoint(epId), nodeId.role(r.name), "REQUIRES_ROLE", "admin endpoint + privileged role (heuristic)");
    }
  }

  // ---- laws ----
  for (const law of laws) {
    const scope = law.appliesTo ?? {};
    const hiddenFields = (scope.fields ?? []).filter((f) => !shownFields.has(f)).length;
    const meta: Record<string, MetaValue> = {};
    for (const k of ["title", "category", "severity", "confidence", "score", "invariant", "source"] as const) {
      const v = law[k];
      if (v !== undefined && v !== null) meta[k] = v as MetaValue;
    }
    if (hiddenFields) meta.fieldsHiddenByFilter = hiddenFields;
    g.addNode({ id: nodeId.law(law.id), type: "law", label: law.id, subtitle: [law.category, law.severity].filter(Boolean).join(" · "), meta });
    const prov = `law scope${law.confidence ? ` (confidence ${law.confidence})` : ""}`;
    for (const ep of scope.endpoints ?? []) g.addEdge(nodeId.law(law.id), nodeId.endpoint(ep), "GOVERNS", prov);
    for (const res of scope.resources ?? []) g.addEdge(nodeId.law(law.id), nodeId.resource(res), "GOVERNS", prov);
    for (const role of scope.roles ?? []) g.addEdge(nodeId.law(law.id), nodeId.role(role), "GOVERNS", prov);
    for (const f of scope.fields ?? []) {
      const dot = f.indexOf(".");
      if (dot > 0) g.addEdge(nodeId.law(law.id), nodeId.field(f.slice(0, dot), f.slice(dot + 1)), "GOVERNS", prov);
    }
  }

  // ---- findings (only when the input actually contains them) ----
  for (const f of input.findings ?? []) {
    g.addEdge(nodeId.endpoint(f.endpointId), nodeId.law(f.lawId), "VIOLATES", `finding ${f.id} (${f.state})`);
  }

  return g.build({ fieldsTotal, fieldsShown });
}

// ---------- queries used by the detail panel and highlighting ----------

export interface NodeDetails {
  node: TwinNode;
  outgoing: { edge: TwinEdge; other: TwinNode }[];
  incoming: { edge: TwinEdge; other: TwinNode }[];
  /** Laws that govern or are violated at this node (for a law node: empty). */
  laws: TwinNode[];
}

export function describeNode(graph: TwinGraph, id: string): NodeDetails | null {
  const byId = new Map(graph.nodes.map((n) => [n.id, n]));
  const node = byId.get(id);
  if (!node) return null;
  const outgoing = graph.edges.filter((e) => e.source === id).map((edge) => ({ edge, other: byId.get(edge.target)! }));
  const incoming = graph.edges.filter((e) => e.target === id).map((edge) => ({ edge, other: byId.get(edge.source)! }));
  const laws = [
    ...new Map(
      [...incoming, ...outgoing]
        .filter(({ other, edge }) => other.type === "law" && (edge.types.includes("GOVERNS") || edge.types.includes("VIOLATES")))
        .map(({ other }) => [other.id, other] as const),
    ).values(),
  ];
  return { node, outgoing, incoming, laws };
}

export function describeEdge(graph: TwinGraph, id: string): { edge: TwinEdge; source: TwinNode; target: TwinNode } | null {
  const edge = graph.edges.find((e) => e.id === id);
  if (!edge) return null;
  const source = graph.nodes.find((n) => n.id === edge.source)!;
  const target = graph.nodes.find((n) => n.id === edge.target)!;
  return { edge, source, target };
}

/** Node and edge ids to emphasise for one law: the law, everything it governs, and any violations. */
export function lawHighlight(graph: TwinGraph, lawId: string): { nodes: Set<string>; edges: Set<string> } {
  const id = nodeId.law(lawId);
  const nodes = new Set<string>();
  const edges = new Set<string>();
  if (!graph.nodes.some((n) => n.id === id)) return { nodes, edges };
  nodes.add(id);
  for (const e of graph.edges) {
    if (e.source !== id && e.target !== id) continue;
    edges.add(e.id);
    nodes.add(e.source === id ? e.target : e.source);
  }
  return { nodes, edges };
}
