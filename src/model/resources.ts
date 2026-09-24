import type {
  Action,
  ApiModel,
  Endpoint,
  Field,
  Relationship,
  Resource,
  ResourceEvidence,
  ResourceField,
  SchemaInfo,
} from "../contracts";
import type { NormalizedSpec, RawEndpoint } from "../openapi";
import { pascal, resourceName, singularize, tokenize } from "./naming";
import { classifyField } from "./sensitivity";

// Structural vocabulary only (HTTP/REST conventions), never domain nouns.
const VERSION_SEGMENT = /^(v\d+(\.\d+)*|api|rest|public|private)$/i;
const PSEUDO_SEGMENTS = new Set(["me", "self", "current", "mine", "search", "count", "export", "import", "bulk", "batch", "all"]);
const ACTION_VERBS = new Set([
  "cancel", "approve", "reject", "submit", "activate", "deactivate", "enable", "disable", "reset", "verify",
  "confirm", "publish", "unpublish", "archive", "restore", "complete", "close", "reopen", "lock", "unlock",
  "assign", "unassign", "retry", "resend", "refresh", "revoke", "start", "stop", "pause", "resume",
]);
const OPERATION_VERBS = new Set([
  "get", "list", "find", "fetch", "read", "create", "add", "update", "patch", "put", "delete", "remove",
  "search", "retrieve", "show", "set", "upsert", "replace", "post", "query", "load", "save", "new",
]);
const SCHEMA_AFFIX_TOKENS = new Set([
  "request", "response", "result", "results", "list", "page", "paged", "collection", "dto", "input",
  "output", "payload", "body", "model", "view", "detail", "details", "create", "update", "new", "patch",
]);
const GENERIC_SCHEMAS = new Set(["error", "errors", "problem", "message", "status", "empty", "object", "any"]);
const GENERIC_TAGS = new Set(["default", "api", "public", "private", "internal", "v1", "v2", "misc", "general"]);
const OWNER_WORDS = ["owner", "user", "customer", "account", "member", "author", "creator", "tenant"] as const;

const WEIGHT = { schema: 4, path: 3, operationId: 2, tag: 1 } as const;

export function isAdminPath(path: string): boolean {
  return staticSegments(path).some((s) => /^admin/i.test(s));
}

/**
 * `responseIsArray` (from the success response schema) decides Read vs List when known.
 * Otherwise: a path ending in a parameter, or a singular segment right after one
 * (/orders/{id}/invoice), addresses a single object.
 */
export function inferAction(method: string, path: string, responseIsArray?: boolean): Action {
  if (isAdminPath(path)) return "AdminAction";
  switch (method) {
    case "GET":
    case "HEAD": {
      if (responseIsArray !== undefined) return responseIsArray ? "List" : "Read";
      const segs = path.split("/").filter(Boolean);
      const last = segs[segs.length - 1] ?? "";
      if (last.includes("{")) return "Read";
      const afterParam = segs.length > 1 && segs[segs.length - 2]!.includes("{");
      return afterParam && singularize(last) === last.toLowerCase() ? "Read" : "List";
    }
    case "POST":
      return "Create";
    case "PUT":
    case "PATCH":
      return "Update";
    case "DELETE":
      return "Delete";
    default:
      return "Other";
  }
}

/** Resource name from a schema name: "CreateOrderRequest" -> "Order", "OrderList" -> "Order". */
export function schemaBaseName(schemaName: string): string | null {
  const tokens = tokenize(schemaName);
  while (tokens.length > 1 && SCHEMA_AFFIX_TOKENS.has(tokens[0]!)) tokens.shift();
  while (tokens.length > 1 && SCHEMA_AFFIX_TOKENS.has(tokens[tokens.length - 1]!)) tokens.pop();
  if (!tokens.length || (tokens.length === 1 && (GENERIC_SCHEMAS.has(tokens[0]!) || SCHEMA_AFFIX_TOKENS.has(tokens[0]!)))) return null;
  tokens[tokens.length - 1] = singularize(tokens[tokens.length - 1]!);
  return pascal(tokens);
}

function staticSegments(path: string): string[] {
  return path.split("/").filter((s) => s && !s.includes("{"));
}

/** Noun from the path: last static segment, skipping versions, pseudo segments and trailing action verbs. */
function pathCandidate(path: string): string | null {
  const segs = path.split("/").filter(Boolean);
  for (let i = segs.length - 1; i >= 0; i--) {
    const seg = segs[i]!;
    if (seg.includes("{") || VERSION_SEGMENT.test(seg) || PSEUDO_SEGMENTS.has(seg.toLowerCase())) continue;
    const prevIsParam = i > 0 && segs[i - 1]!.includes("{");
    if (prevIsParam && ACTION_VERBS.has(seg.toLowerCase())) continue; // /orders/{id}/cancel acts on orders
    if (/^admin/i.test(seg) && i < segs.length - 1) continue;
    const name = resourceName(seg);
    if (name) return name;
  }
  return null;
}

function operationIdCandidate(operationId: string): string | null {
  const tokens = tokenize(operationId);
  const byIdx = tokens.indexOf("by");
  const core = (byIdx > 0 ? tokens.slice(0, byIdx) : tokens).filter((t) => !OPERATION_VERBS.has(t) && t !== "all");
  while (core.length && ["id", "ids", "details", "detail", "info", "list"].includes(core[core.length - 1]!)) core.pop();
  const last = core[core.length - 1];
  return last ? resourceName(last) : null;
}

function primarySchema(ep: RawEndpoint): SchemaInfo | null {
  const success = ep.responses.filter((r) => /^2/.test(r.status) || r.status === "default");
  const respSchema = success.flatMap((r) => r.contents).find((c) => c.schema)?.schema ?? null;
  const bodySchema = ep.requestBody?.contents.find((c) => c.schema)?.schema ?? null;
  return ["POST", "PUT", "PATCH"].includes(ep.method) ? bodySchema ?? respSchema : respSchema ?? bodySchema;
}

function schemaNameOf(info: SchemaInfo | null): string | undefined {
  return info ? info.itemRefName ?? info.refName : undefined;
}

export function inferResource(ep: RawEndpoint): { resource: string; evidence: ResourceEvidence[]; confidence: number } {
  const evidence: ResourceEvidence[] = [];
  const primaryName = schemaNameOf(primarySchema(ep));
  const fromSchema = primaryName ? schemaBaseName(primaryName) : null;
  if (fromSchema) evidence.push({ source: "schema", value: fromSchema, weight: WEIGHT.schema });
  const fromPath = pathCandidate(ep.path);
  if (fromPath) evidence.push({ source: "path", value: fromPath, weight: WEIGHT.path });
  const fromOp = ep.operationId ? operationIdCandidate(ep.operationId) : null;
  if (fromOp) evidence.push({ source: "operationId", value: fromOp, weight: WEIGHT.operationId });
  const tag = ep.tags.find((t) => !GENERIC_TAGS.has(t.toLowerCase()));
  const fromTag = tag ? resourceName(tag) : null;
  if (fromTag) evidence.push({ source: "tag", value: fromTag, weight: WEIGHT.tag });

  if (!evidence.length) return { resource: "Root", evidence, confidence: 0 };
  const score = new Map<string, number>();
  for (const e of evidence) score.set(e.value, (score.get(e.value) ?? 0) + e.weight);
  const total = evidence.reduce((a, e) => a + e.weight, 0);
  // Highest score wins; ties go to the path candidate (most specific to this operation), then schema.
  const order = [fromPath, fromSchema, fromOp, fromTag].filter((x): x is string => !!x);
  let best = order[0]!;
  for (const name of order) if ((score.get(name) ?? 0) > (score.get(best) ?? 0)) best = name;
  return { resource: best, evidence, confidence: Math.round(((score.get(best) ?? 0) / total) * 100) / 100 };
}

// ---------- resources ----------

function ownershipFieldOf(resource: string, fields: readonly Field[]): string | null {
  const selfTokens = tokenize(resource).map(singularize);
  let best: { field: string; rank: number } | null = null;
  for (const f of fields) {
    if (f.path.includes(".") || f.path.includes("[]")) continue; // top-level only
    const t = tokenize(f.name);
    if (t.includes("internal")) continue; // internal references are not ownership boundaries
    const last = t[t.length - 1];
    const isIdLike = last === "id" || last === "uuid" || last === "key" || f.ref !== undefined;
    const createdBy = t.length === 2 && t[0] === "created" && t[1] === "by";
    const owned = t.length === 2 && t[0] === "owned" && t[1] === "by";
    let word: string | undefined;
    if (createdBy) word = "creator";
    else if (owned || (t.length === 1 && t[0] === "owner")) word = "owner";
    else if (isIdLike && t.length >= 2) word = OWNER_WORDS.find((w) => t[t.length - 2] === w);
    if (!word) continue;
    if (selfTokens.includes(word)) continue; // User.userId is the resource's own id, not an owner
    const rank = OWNER_WORDS.indexOf(word as (typeof OWNER_WORDS)[number]);
    if (!best || rank < best.rank) best = { field: f.name, rank };
  }
  return best?.field ?? null;
}

export function buildApiModel(spec: NormalizedSpec): ApiModel {
  const warnings = [...spec.warnings];
  const endpoints: Endpoint[] = spec.endpoints.map((ep) => {
    const r = inferResource(ep);
    const success = ep.responses.filter((x) => /^2/.test(x.status)).flatMap((x) => x.contents).find((c) => c.schema)?.schema;
    return {
      ...ep,
      action: inferAction(ep.method, ep.path, success && success.type !== "unknown" ? success.isArray : undefined),
      resource: r.resource,
      resourceEvidence: r.evidence,
      resourceConfidence: r.confidence,
    };
  });

  const byName = new Map<string, Endpoint[]>();
  for (const ep of endpoints) byName.set(ep.resource, [...(byName.get(ep.resource) ?? []), ep]);

  const resources: Resource[] = [];
  const resourceNames = new Set(byName.keys());
  for (const [name, eps] of byName) {
    const schemaNames = Object.keys(spec.schemas).filter((s) => schemaBaseName(s) === name);
    const rawFields: Field[] = [];
    const seen = new Set<string>();
    const addFields = (fields: readonly Field[]) => {
      for (const f of fields) {
        if (seen.has(f.path)) continue;
        seen.add(f.path);
        rawFields.push(f);
      }
    };
    for (const s of schemaNames) addFields(spec.schemas[s]!.fields);
    if (!rawFields.length) for (const ep of eps) addFields(primarySchema(ep)?.fields ?? []);
    if (!rawFields.length) {
      const idParam = eps.flatMap((ep) => ep.parameters.filter((p) => p.in === "path")).at(-1);
      if (idParam) addFields([{ path: idParam.name, name: idParam.name, type: idParam.schema.type, nullable: false, required: true }]);
      warnings.push(`Resource ${name}: no schema fields found${idParam ? `; identifier "${idParam.name}" taken from path parameter` : ""}.`);
    }

    const fields: ResourceField[] = rawFields.map((f) => {
      const c = classifyField(f.name, name);
      return { ...f, sensitivity: c.level, sensitivityReason: c.reason };
    });

    const relations: Relationship[] = [];
    for (const f of rawFields) {
      if (f.ref) {
        const target = schemaBaseName(f.ref) ?? f.ref;
        if (target !== name) relations.push({ from: name, to: target, kind: "references", via: f.path });
        continue;
      }
      const t = tokenize(f.name);
      if (t.length >= 2 && t[t.length - 1] === "id" && !f.path.includes(".")) {
        const target = resourceName(t.slice(0, -1).join(" "));
        if (target !== name && resourceNames.has(target)) relations.push({ from: name, to: target, kind: "references", via: f.path });
      }
    }
    for (const ep of eps) {
      const resp = ep.responses.filter((r) => /^2/.test(r.status)).flatMap((r) => r.contents).find((c) => c.schema)?.schema;
      const respName = schemaNameOf(resp ?? null);
      if (respName) relations.push({ from: respName, to: ep.id, kind: "returned-by", via: ep.id });
      const bodyName = schemaNameOf(ep.requestBody?.contents.find((c) => c.schema)?.schema ?? null);
      if (bodyName) relations.push({ from: bodyName, to: ep.id, kind: "accepted-by", via: ep.id });
    }

    const topLevel = fields.filter((f) => !f.path.includes(".") && !f.path.includes("[]"));
    resources.push({
      name,
      endpoints: eps.map((e) => e.id),
      schemaNames,
      fields,
      ownershipField: ownershipFieldOf(name, topLevel),
      identifierFields: topLevel.filter((f) => ["id", "uuid"].includes(tokenize(f.name).at(-1) ?? "")).map((f) => f.path),
      relations,
    });
  }

  const model: ApiModel = {
    format: spec.format,
    specVersion: spec.specVersion,
    servers: spec.servers,
    securitySchemes: spec.securitySchemes,
    endpoints,
    schemas: spec.schemas,
    resources,
    warnings,
  };
  if (spec.title) model.title = spec.title;
  if (spec.apiVersion) model.apiVersion = spec.apiVersion;
  return model;
}
