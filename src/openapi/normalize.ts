import type {
  Endpoint,
  HttpMethod,
  MediaContent,
  Parameter,
  ParameterLocation,
  RequestBody,
  ResponseSpec,
  SchemaInfo,
  SecuritySchemeRef,
  SpecFormat,
} from "../contracts";
import { isRecord, type SpecDocument } from "./load";
import { RefResolver } from "./refs";
import { SchemaFlattener } from "./schema";
import { collectSecuritySchemes, resolveAuth } from "./security";

/** Endpoint before semantic enrichment (resource/action are added by src/model). */
export type RawEndpoint = Omit<Endpoint, "action" | "resource" | "resourceEvidence" | "resourceConfidence">;

export interface NormalizedSpec {
  format: SpecFormat;
  specVersion: string;
  title?: string;
  apiVersion?: string;
  servers: string[];
  securitySchemes: Record<string, SecuritySchemeRef>;
  endpoints: RawEndpoint[];
  schemas: Record<string, SchemaInfo>;
  warnings: string[];
}

const METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"] as const;
const LOCATIONS: readonly ParameterLocation[] = ["path", "query", "header", "cookie"];
const DEFAULT_MEDIA = "application/json";

export function normalizeSpec(doc: SpecDocument, format: SpecFormat, specVersion: string, initialWarnings: string[] = []): NormalizedSpec {
  const warnings = [...initialWarnings];
  const resolver = new RefResolver(doc, warnings);
  const flattener = new SchemaFlattener(resolver, warnings);
  const swagger2 = format === "swagger-2.0";
  const securitySchemes = collectSecuritySchemes(doc, format, resolver);
  const rootConsumes = stringList(doc.consumes);
  const rootProduces = stringList(doc.produces);
  const info = isRecord(doc.info) ? doc.info : {};

  const endpoints: RawEndpoint[] = [];
  const operationIds = new Map<string, string>();
  const paths = isRecord(doc.paths) ? doc.paths : {};
  let counter = 1;

  for (const [path, rawItem] of Object.entries(paths)) {
    if (path.startsWith("x-")) continue;
    const item = resolver.deref(rawItem);
    if (!item) {
      warnings.push(`Path "${path}": path item could not be resolved; skipped.`);
      continue;
    }
    for (const m of METHODS) {
      const op = item[m];
      if (!isRecord(op)) continue;
      const method = m.toUpperCase() as HttpMethod;
      const where = `${method} ${path}`;

      const params = mergeParameters(item.parameters, op.parameters, resolver, where, warnings);
      const parameters: Parameter[] = [];
      const bodyParams: Record<string, unknown>[] = [];
      const formParams: Record<string, unknown>[] = [];
      for (const p of params) {
        if (swagger2 && p.in === "body") bodyParams.push(p);
        else if (swagger2 && p.in === "formData") formParams.push(p);
        else parameters.push(toParameter(p, swagger2, flattener));
      }
      addMissingPathParams(path, parameters, flattener, where, warnings);

      const consumes = stringList(op.consumes) ?? rootConsumes ?? [DEFAULT_MEDIA];
      const produces = stringList(op.produces) ?? rootProduces ?? [DEFAULT_MEDIA];
      const requestBody = swagger2
        ? swaggerRequestBody(bodyParams, formParams, consumes, flattener)
        : oasRequestBody(op.requestBody, resolver, flattener);
      const responses = readResponses(op.responses, swagger2, produces, resolver, flattener);

      const operationId = typeof op.operationId === "string" ? op.operationId : undefined;
      if (operationId) {
        const prev = operationIds.get(operationId);
        if (prev) warnings.push(`Duplicate operationId "${operationId}" (${prev} and ${where}).`);
        else operationIds.set(operationId, where);
      }

      const endpoint: RawEndpoint = {
        id: `EP-${String(counter++).padStart(3, "0")}`,
        method,
        path,
        tags: stringList(op.tags) ?? [],
        deprecated: op.deprecated === true,
        parameters,
        requestBody,
        responses,
        auth: resolveAuth(op.security, doc.security, securitySchemes, warnings, where),
      };
      if (operationId) endpoint.operationId = operationId;
      const summary = typeof op.summary === "string" ? op.summary : typeof op.description === "string" ? op.description.split("\n")[0] : undefined;
      if (summary) endpoint.summary = summary;
      endpoints.push(endpoint);
    }
  }
  if (!endpoints.length) warnings.push("No operations found under paths.");

  const schemaContainer = swagger2 ? doc.definitions : isRecord(doc.components) ? doc.components.schemas : undefined;
  const schemas: Record<string, SchemaInfo> = {};
  if (isRecord(schemaContainer)) {
    for (const name of Object.keys(schemaContainer)) {
      schemas[name] = flattener.describe({ $ref: `${swagger2 ? "#/definitions/" : "#/components/schemas/"}${escapePointer(name)}` });
    }
  }

  const result: NormalizedSpec = {
    format,
    specVersion,
    servers: readServers(doc, swagger2),
    securitySchemes,
    endpoints,
    schemas,
    warnings,
  };
  if (typeof info.title === "string") result.title = info.title;
  if (typeof info.version === "string") result.apiVersion = info.version;
  return result;
}

// ---------- parameters ----------

function mergeParameters(
  pathLevel: unknown,
  opLevel: unknown,
  resolver: RefResolver,
  where: string,
  warnings: string[],
): Record<string, unknown>[] {
  // Operation-level parameters override path-level ones with the same (name, in).
  const merged = new Map<string, Record<string, unknown>>();
  for (const list of [pathLevel, opLevel]) {
    if (!Array.isArray(list)) continue;
    for (const raw of list) {
      const p = resolver.deref(raw);
      if (!p || typeof p.name !== "string" || typeof p.in !== "string") {
        warnings.push(`${where}: parameter without a valid "name"/"in" skipped.`);
        continue;
      }
      merged.set(`${p.in}:${p.name}`, p);
    }
  }
  return [...merged.values()];
}

function toParameter(p: Record<string, unknown>, swagger2: boolean, flattener: SchemaFlattener): Parameter {
  const loc = LOCATIONS.includes(p.in as ParameterLocation) ? (p.in as ParameterLocation) : "query";
  let schemaNode: unknown = p.schema;
  if (swagger2) {
    // Swagger 2 non-body parameters carry type/format/items/enum inline.
    const { name: _n, in: _i, required: _r, description: _d, ...rest } = p;
    schemaNode = rest;
  } else if (schemaNode === undefined && isRecord(p.content)) {
    schemaNode = Object.values(p.content).map((c) => (isRecord(c) ? c.schema : undefined)).find(Boolean);
  }
  const param: Parameter = {
    name: String(p.name),
    in: loc,
    required: loc === "path" ? true : p.required === true,
    schema: flattener.describe(schemaNode ?? { type: "string" }),
  };
  if (typeof p.description === "string") param.description = p.description;
  return param;
}

function addMissingPathParams(path: string, params: Parameter[], flattener: SchemaFlattener, where: string, warnings: string[]): void {
  for (const match of path.matchAll(/\{([^}]+)\}/g)) {
    const name = match[1]!;
    if (params.some((p) => p.in === "path" && p.name === name)) continue;
    warnings.push(`${where}: path parameter "{${name}}" is not declared; assumed required string.`);
    params.push({ name, in: "path", required: true, schema: flattener.describe({ type: "string" }) });
  }
}

// ---------- bodies & responses ----------

function oasRequestBody(raw: unknown, resolver: RefResolver, flattener: SchemaFlattener): RequestBody | null {
  const rb = resolver.deref(raw);
  if (!rb) return null;
  return { required: rb.required === true, contents: readContent(rb.content, flattener) };
}

function swaggerRequestBody(
  bodyParams: Record<string, unknown>[],
  formParams: Record<string, unknown>[],
  consumes: string[],
  flattener: SchemaFlattener,
): RequestBody | null {
  const body = bodyParams[0];
  if (body) {
    const schema = flattener.describe(body.schema);
    return { required: body.required === true, contents: consumes.map((contentType) => ({ contentType, schema })) };
  }
  if (!formParams.length) return null;
  const properties: Record<string, unknown> = {};
  const required: string[] = [];
  for (const p of formParams) {
    const { name, in: _i, required: req, description: _d, ...rest } = p;
    properties[String(name)] = rest;
    if (req === true) required.push(String(name));
  }
  const schema = flattener.describe({ type: "object", properties, required });
  const hasFile = formParams.some((p) => p.type === "file");
  const formTypes = consumes.filter((c) => /form/.test(c));
  const types = formTypes.length ? formTypes : [hasFile ? "multipart/form-data" : "application/x-www-form-urlencoded"];
  return { required: required.length > 0, contents: types.map((contentType) => ({ contentType, schema })) };
}

function readResponses(
  raw: unknown,
  swagger2: boolean,
  produces: string[],
  resolver: RefResolver,
  flattener: SchemaFlattener,
): ResponseSpec[] {
  if (!isRecord(raw)) return [];
  const out: ResponseSpec[] = [];
  for (const [status, rawResp] of Object.entries(raw)) {
    if (status.startsWith("x-")) continue;
    const r = resolver.deref(rawResp);
    if (!r) continue;
    let contents: MediaContent[];
    if (swagger2) {
      const schema = r.schema !== undefined ? flattener.describe(r.schema) : null;
      contents = schema ? produces.map((contentType) => ({ contentType, schema })) : [];
    } else {
      contents = readContent(r.content, flattener);
    }
    const resp: ResponseSpec = { status, contents };
    if (typeof r.description === "string") resp.description = r.description;
    out.push(resp);
  }
  return out;
}

function readContent(content: unknown, flattener: SchemaFlattener): MediaContent[] {
  if (!isRecord(content)) return [];
  return Object.entries(content).map(([contentType, media]) => ({
    contentType,
    schema: isRecord(media) && media.schema !== undefined ? flattener.describe(media.schema) : null,
  }));
}

// ---------- misc ----------

function readServers(doc: SpecDocument, swagger2: boolean): string[] {
  if (swagger2) {
    if (typeof doc.host !== "string") return typeof doc.basePath === "string" ? [doc.basePath] : [];
    const base = typeof doc.basePath === "string" && doc.basePath !== "/" ? doc.basePath : "";
    const schemes = stringList(doc.schemes) ?? ["https"];
    return schemes.map((s) => `${s}://${doc.host}${base}`);
  }
  if (!Array.isArray(doc.servers)) return [];
  return doc.servers
    .filter(isRecord)
    .map((s) => {
      if (typeof s.url !== "string") return "";
      const vars = isRecord(s.variables) ? s.variables : {};
      return s.url.replace(/\{([^}]+)\}/g, (whole, name: string) => {
        const v = vars[name];
        return isRecord(v) && typeof v.default === "string" ? v.default : whole;
      });
    })
    .filter(Boolean);
}

function stringList(v: unknown): string[] | undefined {
  if (!Array.isArray(v)) return undefined;
  return v.filter((x): x is string => typeof x === "string");
}

function escapePointer(name: string): string {
  return name.replace(/~/g, "~0").replace(/\//g, "~1");
}
