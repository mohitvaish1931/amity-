import type { ApiModel, Sensitivity } from "../contracts";

// Shapes consumed by the existing browser apps (1-security-twin twin/law builders and the
// testable-security-model.json contract read by 2-test-lab). Keep field names stable.

export interface LegacyEndpoint {
  id: string;
  method: string;
  path: string;
  auth: boolean;
  authMode: string;
  authDetail: string;
  authInferred: boolean;
  resource: string;
  action: string;
  summary: string;
  operationId: string | null;
  tags: string[];
  params: { name: string; in: string; required: boolean; type: string }[];
  bodyRef: string | null;
  bodySchemaName: string | null;
  bodyContentTypes: string[];
  respRef: string | null;
  respSchemaName: string | null;
  respContentTypes: string[];
}

export interface LegacyField {
  type: string;
  sensitivity: Sensitivity;
  reason: string;
  ref: string | null;
}

export interface LegacyResource {
  endpoints: string[];
  fields: Record<string, LegacyField>;
  relations: string[];
  ownershipField: string | null;
}

export interface LegacyView {
  endpoints: LegacyEndpoint[];
  resources: Record<string, LegacyResource>;
  specInfo: { version: string; servers: string[]; title: string | null };
  warnings: string[];
}

/** `overrides` maps "Resource.fieldPath" to an analyst-chosen sensitivity. */
export function toLegacyView(model: ApiModel, overrides: Record<string, Sensitivity> = {}): LegacyView {
  const endpoints: LegacyEndpoint[] = model.endpoints.map((e) => {
    const body = e.requestBody?.contents.find((c) => c.schema)?.schema ?? null;
    const resp =
      e.responses.filter((r) => /^2/.test(r.status)).flatMap((r) => r.contents).find((c) => c.schema)?.schema ?? null;
    const bodyName = body ? body.itemRefName ?? body.refName ?? null : null;
    const respName = resp ? resp.itemRefName ?? resp.refName ?? null : null;
    return {
      id: e.id,
      method: e.method,
      path: e.path,
      auth: e.auth.mode === "required",
      authMode: e.auth.mode,
      authDetail: e.auth.detail,
      authInferred: e.auth.source === "none",
      resource: e.resource,
      action: e.action,
      summary: e.summary ?? e.operationId ?? "",
      operationId: e.operationId ?? null,
      tags: e.tags,
      params: e.parameters.map((p) => ({ name: p.name, in: p.in, required: p.required, type: p.schema.type })),
      bodyRef: bodyName,
      bodySchemaName: bodyName ? (body?.isArray ? `${bodyName}[]` : bodyName) : null,
      bodyContentTypes: e.requestBody?.contents.map((c) => c.contentType) ?? [],
      respRef: respName,
      respSchemaName: respName ? (resp?.isArray ? `${respName}[]` : respName) : null,
      respContentTypes: [...new Set(e.responses.flatMap((r) => r.contents.map((c) => c.contentType)))],
    };
  });

  const resources: Record<string, LegacyResource> = {};
  for (const r of model.resources) {
    const fields: Record<string, LegacyField> = {};
    for (const f of r.fields) {
      const override = overrides[`${r.name}.${f.path}`];
      fields[f.path] = {
        type: f.recursive ? `${f.type} (recursive)` : f.type,
        sensitivity: override ?? f.sensitivity,
        reason: override ? "manual override by analyst" : f.sensitivityReason,
        ref: f.ref ?? null,
      };
    }
    resources[r.name] = {
      endpoints: r.endpoints,
      fields,
      relations: r.relations.map((rel) =>
        rel.kind === "references" ? `${rel.via} -> ${rel.to}` : `endpoint ${rel.to} ${rel.kind === "returned-by" ? "returns" : "accepts"} ${rel.from}`,
      ),
      ownershipField: r.ownershipField,
    };
  }

  const version = model.format === "swagger-2.0" ? `Swagger ${model.specVersion}` : `OpenAPI ${model.specVersion}`;
  return { endpoints, resources, specInfo: { version, servers: model.servers, title: model.title ?? null }, warnings: model.warnings };
}
