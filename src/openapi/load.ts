import { parse as parseYaml } from "yaml";
import type { SpecFormat } from "../contracts";

export type SpecDocument = Record<string, unknown>;

export type LoadResult =
  | { ok: true; doc: SpecDocument; format: SpecFormat; specVersion: string; warnings: string[] }
  | { ok: false; errors: string[] };

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Parse spec text (JSON or YAML) and identify the OpenAPI/Swagger version. Never throws. */
export function loadSpecText(text: string): LoadResult {
  const trimmed = text.trim();
  if (!trimmed) return { ok: false, errors: ["Specification is empty."] };

  let raw: unknown;
  const looksJson = trimmed.startsWith("{") || trimmed.startsWith("[");
  try {
    raw = looksJson ? JSON.parse(trimmed) : parseYaml(trimmed, { maxAliasCount: 100 });
  } catch (e) {
    const kind = looksJson ? "JSON" : "YAML";
    return { ok: false, errors: [`Invalid ${kind}: ${e instanceof Error ? e.message : String(e)}`] };
  }
  return loadSpecObject(raw);
}

/** Validate an already-parsed document. Never throws. */
export function loadSpecObject(raw: unknown): LoadResult {
  if (!isRecord(raw)) return { ok: false, errors: ["Specification must be a JSON/YAML object."] };

  const errors: string[] = [];
  const warnings: string[] = [];
  let format: SpecFormat | null = null;
  let specVersion = "";

  if (typeof raw.openapi === "string") {
    specVersion = raw.openapi;
    if (/^3\.0(\.|$)/.test(raw.openapi)) format = "openapi-3.0";
    else if (/^3\.1(\.|$)/.test(raw.openapi)) format = "openapi-3.1";
    else errors.push(`Unsupported OpenAPI version "${raw.openapi}" (supported: 3.0.x, 3.1.x).`);
  } else if (raw.swagger !== undefined) {
    specVersion = String(raw.swagger);
    if (specVersion === "2.0") format = "swagger-2.0";
    else errors.push(`Unsupported Swagger version "${specVersion}" (supported: 2.0).`);
  } else {
    errors.push('Missing version field: expected "openapi: 3.x" or "swagger: 2.0".');
  }

  if (raw.paths === undefined) {
    warnings.push("No paths object: the API has no operations.");
  } else if (!isRecord(raw.paths)) {
    errors.push('"paths" must be an object mapping path templates to path items.');
  }

  if (errors.length || !format) return { ok: false, errors };
  return { ok: true, doc: raw, format, specVersion, warnings };
}
