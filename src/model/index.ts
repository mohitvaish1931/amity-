import type { ApiModel, Sensitivity } from "../contracts";
import { parseApiSpec } from "../openapi";
import { toLegacyView, type LegacyView } from "./legacy-view";
import { buildApiModel } from "./resources";

export { buildApiModel, inferAction, inferResource, isAdminPath, schemaBaseName } from "./resources";
export { classifyField } from "./sensitivity";
export { pascal, resourceName, singularize, tokenize } from "./naming";
export { toLegacyView } from "./legacy-view";
export type { LegacyEndpoint, LegacyField, LegacyResource, LegacyView } from "./legacy-view";

export type AnalysisResult = { ok: true; model: ApiModel; view: LegacyView } | { ok: false; errors: string[] };

/** Spec text -> typed ApiModel + legacy view for the browser apps. Never throws. */
export function analyzeSpecText(text: string, overrides: Record<string, Sensitivity> = {}): AnalysisResult {
  const parsed = parseApiSpec(text);
  if (!parsed.ok) return parsed;
  const model = buildApiModel(parsed.spec);
  return { ok: true, model, view: toLegacyView(model, overrides) };
}

/** Fill every {param} in a path template. Values are looked up by name, then used positionally. */
export function fillPathTemplate(path: string, values: Record<string, string> | readonly string[]): string {
  let i = 0;
  return path.replace(/\{([^}]+)\}/g, (whole, name: string) => {
    const v = Array.isArray(values) ? values[i++] : (values as Record<string, string>)[name];
    return v === undefined ? whole : encodeURIComponent(v);
  });
}
