import { loadSpecObject, loadSpecText } from "./load";
import { normalizeSpec, type NormalizedSpec } from "./normalize";

export type { NormalizedSpec, RawEndpoint } from "./normalize";
export { loadSpecObject, loadSpecText } from "./load";

export type ParseResult = { ok: true; spec: NormalizedSpec } | { ok: false; errors: string[] };

/** Parse OpenAPI 3.x / Swagger 2.0 text (JSON or YAML) into the normalized model. Never throws. */
export function parseApiSpec(text: string): ParseResult {
  return fromLoad(loadSpecText(text));
}

/** Same as parseApiSpec for an already-parsed object. */
export function parseApiSpecObject(doc: unknown): ParseResult {
  return fromLoad(loadSpecObject(doc));
}

function fromLoad(loaded: ReturnType<typeof loadSpecText>): ParseResult {
  if (!loaded.ok) return loaded;
  try {
    return { ok: true, spec: normalizeSpec(loaded.doc, loaded.format, loaded.specVersion, loaded.warnings) };
  } catch (e) {
    // Defensive: malformed input must surface as an error, never crash the caller.
    return { ok: false, errors: [`Could not normalize specification: ${e instanceof Error ? e.message : String(e)}`] };
  }
}
