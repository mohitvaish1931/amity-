// Validation of the Step 1 → Step 2 contract (testable-security-model.json) before the Test Lab plans anything.
// A malformed model produces a list of readable errors instead of a planner crash half-way through.

/** Legacy law categories the Step 2 planner generates cases for (see src/constitution/legacy.ts). */
export const PLANNED_CATEGORIES = ["BOLA", "ADMIN", "DATA", "AUTHN", "ROLE"] as const;
const KNOWN_CATEGORIES: readonly string[] = [...PLANNED_CATEGORIES, "POLICY"];

/** At most this many errors are listed; a badly broken file would otherwise flood the status area. */
export const MAX_MODEL_ERRORS = 10;

export type ModelCheck = { ok: true; warnings: string[] } | { ok: false; errors: string[] };

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string" && v.trim() !== "";

export function validateTestableModel(value: unknown): ModelCheck {
  const errors: string[] = [];
  const warnings: string[] = [];
  if (!isObj(value)) return { ok: false, errors: ["The model must be a JSON object (testable-security-model.json from Step 1)."] };
  const m = value;

  if (!Array.isArray(m.endpoints)) errors.push("endpoints: missing or not an array.");
  else
    m.endpoints.forEach((e, i) => {
      if (!isObj(e)) return errors.push(`endpoints[${i}]: not an object.`);
      if (!isStr(e.method)) errors.push(`endpoints[${i}].method: missing.`);
      if (!isStr(e.path) || !e.path.startsWith("/")) errors.push(`endpoints[${i}].path: missing or does not start with "/".`);
    });

  if (!Array.isArray(m.laws)) errors.push("laws: missing or not an array.");
  else
    m.laws.forEach((l, i) => {
      if (!isObj(l)) return errors.push(`laws[${i}]: not an object.`);
      if (!isStr(l.id)) errors.push(`laws[${i}].id: missing.`);
      if (!isStr(l.category)) errors.push(`laws[${i}].category: missing.`);
      else if (!KNOWN_CATEGORIES.includes(l.category)) warnings.push(`${String(l.id)}: category ${l.category} is not planned by this Test Lab.`);
    });

  if (m.testIdentities !== undefined) {
    if (!Array.isArray(m.testIdentities)) errors.push("testIdentities: not an array.");
    else
      m.testIdentities.forEach((t, i) => {
        if (!isObj(t) || !isStr(t.id)) errors.push(`testIdentities[${i}].id: missing.`);
      });
  }
  if (m.ownership !== undefined) {
    if (!Array.isArray(m.ownership)) errors.push("ownership: not an array of {objectId, ownerId}.");
    else
      m.ownership.forEach((o, i) => {
        if (!isObj(o) || (typeof o.objectId !== "string" && typeof o.objectId !== "number") || !isStr(o.ownerId)) errors.push(`ownership[${i}]: needs objectId and ownerId.`);
      });
  }
  if (m.resources !== undefined && !isObj(m.resources)) errors.push("resources: not an object.");
  if (m.twin !== undefined && !isObj(m.twin)) errors.push("twin: not an object.");
  if (m.sandboxBaseUrl !== undefined && m.sandboxBaseUrl !== null && typeof m.sandboxBaseUrl !== "string") errors.push("sandboxBaseUrl: not a string.");

  if (errors.length) {
    const extra = errors.length - MAX_MODEL_ERRORS;
    return { ok: false, errors: extra > 0 ? [...errors.slice(0, MAX_MODEL_ERRORS), `…and ${extra} more.`] : errors };
  }
  if (Array.isArray(m.laws) && m.laws.length === 0) warnings.push("The model has no laws, so there is nothing to plan.");
  if (Array.isArray(m.endpoints) && m.endpoints.length === 0) warnings.push("The model has no endpoints.");
  return { ok: true, warnings };
}
