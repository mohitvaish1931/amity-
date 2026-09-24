import type { AuthRequirement, SecurityAlternative, SecuritySchemeRef, SpecFormat } from "../contracts";
import { isRecord, type SpecDocument } from "./load";
import type { RefResolver } from "./refs";

/** Declared schemes from components.securitySchemes (OAS 3) or securityDefinitions (Swagger 2). */
export function collectSecuritySchemes(
  doc: SpecDocument,
  format: SpecFormat,
  resolver: RefResolver,
): Record<string, SecuritySchemeRef> {
  const container =
    format === "swagger-2.0"
      ? doc.securityDefinitions
      : isRecord(doc.components)
        ? doc.components.securitySchemes
        : undefined;
  const out: Record<string, SecuritySchemeRef> = {};
  if (!isRecord(container)) return out;
  for (const [name, rawScheme] of Object.entries(container)) {
    const s = resolver.deref(rawScheme);
    if (!s) continue;
    const scheme: SecuritySchemeRef = { name, type: typeof s.type === "string" ? s.type : "unknown", scopes: [], known: true };
    if (scheme.type === "basic") {
      // Swagger 2 "basic" is HTTP basic auth in OAS 3 terms.
      scheme.type = "http";
      scheme.scheme = "basic";
    }
    if (typeof s.scheme === "string") scheme.scheme = s.scheme.toLowerCase();
    if (typeof s.in === "string") scheme.in = s.in;
    if (typeof s.name === "string") scheme.paramName = s.name;
    out[name] = scheme;
  }
  return out;
}

/**
 * Effective security for one operation, following OpenAPI semantics:
 * - operation `security` (even `[]`) replaces root `security`;
 * - `[]` means no authentication;
 * - an empty requirement object `{}` inside the list makes authentication optional;
 * - entries inside one requirement object are AND-ed, list entries are OR-ed;
 * - nothing declared anywhere means the spec requires no authentication.
 */
export function resolveAuth(
  opSecurity: unknown,
  rootSecurity: unknown,
  schemes: Record<string, SecuritySchemeRef>,
  warnings: string[],
  where: string,
): AuthRequirement {
  let source: AuthRequirement["source"];
  let reqs: unknown[];
  if (opSecurity !== undefined) {
    if (!Array.isArray(opSecurity)) {
      warnings.push(`${where}: "security" must be an array; ignored.`);
      return resolveAuth(undefined, rootSecurity, schemes, warnings, where);
    }
    source = "operation";
    reqs = opSecurity;
  } else if (Array.isArray(rootSecurity)) {
    source = "root";
    reqs = rootSecurity;
  } else {
    return {
      mode: "public",
      source: "none",
      alternatives: [],
      detail: "no security requirement declared (public per spec; verify intent)",
    };
  }

  const label = source === "operation" ? "operation security" : "root security";
  if (reqs.length === 0) {
    return { mode: "public", source, alternatives: [], detail: `${label}: [] (explicitly public)` };
  }

  const alternatives: SecurityAlternative[] = reqs.map((req) => {
    if (!isRecord(req)) return { schemes: [] };
    return {
      schemes: Object.entries(req).map(([name, scopes]) => {
        const declared = schemes[name];
        const scopeList = Array.isArray(scopes) ? scopes.filter((x): x is string => typeof x === "string") : [];
        if (!declared) warnings.push(`${where}: security requirement references undeclared scheme "${name}".`);
        return declared
          ? { ...declared, scopes: scopeList }
          : { name, type: "unknown", scopes: scopeList, known: false };
      }),
    };
  });

  const anonymousAllowed = alternatives.some((a) => a.schemes.length === 0);
  const text = alternatives
    .map((a) => {
      if (!a.schemes.length) return "anonymous";
      const parts = a.schemes.map((s) => (s.scopes.length ? `${s.name}[${s.scopes.join(",")}]` : s.name));
      return parts.length > 1 ? `(${parts.join(" AND ")})` : parts[0];
    })
    .join(" OR ");
  return {
    mode: anonymousAllowed ? "optional" : "required",
    source,
    alternatives,
    detail: `${label}: ${text}${anonymousAllowed ? " (authentication optional)" : ""}`,
  };
}
