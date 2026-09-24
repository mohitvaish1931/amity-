import type { Sensitivity } from "../contracts";
import { tokenize } from "./naming";

export interface Classification {
  level: Sensitivity;
  reason: string;
}

// Token-based rules (whole words after camelCase/snake splitting), so "filename" never matches "name".
const SENSITIVE_TOKENS = new Set([
  "password", "passwd", "passphrase", "secret", "token", "credential", "credentials", "apikey",
  "ssn", "cvv", "cvc", "pin", "iban", "card", "payment", "otp", "salt", "session", "authorization",
  "privatekey", "passport",
]);
const SENSITIVE_PAIRS: readonly (readonly [string, string])[] = [
  ["api", "key"], ["private", "key"], ["access", "key"], ["account", "number"], ["routing", "number"],
  ["tax", "id"], ["national", "id"],
];
const PERSONAL_TOKENS = new Set([
  "email", "phone", "mobile", "telephone", "address", "street", "city", "zip", "zipcode", "postcode",
  "postal", "dob", "birth", "birthday", "birthdate", "gender", "nationality", "username", "surname",
  "firstname", "lastname", "fullname", "latitude", "longitude",
]);
const PERSON_QUALIFIERS = new Set([
  "first", "last", "full", "middle", "given", "family", "display", "legal", "contact", "customer",
  "user", "member", "owner", "holder", "employee", "person", "billing", "shipping", "recipient",
]);
const PERSON_RESOURCES = new Set([
  "user", "customer", "person", "member", "employee", "account", "profile", "contact", "patient", "student",
]);
const INTERNAL_TOKENS = new Set(["internal", "debug", "trace", "stacktrace", "stack"]);
const AUDIT_PAIRS: readonly (readonly [string, string])[] = [["created", "by"], ["updated", "by"], ["modified", "by"], ["deleted", "by"]];

function hasPair(tokens: readonly string[], [a, b]: readonly [string, string]): boolean {
  return tokens.some((t, i) => t === a && tokens[i + 1] === b);
}

/**
 * Heuristic sensitivity for one field. `fieldName` is the leaf name ("email", not "owner.email").
 * `resource` lets a bare "name" count as personal on person-like resources only.
 */
export function classifyField(fieldName: string, resource?: string): Classification {
  const tokens = tokenize(fieldName);
  const joined = tokens.join("");

  const sensitiveHit = tokens.find((t) => SENSITIVE_TOKENS.has(t)) ?? (SENSITIVE_TOKENS.has(joined) ? joined : undefined);
  if (sensitiveHit) return { level: "SENSITIVE", reason: `contains "${sensitiveHit}" (credential/payment/secret pattern)` };
  const sensitivePair = SENSITIVE_PAIRS.find((p) => hasPair(tokens, p));
  if (sensitivePair) return { level: "SENSITIVE", reason: `contains "${sensitivePair.join(" ")}" (credential/identifier pattern)` };

  if (tokens.includes("internal") || tokens.some((t) => INTERNAL_TOKENS.has(t))) {
    return { level: "INTERNAL", reason: "contains internal/debug marker" };
  }
  const audit = AUDIT_PAIRS.find((p) => hasPair(tokens, p));
  if (audit) return { level: "INTERNAL", reason: `audit attribution field ("${audit.join(" ")}")` };

  const last = tokens[tokens.length - 1];
  if (last === "id" || last === "ids" || last === "uuid" || last === "ref") {
    return { level: "PUBLIC", reason: "object identifier/reference" };
  }

  const personalHit = tokens.find((t) => PERSONAL_TOKENS.has(t)) ?? (PERSONAL_TOKENS.has(joined) ? joined : undefined);
  if (personalHit) return { level: "PERSONAL", reason: `contains "${personalHit}" (personal data pattern)` };

  if (tokens.includes("name")) {
    const qualifier = tokens.find((t) => PERSON_QUALIFIERS.has(t));
    if (qualifier) return { level: "PERSONAL", reason: `person name ("${qualifier} name")` };
    const res = resource ? tokenize(resource).at(-1) : undefined;
    if (tokens.length === 1 && res && PERSON_RESOURCES.has(res)) {
      return { level: "PERSONAL", reason: `name on person-like resource "${resource}"` };
    }
  }
  return { level: "PUBLIC", reason: "no sensitive pattern" };
}
