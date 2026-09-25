// Maps constitution laws onto the older Step 1 → Step 2 contract (testable-security-model.json `laws`),
// which Step 2's planner consumes by legacy category. One legacy law per legacy category, in the
// historical order; it points back to the constitution laws it summarizes.
import type { Confidence, LawScope, LegacyLawCategory, SecurityConstitution, SecurityLaw, Severity } from "../contracts";

export interface LegacyLaw {
  id: string;
  category: LegacyLawCategory;
  severity: Severity;
  title: string;
  source: string;
  confidence: Confidence;
  /** Share of the primary law's confidence signals that are present (0-100); never a fixed number per level. */
  score: number;
  reason: string;
  invariant: string;
  appliesTo: LawScope;
  /** Constitution law ids summarized by this legacy law (first = primary). */
  constitutionLawIds: string[];
}

export const LEGACY_ORDER: readonly LegacyLawCategory[] = ["BOLA", "ADMIN", "DATA", "AUTHN", "ROLE", "POLICY"];
const SEVERITY_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };

export function legacyCategoryOf(law: SecurityLaw): LegacyLawCategory {
  switch (law.category) {
    case "OBJECT_AUTHORIZATION":
      return "BOLA";
    case "FUNCTION_AUTHORIZATION":
      return law.rule.type === "permission-matrix" ? "ROLE" : "ADMIN";
    case "DATA_EXPOSURE":
      return "DATA";
    case "AUTHENTICATION":
      return "AUTHN";
    case "SECURITY_CONFIGURATION":
      return law.rule.type === "explicit-public-access" ? "AUTHN" : "POLICY";
    case "STATE_TRANSITION":
      return "POLICY";
  }
}

const union = (xs: readonly string[][]) => [...new Set(xs.flat())].sort((a, b) => a.localeCompare(b));

export function toLegacyLaws(constitution: SecurityConstitution): LegacyLaw[] {
  const groups = new Map<LegacyLawCategory, SecurityLaw[]>();
  for (const law of constitution.laws) {
    const c = legacyCategoryOf(law);
    groups.set(c, [...(groups.get(c) ?? []), law]);
  }
  return LEGACY_ORDER.filter((c) => groups.has(c)).map((category) => {
    const laws = groups.get(category)!; // already ordered HIGH-first by the constitution
    const primary = laws[0]!;
    const others = laws.length - 1;
    return {
      id: primary.id,
      category,
      severity: laws.map((l) => l.severity).sort((a, b) => SEVERITY_RANK[a] - SEVERITY_RANK[b])[0]!,
      title: others ? `${primary.statement} (+${others} related law${others > 1 ? "s" : ""}: ${laws.slice(1).map((l) => l.id).join(", ")})` : primary.statement,
      source: [...new Set(laws.flatMap((l) => l.provenance.map((p) => p.ref)))].slice(0, 8).join("; "),
      confidence: primary.confidence,
      score: primary.confidenceRationale.score,
      reason: primary.confidenceRationale.rule,
      invariant: primary.invariant,
      appliesTo: {
        endpoints: union(laws.map((l) => l.appliesTo.endpoints)),
        resources: union(laws.map((l) => l.appliesTo.resources)),
        fields: union(laws.map((l) => l.appliesTo.fields)),
        roles: union(laws.map((l) => l.appliesTo.roles)),
        identities: union(laws.map((l) => l.appliesTo.identities)),
      },
      constitutionLawIds: laws.map((l) => l.id),
    };
  });
}
