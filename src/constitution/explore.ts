// Constitution Explorer: filtering and export of generated laws. Pure functions; no knowledge of any particular API.
import type { Confidence, LawCategory, SecurityConstitution, SecurityLaw, Severity } from "../contracts/index";

export interface LawFilter {
  categories?: LawCategory[];
  severities?: Severity[];
  confidences?: Confidence[];
  /** Case-insensitive; matches id, statement, invariant, scope entries and provenance refs. */
  text?: string;
}

/** Everything a law can be found by in a text search. */
function searchableText(law: SecurityLaw): string {
  const s = law.appliesTo;
  return [law.id, law.category, law.statement, law.invariant, ...s.endpoints, ...s.resources, ...s.fields, ...s.roles, ...s.identities, ...law.provenance.map((p) => p.ref)]
    .join("\n")
    .toLowerCase();
}

export function filterLaws(laws: readonly SecurityLaw[], filter: LawFilter = {}): SecurityLaw[] {
  const text = (filter.text ?? "").trim().toLowerCase();
  const inSet = <T>(set: T[] | undefined, v: T) => !set || set.length === 0 || set.includes(v);
  return laws.filter(
    (l) =>
      inSet(filter.categories, l.category) &&
      inSet(filter.severities, l.severity) &&
      inSet(filter.confidences, l.confidence) &&
      (!text || searchableText(l).includes(text)),
  );
}

/** Where the exported laws came from. */
export interface ExportContext {
  specTitle: string | null;
  specVersion: string | null;
  generatedAt: string;
  filter: LawFilter;
}

const NOT_EXECUTED =
  "Specification-derived: laws come from the OpenAPI model and the supplied configuration. Test strategies are specifications; no test was executed and no law is a confirmed vulnerability.";

export interface ConstitutionExport {
  format: "sentinel-x-constitution-export-v1";
  basis: "specification";
  disclaimer: string;
  source: { specTitle: string | null; specVersion: string | null };
  generatedAt: string;
  filter: LawFilter;
  totalLaws: number;
  exportedLaws: number;
  notes: string[];
  laws: SecurityLaw[];
}

export function exportConstitutionJson(constitution: SecurityConstitution, laws: readonly SecurityLaw[], ctx: ExportContext): ConstitutionExport {
  return {
    format: "sentinel-x-constitution-export-v1",
    basis: "specification",
    disclaimer: NOT_EXECUTED,
    source: { specTitle: ctx.specTitle, specVersion: ctx.specVersion },
    generatedAt: ctx.generatedAt,
    filter: ctx.filter,
    totalLaws: constitution.laws.length,
    exportedLaws: laws.length,
    notes: [...constitution.notes],
    // Laws are plain JSON data; a JSON round trip copies them without relying on structuredClone.
    laws: laws.map((l) => JSON.parse(JSON.stringify(l)) as SecurityLaw),
  };
}

/** Escapes Markdown syntax in free text so spec-supplied names cannot inject links, HTML or formatting. */
export function mdText(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/[\\`*_{}[\]()#+!|~]/g, (c) => `\\${c}`)
    .replace(/\r?\n/g, " ");
}

/** Inline code span that stays intact whatever backticks the value contains. */
export function mdCode(value: string): string {
  const text = value.replace(/\r?\n/g, " ");
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((r) => r.length));
  const fence = "`".repeat(longest + 1);
  const pad = text.startsWith("`") || text.endsWith("`") ? " " : "";
  return `${fence}${pad}${text}${pad}${fence}`;
}

function describeFilter(f: LawFilter): string {
  const parts = [
    f.categories?.length ? `category ${f.categories.join(", ")}` : "",
    f.severities?.length ? `severity ${f.severities.join(", ")}` : "",
    f.confidences?.length ? `confidence ${f.confidences.join(", ")}` : "",
    f.text?.trim() ? `text "${f.text.trim()}"` : "",
  ].filter(Boolean);
  return parts.length ? parts.join("; ") : "none";
}

export function exportConstitutionMarkdown(constitution: SecurityConstitution, laws: readonly SecurityLaw[], ctx: ExportContext): string {
  const out: string[] = [];
  const title = ctx.specTitle ? `${ctx.specTitle}${ctx.specVersion ? ` (${ctx.specVersion})` : ""}` : "Untitled specification";
  out.push(`# Security Constitution: ${mdText(title)}`, "");
  out.push(`> ${NOT_EXECUTED}`, "");
  out.push(`- Generated: ${mdText(ctx.generatedAt)}`);
  out.push(`- Laws: ${laws.length} of ${constitution.laws.length} (filter: ${mdText(describeFilter(ctx.filter))})`, "");
  if (laws.length) {
    out.push("| Law | Category | Severity | Confidence | Statement |", "|---|---|---|---|---|");
    for (const l of laws) out.push(`| ${l.id} | ${l.category} | ${l.severity} | ${l.confidence} (${l.confidenceRationale.score}% of signals) | ${mdText(l.statement)} |`);
    out.push("");
  } else {
    out.push("_No laws match the filter._", "");
  }
  for (const l of laws) {
    out.push(`## ${l.id}: ${mdText(l.statement)}`, "");
    out.push(`- Category: ${l.category}`, `- Severity: ${l.severity}`, `- Confidence: ${l.confidence} (${l.confidenceRationale.score}% of signals)`, "");
    out.push("**Machine rule**", "", mdCode(l.invariant), "");
    const scope: [string, string[]][] = [
      ["Endpoints", l.appliesTo.endpoints],
      ["Resources", l.appliesTo.resources],
      ["Fields", l.appliesTo.fields],
      ["Roles", l.appliesTo.roles],
      ["Identities", l.appliesTo.identities],
    ];
    out.push("**Scope**", "");
    for (const [label, items] of scope) if (items.length) out.push(`- ${label}: ${items.map(mdCode).join(", ")}`);
    out.push("", `**Provenance (${l.provenance.length})**`, "");
    for (const p of l.provenance) out.push(`- ${mdCode(p.ref)}: ${mdText(p.detail)}`);
    out.push("", `**Confidence rationale**: ${mdText(l.confidenceRationale.rule)}`, "");
    for (const s of l.confidenceRationale.signals) out.push(`- [${s.present ? "x" : " "}] ${mdText(s.description)}`);
    out.push("", `**Test strategy** (${mdText(l.testStrategy.kind)}; specification only, not executed)`, "");
    if (l.testStrategy.preconditions.length) out.push(`Preconditions: ${l.testStrategy.preconditions.map(mdText).join("; ")}`, "");
    l.testStrategy.steps.forEach((st, i) => out.push(`${i + 1}. ${mdText(st)}`));
    out.push("", `Expected: ${mdText(l.testStrategy.expected)}`, "");
  }
  if (constitution.notes.length) {
    out.push("## Model notes", "");
    for (const n of constitution.notes) out.push(`- ${mdText(n)}`);
    out.push("");
  }
  return out.join("\n");
}
