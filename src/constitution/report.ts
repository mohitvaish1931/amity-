// Printable Security Constitution report (browser "Save as PDF"). Pure: the caller supplies every value, and every
// interpolation is escaped by html``. Specification-derived only: nothing in it comes from executing a test.
import type { LawCategory, SecurityLaw } from "../contracts/index";
import { html, type SafeHtml } from "../ui/safe-html";
import type { LawFilter } from "./explore";

/** Generic remediation guidance per law category (independent of any particular API). */
export const REMEDIATION: Record<LawCategory, string[]> = {
  AUTHENTICATION: [
    "Require authentication on every endpoint that is not deliberately public, and declare it in the spec.",
    "Reject missing, expired or malformed credentials with 401 before any business logic runs.",
  ],
  OBJECT_AUTHORIZATION: [
    "Check on the server, for every request, that the authenticated principal owns (or is entitled to) the object identified in the path or body.",
    "Derive ownership from server-side data (the ownership field), never from a client-supplied identifier.",
    "Return the same response for 'not found' and 'not yours' (404) to avoid object enumeration.",
  ],
  FUNCTION_AUTHORIZATION: [
    "Enforce role checks on the server for administrative and privileged operations; deny by default.",
    "Keep the role-to-permission mapping in one place and test that non-privileged roles are denied.",
  ],
  DATA_EXPOSURE: [
    "Return only the fields the caller is entitled to see: use per-role response schemas or explicit serialization allow-lists.",
    "Never return credentials, secrets or payment data in general-purpose responses.",
  ],
  STATE_TRANSITION: [
    "Validate state changes on the server against an explicit transition table and the caller's role.",
    "Reject transitions that skip required steps, and record who performed each transition.",
  ],
  SECURITY_CONFIGURATION: [
    "Declare every security scheme referenced by operations, and make public access explicit (security: []).",
    "Resolve contested permissions in the configuration so that each action has one intended outcome per role.",
  ],
};

export interface ReportCheck {
  label: string;
  ok: boolean;
  detail: string;
}

export interface ReportInput {
  specTitle: string | null;
  specVersion: string | null;
  generatedAt: string;
  target: { label: string; detail: string };
  summary: { endpoints: number; resources: number; fields: number; sensitiveFields: number; identities: number; roles: string[] };
  readiness: ReportCheck[];
  /** The laws to include (e.g. the explorer's current selection). */
  laws: readonly SecurityLaw[];
  totalLaws: number;
  filter: LawFilter;
  /** Constitution notes (facts that limited or prevented laws). */
  notes: readonly string[];
  /** Parser/model warnings. */
  warnings: readonly string[];
}

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"] as const;
const CONFIDENCE_ORDER = ["HIGH", "MEDIUM", "LOW"] as const;
const CATEGORY_LABEL: Record<LawCategory, string> = {
  OBJECT_AUTHORIZATION: "Object authorization",
  FUNCTION_AUTHORIZATION: "Function authorization",
  DATA_EXPOSURE: "Data exposure",
  AUTHENTICATION: "Authentication",
  STATE_TRANSITION: "State transition",
  SECURITY_CONFIGURATION: "Security configuration",
};

/** Heuristics the engine relies on; always listed so a reader knows what is inferred rather than declared. */
export const REPORT_LIMITATIONS = [
  "Specification-derived: every law comes from the OpenAPI document and the supplied configuration. No request was sent and no test was executed.",
  "A law is a hypothesis to verify, not a confirmed vulnerability. Confidence rates the evidence in the model, not the behaviour of the API.",
  "Heuristics: resources are inferred from paths, schemas, operation ids and tags; field sensitivity from field names; permissions by matching configuration text to resources and operations; the privileged role by name unless configured. Each is labelled in the law's provenance.",
  "Ownership rules depend on the ownership map in the configuration; objects outside it are not covered.",
];

function describeFilter(f: LawFilter): string {
  const parts = [
    f.categories?.length ? `category ${f.categories.join(", ")}` : "",
    f.severities?.length ? `severity ${f.severities.join(", ")}` : "",
    f.confidences?.length ? `confidence ${f.confidences.join(", ")}` : "",
    f.text?.trim() ? `text "${f.text.trim()}"` : "",
  ].filter(Boolean);
  return parts.length ? parts.join("; ") : "none";
}

function countBy<T extends string>(laws: readonly SecurityLaw[], key: (l: SecurityLaw) => string, order: readonly T[]): [T, number][] {
  return order.map((k) => [k, laws.filter((l) => key(l) === k).length] as [T, number]).filter(([, n]) => n > 0);
}

export function renderConstitutionReport(r: ReportInput): SafeHtml {
  const title = r.specTitle ? `${r.specTitle}${r.specVersion ? ` (${r.specVersion})` : ""}` : "Untitled specification";
  const priority = r.laws.filter((l) => (l.severity === "Critical" || l.severity === "High") && l.confidence === "HIGH");
  const categories = [...new Set(r.laws.map((l) => l.category))];
  const passed = r.readiness.filter((c) => c.ok).length;
  const scopeRow = (label: string, items: readonly string[]) => (items.length ? html`<tr><th scope="row">${label}</th><td>${items.join(", ")}</td></tr>` : "");

  return html`<article class="report" data-testid="constitution-report">
  <header class="report-head">
    <p class="report-kicker">Sentinel X · Security Constitution report</p>
    <h1>${title}</h1>
    <p class="report-basis" data-testid="report-basis"><b>Specification-derived.</b> No test was executed; laws are hypotheses to verify, not confirmed vulnerabilities.</p>
    <table class="report-meta"><tbody>
      <tr><th scope="row">Generated</th><td>${r.generatedAt}</td></tr>
      <tr><th scope="row">Target</th><td>${r.target.label}. ${r.target.detail}</td></tr>
      <tr><th scope="row">Environment</th><td>Sandbox only (policy). Authorization is not verified by Sentinel X.</td></tr>
      <tr><th scope="row">Laws in report</th><td>${r.laws.length} of ${r.totalLaws} (filter: ${describeFilter(r.filter)})</td></tr>
    </tbody></table>
  </header>

  <section>
    <h2>1. Executive summary</h2>
    <p>The specification describes ${r.summary.endpoints} endpoint(s) over ${r.summary.resources} resource(s) with ${r.summary.fields} field(s), ${r.summary.sensitiveFields} of them personal or sensitive. The configuration defines ${r.summary.identities} identit${r.summary.identities === 1 ? "y" : "ies"} in ${r.summary.roles.length} role(s)${r.summary.roles.length ? html` (${r.summary.roles.join(", ")})` : ""}.</p>
    <p>${r.laws.length} law(s) in this report: ${countBy(r.laws, (l) => l.severity, SEVERITY_ORDER).map(([k, n]) => `${n} ${k}`).join(", ") || "none"} by severity; ${countBy(r.laws, (l) => l.confidence, CONFIDENCE_ORDER).map(([k, n]) => `${n} ${k}`).join(", ") || "none"} by confidence.</p>
    ${priority.length
      ? html`<p><b>Verify first</b> (high severity, high-confidence evidence):</p><ul>${priority.map((l) => html`<li><b>${l.id}</b> ${l.statement}</li>`)}</ul>`
      : html`<p>No law combines high severity with high-confidence evidence.</p>`}
    <h3>Readiness for testing: ${passed}/${r.readiness.length} checks</h3>
    <ul class="report-checks">${r.readiness.map((c) => html`<li>${c.ok ? "✓" : "✗"} ${c.label} <span class="report-muted">(${c.detail})</span></li>`)}</ul>
  </section>

  <section>
    <h2>2. Security Constitution</h2>
    ${r.laws.length
      ? html`<table class="report-table"><thead><tr><th scope="col">Law</th><th scope="col">Category</th><th scope="col">Severity</th><th scope="col">Confidence</th><th scope="col">Statement</th></tr></thead><tbody>
      ${r.laws.map((l) => html`<tr><td>${l.id}</td><td>${CATEGORY_LABEL[l.category]}</td><td>${l.severity}</td><td>${l.confidence} (${l.confidenceRationale.score}% of signals)</td><td>${l.statement}</td></tr>`)}
      </tbody></table>`
      : html`<p>No laws match the filter.</p>`}
  </section>

  <section>
    <h2>3. Law details</h2>
    ${r.laws.map((l) => html`<div class="report-law" data-law="${l.id}">
      <h3>${l.id}: ${l.statement}</h3>
      <p class="report-muted">${CATEGORY_LABEL[l.category]} · ${l.severity} severity · ${l.confidence} confidence (${l.confidenceRationale.score}% of signals)</p>
      <p><b>Machine rule:</b> <code>${l.invariant}</code></p>
      <table class="report-meta"><tbody>
        ${scopeRow("Endpoints", l.appliesTo.endpoints)}${scopeRow("Resources", l.appliesTo.resources)}${scopeRow("Fields", l.appliesTo.fields)}${scopeRow("Roles", l.appliesTo.roles)}${scopeRow("Identities", l.appliesTo.identities)}
      </tbody></table>
      <p><b>Confidence rationale:</b> ${l.confidenceRationale.rule}</p>
      <ul>${l.confidenceRationale.signals.map((s) => html`<li>${s.present ? "✓" : "✗"} ${s.description}</li>`)}</ul>
      <p><b>Provenance:</b></p>
      <ul>${l.provenance.map((p) => html`<li><code>${p.ref}</code>: ${p.detail}</li>`)}</ul>
      <p><b>Test strategy</b> (${l.testStrategy.kind}; specification only, not executed): ${l.testStrategy.steps.join(" → ").replace(/[.\s]*$/, ".")} <b>Expected:</b> ${l.testStrategy.expected}</p>
    </div>`)}
  </section>

  <section>
    <h2>4. Remediation guidance</h2>
    ${categories.length
      ? categories.map((c) => html`<h3>${CATEGORY_LABEL[c]}</h3><p class="report-muted">Applies to ${r.laws.filter((l) => l.category === c).map((l) => l.id).join(", ")}</p><ul>${REMEDIATION[c].map((g) => html`<li>${g}</li>`)}</ul>`)
      : html`<p>No laws in this report.</p>`}
  </section>

  <section>
    <h2>5. Limitations</h2>
    <ul>${REPORT_LIMITATIONS.map((t) => html`<li>${t}</li>`)}</ul>
    ${r.notes.length ? html`<h3>Model notes</h3><ul>${r.notes.map((n) => html`<li>${n}</li>`)}</ul>` : ""}
    ${r.warnings.length ? html`<h3>Parser warnings</h3><ul>${r.warnings.map((w) => html`<li>${w}</li>`)}</ul>` : ""}
  </section>
  <footer class="report-muted">Generated by Sentinel X at ${r.generatedAt}. Specification-derived; no test was executed.</footer>
</article>`;
}
