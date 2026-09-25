# Security Constitution

The Security Constitution is a set of machine-readable security laws derived from the typed API model and the configuration. It is produced by one pure, deterministic function:

```ts
generateSecurityConstitution(model: ApiModel, config: ConstitutionConfig): SecurityConstitution
```

(`src/constitution/generate.ts`). It reads nothing from the UI and makes no network requests. A test enforces that no request code exists in `src/constitution/`.

## Pipeline

```
OpenAPI / Swagger ──► ApiModel ──► Security Twin ──► Security Constitution ──► Test specification
 (src/openapi)       (src/model)   (src/twin: graph    (src/constitution:       (law.testStrategy,
                                    of the model)        laws + provenance +      executable: false)
                                                         confidence)
```

- **Model**: endpoints (auth mode, action, resource), resources (fields, sensitivity, ownership field, relationships).
- **Security Twin**: the same model plus configuration as a graph, used for exploration and highlighting.
- **Constitution**: laws. Each has a human statement, a machine rule, a precise scope, provenance, and a confidence rating with its rationale.
- **Test specification**: each law's `testStrategy` describes how the law *would* be verified: preconditions, steps, expected outcome. In this phase it is a specification only. Nothing executes it.

## A law

```ts
interface SecurityLaw {
  id: string;                 // LAW-001… (ordered: category, confidence, severity, key)
  key: string;                // dedup key, e.g. "OBJECT_AUTHORIZATION:Order"
  category: LawCategory;      // see below
  severity: Severity;
  statement: string;          // human-readable
  rule: LawRule;              // machine-readable, typed per rule kind
  invariant: string;          // formal rendering of `rule`
  appliesTo: { endpoints, resources, fields, roles, identities };
  provenance: { kind, ref, detail }[];
  confidence: "HIGH" | "MEDIUM" | "LOW";
  confidenceRationale: { level, score, signals: { id, description, present }[], rule };
  testStrategy: { kind, preconditions, steps, expected, executable: false };
}
```

## Categories and derivation rules

| Category | Generated when | Rule | Confidence |
|---|---|---|---|
| `OBJECT_AUTHORIZATION` | A resource is addressed by an identifier in a path. `/orders/{id}` and `/orders/{id}/invoice` both address **Order** through `{id}`. One law per resource. | `owner-only-access` | **HIGH**: ownership field + objects of ≥2 configured owners + all endpoints authenticated. **MEDIUM**: ownership field. **LOW**: no ownership field. |
| `FUNCTION_AUTHORIZATION` | (a) Administrative endpoints (path segment `admin…`), one law per resource. (b) An explicit deny permission whose name matches a resource and action, e.g. `"Delete Listing": false` for `DELETE /listings/{id}`. (c) Permissions that differ by role but match no endpoint. | `role-restricted` / `permission-matrix` | (a) **HIGH**: privileged role + other roles + explicit deny; **MEDIUM**: privileged role + other roles; **LOW** otherwise. (b) **MEDIUM**, never HIGH (name match). (c) **LOW**. |
| `DATA_EXPOSURE` | A resource's schema has PERSONAL/SENSITIVE fields **and** some endpoint's success response returns it. One law per resource. | `no-unauthorized-field-exposure` | **HIGH**: analyst-confirmed sensitivity + ownership defined. **MEDIUM**: ownership defined or SENSITIVE-level fields. **LOW**: PERSONAL-only without ownership. |
| `AUTHENTICATION` | Endpoints whose effective requirement is `required`, grouped by requirement (e.g. `bearerAuth`). | `requires-authentication` | **HIGH**: declared, typed schemes. **MEDIUM**: a scheme is undeclared or untyped. |
| `STATE_TRANSITION` | A top-level `status`/`state`/`stage`/`phase` field with an enum, changed by an update of that object or a dedicated transition endpoint (`POST /listings/{id}/publish`). | `guarded-state-transition` | **MEDIUM** with dedicated transition endpoints, else **LOW**. Never HIGH, because OpenAPI cannot express the transition table. |
| `SECURITY_CONFIGURATION` | (a) Public (`security: []`), optional (`[{}]`) or undeclared-security endpoints, grouped by mode. Flags sensitive fields in their responses. (b) Requirements that name an undeclared scheme. | `explicit-public-access` / `declared-security-schemes` | (a) **MEDIUM** when declared explicitly, **LOW** when nothing is declared. (b) **HIGH** (a fact of the spec). |

The `score` in the rationale is the share of evidence signals present. The **level** always comes from the category rule above, never from the score alone, and never from a demo requirement.

## Precise scope

- Object laws include only endpoints that address the resource through a path parameter. `POST /orders` (create) is not in the Order object law.
- The configured ownership map (`objectId → ownerId`) is **not typed by resource**, so it is only applied to resources that have an ownership field. It is never attached to others: a User law does not claim the Order owners. When several resources have ownership fields, the law's preconditions say the map needs confirming.
- Data-exposure laws are scoped to the endpoints that *return* the resource and to *its* fields. Two resources sharing a field name (`email`) never share a law.
- **Inherited entitlement:** a resource without its own ownership field that is only reachable through an owned parent's identifier (`/orders/{id}/invoice` → Order) inherits the parent's rule. This is recorded as `relationship:Invoice→Order` provenance and `rule.inheritedFrom = "Order.customerId"`.
- Roles exempt through permissions (`"View any Listing": true`) are excluded from the owner-only subject roles, and are listed in provenance as exempt.

## Provenance

Every law lists its evidence as `{ kind, ref, detail }`. References use these forms:

| Kind | Example ref |
|---|---|
| endpoint / path | `endpoint:GET /orders/{id}` |
| schema | `schema:Order.customerId` |
| sensitivity | `sensitivity:Order.paymentMetadata=SENSITIVE` |
| security | `security:bearerAuth` |
| role | `role:Administrator` (detail says why it is privileged, e.g. a name heuristic) |
| permission | `permission:Customer.View Foreign Order=false` |
| ownership | `ownership:config` (detail lists owners and their objects) |
| relationship | `relationship:Invoice→Order` |

A test checks that every reference resolves to an existing endpoint, schema field, scheme, role, permission or resource, so nothing is invented. Heuristics are labelled as heuristics in the detail text (permission name matching, sensitivity classification, admin role by name).

## Deduplication

Laws are keyed (`OBJECT_AUTHORIZATION:Order`, `FUNCTION_AUTHORIZATION:Listing:delete`, …). Signals that imply the same law are merged into one law: provenance, scope and rule lists are unioned, and a signal counts as present if any source has it. Deny permissions from several roles for the same resource and operation become one law naming all the roles.

## Step 2 compatibility

Step 2 plans by the older law categories. `toLegacyLaws()` (`src/constitution/legacy.ts`) maps the constitution to the historical contract:

| Constitution category | Legacy category |
|---|---|
| OBJECT_AUTHORIZATION | BOLA |
| FUNCTION_AUTHORIZATION (role-restricted / permission-matrix) | ADMIN / ROLE |
| DATA_EXPOSURE | DATA |
| AUTHENTICATION, SECURITY_CONFIGURATION (public access) | AUTHN |
| STATE_TRANSITION, SECURITY_CONFIGURATION (undeclared schemes) | POLICY (no Step 2 cases) |

There is one legacy law per category, identified by its primary (highest-confidence) constitution law, with `constitutionLawIds` listing all the laws it summarizes. The export `testable-security-model.json` contains both `constitution` (full) and `laws` (legacy). The Step 2 demo plan is unchanged (22 cases).

## Demo result

With the demo spec and configuration, the engine derives 7 laws:

| Id | Category | Confidence | Statement |
|---|---|---|---|
| LAW-001 | Object authorization | HIGH | Customer may access only Order objects they own (ownership field Order.customerId). |
| LAW-002 | Object authorization | LOW | Access to User objects by identifier must be authorized per object; the model does not describe who owns a User. |
| LAW-003 | Function authorization | HIGH | Only Administrator may invoke POST /admin/refund; Customer must be denied. |
| LAW-004 | Data exposure | MEDIUM | Invoice responses must not expose paymentMetadata to callers who do not own the parent Order (ownership field Order.customerId). |
| LAW-005 | Data exposure | MEDIUM | Order responses must not expose customerName, phone, address, paymentMetadata to callers who do not own the Order. |
| LAW-006 | Data exposure | LOW | User responses may expose customerName, phone, address only to callers entitled to that User. |
| LAW-007 | Authentication | HIGH | Endpoints secured by bearerAuth must reject requests without valid credentials. |

## Limitations

- Permission names are free text. Matching them to resources and actions is a whole-token heuristic, recorded as such, which is why permission-derived function laws never reach HIGH.
- The ownership map is not typed by resource. Object laws use it only for resources with an ownership field, and flag ambiguity when several exist.
- Sensitivity comes from a name heuristic unless an analyst overrides it. Data-exposure laws only reach HIGH with an override.
- State-transition laws cannot know the allowed transitions (OpenAPI has no way to express them). The test strategy asks for them as a precondition.
- Test strategies are not executed in this phase.

## Constitution Explorer and export

Step 1's Constitution panel has an explorer (`src/constitution/explore.ts`):

- **Filters** by category, severity and confidence. The options are generated from the laws actually present, with counts. There is also a text search over id, statement, invariant, scope entries and provenance references. Non-matching law cards are hidden, not re-rendered, so open cards stay open. Filters survive a rebuild when the value still exists.
- **Export shown laws** as JSON (`sentinel-x-constitution-export-v1`) or Markdown. Exports contain exactly the laws currently shown, record the filter and the total, and state `basis: "specification"` with the disclaimer that no test was executed and no law is a confirmed vulnerability.
- Spec-supplied text is escaped in Markdown, so resource or field names cannot inject links, HTML or table cells.

## Printable report (PDF)

**Report: print / save as PDF** renders `renderConstitutionReport` (`src/constitution/report.ts`) for the laws currently shown and opens the browser's print dialog; choosing "Save as PDF" produces the PDF (no extra dependency). On screen the report stays hidden; print CSS shows only the report, in light colours for paper. Sections:

1. **Executive summary**: counts from the model and configuration, laws by severity and confidence, "verify first" (high severity with high-confidence evidence), and the readiness checklist.
2. **Security Constitution**: one table row per law.
3. **Law details**: statement, machine rule, scope, confidence rationale and signals, provenance, and the test strategy (specification only).
4. **Remediation guidance**: generic guidance per category present (`REMEDIATION`), naming the laws it applies to.
5. **Limitations**: the engine's heuristics (always listed), model notes and parser warnings.

The header states the target, that authorization is not verified, the generation time and the filter. Every part is labelled specification-derived; the report never uses the word CONFIRMED. All spec-supplied text is escaped.
