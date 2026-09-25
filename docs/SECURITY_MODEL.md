# Security Model

How Sentinel X derives its security model from a specification, and the safety rules the apps themselves follow. Everything here is static analysis of the spec and config. Nothing in this document performs network activity.

## 1. Authentication semantics (per operation)

The effective requirement follows the OpenAPI specification:

| Declaration | Result |
|---|---|
| Operation has `security` (any array) | It replaces the root requirement (`source: "operation"`). |
| Operation has none, root has `security` | Inherited (`source: "root"`). |
| Neither declares `security` | `mode: "public"`, `source: "none"`: no authentication by spec. The detail text flags it for review. |
| `security: []` | `mode: "public"`, explicitly. |
| A list containing `{}` | `mode: "optional"`: anonymous access is allowed next to authenticated access. |
| Otherwise | `mode: "required"`. Schemes inside one object are AND-ed, list entries are OR-ed, and scopes are kept. |

Requirements that name an undeclared scheme are kept with `known: false` and produce a warning. Declaring `securitySchemes` without applying them does **not** make an operation protected.

The step 1 view uses `auth: true` only for `required`. `optional` and `public` endpoints count as open and get the "open endpoints must be intentional" law.

## 2. Resources and actions

- **Action** comes from the HTTP method. A path containing an `admin…` segment gives `AdminAction`. GET/HEAD returns `Read` or `List` based on the success response (array vs object) when known; otherwise it goes by the path shape (a trailing parameter, or a singular segment after a parameter, means `Read`).
- **Resource** is picked by weighted evidence, and every endpoint records the evidence behind its choice:
  - schema name of the primary request/response (weight 4), with affixes like `Create…Request` and `…List` removed;
  - last meaningful static path segment (weight 3), skipping version segments, pseudo segments (`me`, `search`…) and trailing action verbs after an id (`/orders/{id}/cancel` belongs to `Order`);
  - operationId noun (weight 2);
  - first non-generic tag (weight 1).
- **Fields** come from component schemas whose base name matches the resource. Otherwise they come from the endpoints' primary schemas. As a last resort the trailing path parameter is used, with a warning. Nested and array fields are included.
- **Ownership field**: a top-level identifier whose preceding word is an owner-like term (`owner`, `user`, `customer`, `account`, `member`, `author`, `creator`, `tenant`), or `createdBy`/`ownedBy`/`owner`. It skips the resource's own id (`User.userId`) and anything marked `internal`.
- **Relationships**: `$ref` fields (`references`), `<name>Id` fields that match another resource, and which endpoints return or accept each schema.

## 3. Field sensitivity

Classification works on whole-word tokens after camelCase/snake splitting, so `filename` never matches `name`. It is checked in this order, and each result carries a reason:

1. **SENSITIVE**: credentials, secrets and payment data (`password`, `token`, `apiKey`, `secret`, `card…`, `payment…`, `ssn`, `iban`, `cvv`, `session`…).
2. **INTERNAL**: `internal`/`debug`/`trace` markers and audit attribution (`createdBy`, `updatedBy`).
3. **PUBLIC**: identifier references (`…Id`, `…Uuid`) such as `customerId`.
4. **PERSONAL**: contact and identity data (`email`, `phone`, `address`, `username`, `dateOfBirth`…), person names (`customerName`, `displayName`), and a bare `name` only on person-like resources.
5. **PUBLIC**: everything else.

Analysts can override any field in step 1, keyed by `Resource.fieldPath`. Overrides survive rebuilds.

## 4. Security Constitution (laws)

Laws come from `generateSecurityConstitution(model, config)` (`src/constitution`). It is pure and deterministic, and makes no requests. The categories are `AUTHENTICATION`, `OBJECT_AUTHORIZATION`, `FUNCTION_AUTHORIZATION`, `DATA_EXPOSURE`, `STATE_TRANSITION` and `SECURITY_CONFIGURATION`. Each law has:

- a human-readable **statement** and a separate typed **machine rule** (with a formal invariant);
- a precise **scope**: endpoints, resources, fields, roles and identities;
- **provenance**: every piece of evidence as a resolvable reference, with heuristics labelled;
- an explainable **confidence**: per-category rules over named evidence signals, with each signal shown as present or missing;
- a **test strategy**, which is a specification only (`executable: false`).

A law is a hypothesis to verify, not a finding. See [SECURITY_CONSTITUTION.md](SECURITY_CONSTITUTION.md) for the derivation rules, confidence thresholds, scope rules and the Step 2 mapping. Step 2 still receives laws in the legacy categories (BOLA/ADMIN/DATA/AUTHN/ROLE/POLICY) through `toLegacyLaws()`.

## 5. Findings (contract)

`src/contracts` defines `Finding.state` as `SUSPECTED | OBSERVED | CONFIRMED`, and marks `TestResult`/`Evidence` with `simulated`. Simulated results can never back a CONFIRMED finding. The Step 2 prototype now labels every mock result and finding **SIMULATED** (badges, evidence package `status`/`simulated`, and the reasoning trail), shows the law's own confidence level instead of a percentage, and reserves CONFIRMED for live runs against a registered target. Its execution and confirmation logic is otherwise still the prototype (see docs/TEST_LAB.md).

## 6. Application safety rules

| Rule | Enforcement |
|---|---|
| Untrusted content (spec, config, imported model, LLM text) is rendered as text | `html``/`setHtml` escape every interpolation (`& < > " ' \``); `setHtml` rejects plain strings; `SafeHtml` refuses implicit string conversion. |
| No raw HTML sinks in app code | ESLint `no-restricted-properties` for `innerHTML`/`outerHTML` and a restricted-syntax rule for `insertAdjacentHTML`, plus a static test. |
| XSS regressions | `tests/apps/xss.test.ts` loads the real bundles with crafted spec, config and model content and asserts: no injected elements, no `on*` attributes, no attribute breakout, and no handler execution on focus. The same suite fails 8 of 10 tests against the pre-hardening code. |
| Credentials never serialized into markup | Step 2 sets credential inputs through the DOM `value` property. A test checks the secret is absent from `innerHTML` after a re-render. |
| Parser robustness | Malformed or hostile documents return errors or warnings (tests cover invalid JSON/YAML, wrong roots, bad versions, broken/external/circular refs). YAML alias expansion is capped. |
| Local server | `scripts/serve.mjs` binds to 127.0.0.1, sends `X-Content-Type-Options: nosniff`, and resolves paths with `scripts/static-path.mjs`: 400 for undecodable paths (previously a malformed escape crashed the server), 403 outside `dist/` (previously a prefix-sharing sibling such as `dist-old/` was reachable). |
| Target scope | `src/target/policy.ts`: only loopback, private-network and reserved-name hosts can be registered, and every live request must stay on the registered origin and base path. Redirects are refused. See docs/SANDBOX.md. |
| Content-Security-Policy | Both pages: `script-src 'self'`, no inline scripts or `on*` attributes (the last inline handler was removed), `object-src 'none'`, `base-uri 'none'`, `form-action 'none'`. A test checks it. |
| Honest status | No blocking `alert()`: operations report loading/success/empty/error inline (`src/ui/status.ts`). A failed demo load offers Retry, and a denied clipboard is reported instead of claiming the copy worked. |
| Browser storage | Only Step 1, and only after the user ticks "Remember…": spec, configuration, sandbox URL and sensitivity overrides (`src/ui/persist.ts`, declared fields only, validated on load, removed if unreadable). Unticking or **Clear saved data** removes it. Step 2 stores nothing (targets and credentials stay in memory). |
| Printable report | `renderConstitutionReport` escapes every value; the report is labelled specification-derived and never says CONFIRMED. |
| Markdown export | `exportConstitutionMarkdown` escapes spec-supplied text (HTML entities for `<`, `>` and `&`, backslash escapes for Markdown syntax), and code spans use a fence longer than any backtick run. |
