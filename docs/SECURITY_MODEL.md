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

## 4. Laws (step 1)

Laws are generated from the model and config. There are six categories: BOLA, ADMIN, DATA, AUTHN (protected), AUTHN (open) and ROLE. Each law carries a source, confidence, invariant text and Given/When/Expect tests. Confidence reflects spec and config evidence only. A law is a hypothesis to verify, not a finding.

## 5. Findings (contract)

`src/contracts` defines `Finding.state` as `SUSPECTED | OBSERVED | CONFIRMED`, and marks `TestResult`/`Evidence` with `simulated`. The intended rule is that simulated results can never back a CONFIRMED finding. **The step 2 prototype does not follow this contract yet.** Its mock results are still labelled CONFIRMED. See progress.md.

## 6. Application safety rules

| Rule | Enforcement |
|---|---|
| Untrusted content (spec, config, imported model, LLM text) is rendered as text | `html``/`setHtml` escape every interpolation (`& < > " ' \``); `setHtml` rejects plain strings; `SafeHtml` refuses implicit string conversion. |
| No raw HTML sinks in app code | ESLint `no-restricted-properties` for `innerHTML`/`outerHTML` and a restricted-syntax rule for `insertAdjacentHTML`, plus a static test. |
| XSS regressions | `tests/apps/xss.test.ts` loads the real bundles with crafted spec, config and model content and asserts: no injected elements, no `on*` attributes, no attribute breakout, and no handler execution on focus. The same suite fails 8 of 10 tests against the pre-hardening code. |
| Credentials never serialized into markup | Step 2 sets credential inputs through the DOM `value` property. A test checks the secret is absent from `innerHTML` after a re-render. |
| Parser robustness | Malformed or hostile documents return errors or warnings (tests cover invalid JSON/YAML, wrong roots, bad versions, broken/external/circular refs). YAML alias expansion is capped. |
| Local server | `scripts/serve.mjs` binds to 127.0.0.1, blocks path traversal and sends `X-Content-Type-Options: nosniff`. |
