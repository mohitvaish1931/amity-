# Progress

## 2026-09-24: Phase: Small foundation blockers ✅

Scope: UI truthfulness and path-template handling. No runtime or network features were added.

### Sandbox authorization state (Step 1)

- Removed the static `🟢 Authorized Sandbox` label. The banner is now a policy statement (`🛡 POLICY: use only sandbox targets you are authorized to test`), not a status.
- New typed model `src/target/authorization.ts`: `TargetAuthorizationState = "UNKNOWN" | "CONFIGURED" | "CONFIRMED"`.
  - `UNKNOWN`: no URL, or an invalid one (non-http(s), unparsable, or with embedded credentials).
  - `CONFIGURED`: a valid URL. The label says "Authorization status unknown", because configuring a URL proves nothing.
  - `CONFIRMED`: only with a complete authorization record for the same normalized target. **Nothing in the apps produces such a record yet**, so Step 1 can never show it.
- The Connect card, dashboard and exported model (`targetAuthorization`) render from this state, and it updates as the URL is typed.

### Path parameters

- One implementation, `src/paths/index.ts`: `fillPath(template, params, { onMissing })`, plus `pathParamNames` and `lastPathParam`.
  - Exact-name matching (`{id}` never touches `{userId}`), template order, repeated params, strings/numbers/bigints.
  - Values are percent-encoded as a single segment (`/` → `%2F`, space → `%20`).
  - Inputs are never mutated.
  - Missing values raise `MissingPathParameterError`, listing every missing name. Unsafe values raise `InvalidPathParameterError`: empty, `.`/`..` dot-segments (URL parsers resolve them even when encoded), non-finite numbers, objects.
  - `onMissing: "keep"` exists for human-readable display only.
- Removed: Step 2's first-parameter-only `fillPath`/`idParam`, and `src/model`'s lenient `fillPathTemplate`. Step 1's `fillObjectId` now uses `fillPath` (display mode).
- Step 2 behaviour:
  - An object id fills the endpoint's **last** parameter (the addressed object).
  - Endpoints with other parameters that have no known values are **skipped with a reason** in the planner. Values are never invented.
  - Admin endpoints with path params are handled the same way. They were previously planned with a literal `{param}` in the URL.
  - Anonymous (AUTHN) probes fill **every** parameter with the documented placeholder `1`, not just the first.
  - The matrix shows "not planned — missing path parameter values" instead of a broken path.
- Not consolidated on purpose: OpenAPI **server URL variables** (`src/openapi/normalize.ts`). These are server templates with spec-defined defaults that must not be percent-encoded, not path parameters.

### Verification

- `npm run check`: typecheck ✅ lint ✅ **207/207** tests ✅ build ✅
- Negative control: the new app tests fail **6 of 7** against the previous commit's code. The seventh, "demo plan unchanged", is meant to pass on both.
- Manual check of the production build: Step 1 shows the CONFIGURED state wording, the graph renders (27 nodes, 49 edges), law test paths are filled, and there are no console errors. Step 2 demo plan unchanged (22 cases). A two-parameter endpoint is skipped with a reason, and no planned path contains `{`.

## 2026-09-24: Phase: Security Twin visualization ✅

Scope: frontend/model visualization only. No network testing or runtime logic was added.

### Done (verified by running it)

| Item | Evidence |
|---|---|
| Pure graph transformation `src/twin/graph.ts` (model + config + laws → nodes/edges with provenance) | `tests/twin/graph.test.ts` (23 tests) |
| Deterministic layered layout `src/twin/layout.ts` | `tests/twin/layout.test.ts` (6 tests: empty, single, row order, crossing reduction, 83-node no-overlap + wrapping, determinism) |
| React Flow `SecurityTwinGraph` replacing the ASCII twin in Step 1 | `tests/apps/twin-graph.test.ts` (8 tests on the real bundle in jsdom) |
| Laws carry a structured `appliesTo` scope (endpoints/resources/fields/roles) | Contract `LawScope`; graph GOVERNS edges; sample model regenerated |
| Visual check of the production build in a real browser | Demo: 27 nodes, 49 edges, none hidden. Real mouse clicks select nodes and edges; the detail panel shows relationships, laws and provenance; law highlight dims out-of-scope entities |
| `npm run check` | typecheck ✅ lint ✅ 178/178 tests ✅ build ✅; `npm audit` 0 vulnerabilities |

### Graph semantics (only relationships present in the data)

- `HAS_ROLE` identity→role (config) · `OWNS` identity→resource (config ownership map + the resource's ownership field; flagged when the map could apply to several resources)
- `READS`/`WRITES` endpoint→resource (action inference) · `RETURNS` endpoint→resource (response schema)
- `RELATES_TO` resource→resource (reference fields) · `EXPOSES` / `HAS_FIELD` resource→field (sensitive / ownership field)
- `REQUIRES_ROLE` admin endpoint→privileged role (heuristic, labelled as such) · `GOVERNS` law→scope entities
- `VIOLATES` endpoint→law **only** when findings are supplied. Step 1 has none, so none are drawn.

### Fixed while verifying

- `describeNode` listed a law twice when it both governs and is violated at a node (found by a unit test).
- The toolbar said "identitys" (found by the app test).
- The minimap covered part of the canvas on normal-sized graphs. It now appears only above 60 nodes, compact and dark.
- Field nodes didn't show their resource, so the two `customerName` fields looked identical. The subtitle now shows `SENSITIVITY · Resource`.

### Limitations

- CAN_CALL (role→endpoint) is not drawn: permissions in the config are free-text action names, not bound to endpoints, so any such edge would be invented.
- The configured ownership map is not typed by resource, so OWNS edges attach to every resource with an ownership field (noted in provenance).
- In jsdom, tests drive clicks through DOM events. Real pointer interactions (drag, zoom, pan) were checked by hand in the browser, not automated (no Playwright yet).
- The Step 1 bundle grew from 143 KiB to 556 KiB (React + React Flow).

## 2026-09-24: Phase: Foundation hardening ✅

Scope: parser hardening, XSS safety, test infrastructure, typed contracts, docs. No network or runtime testing work was done in this phase.

### Done (verified by running it)

| Item | Evidence |
|---|---|
| TypeScript toolchain (`package.json`, strict `tsconfig`, ESLint, Vitest, esbuild build) | `npm run check` passes: typecheck ✅ lint ✅ 141/141 tests ✅ build ✅ |
| `npm audit` | 0 vulnerabilities (vitest pinned to 4.1.11 to clear a dev-only advisory) |
| Shared typed contracts (`src/contracts`) | Used by parser, model and tests |
| OpenAPI parser rewrite (`src/openapi`) | Fixtures A–M; see tests.json |
| Security model (`src/model`): resources, actions, sensitivity, ownership, relations | `tests/model/*` |
| Step 1 app uses the typed parser/model | App-level jsdom tests with the real bundle; checked manually in the browser from `dist/` |
| XSS fixed in both apps (all rendering through `html``/`setHtml`) | `tests/apps/xss.test.ts`; the same suite **fails 8/10** against the pre-hardening code |
| Step 2 demo model regenerated from the new step 1 | Drift test in `tests/apps/apps.test.ts` |

### Audit issues closed in this phase

| Audit ID | Fix |
|---|---|
| BUG-09 (step 1 part) | Law test paths fill the object id into the last path parameter. `fillPathTemplate` fills every parameter. |
| BUG-14 | Warnings are rebuilt from scratch on every rebuild (test: repeated Apply config). |
| BUG-15a | Parameter `$ref` resolved (fixtures B, F). |
| BUG-15b | `requestBody`/`responses` `$ref` chains, array responses and inline schemas (fixtures A, J, K). |
| BUG-15c | `security: [{}]` = optional, `[]` = public, AND/OR kept (fixtures G, H, I). |
| BUG-15d | All `oneOf`/`anyOf` branches, branch-only fields tagged (fixture M). |
| BUG-15e | Nested and array fields flattened and classified (fixtures C, D). |
| BUG-15f | Swagger 2 root-level `consumes`/`produces` and `formData` (fixture B). |
| BUG-15g | YAML input (fixture E, app test). |
| BUG-15h | Path-level + operation-level parameter merge by (name, in); content types recorded; undeclared path params synthesized. |
| BUG-16 | Resource inference from weighted path/schema/operationId/tag evidence; hardcoded keyword list removed. |
| BUG-17 | Token-based classifier (`customerId`, `filename`, `hostname` no longer PERSONAL). |
| BUG-12 (message) | Step 1 no longer claims "production blocked" while sending the request. |
| SEC-03 | Stored XSS in both apps fixed and regression-tested. |
| SEC-09 | Credential values are no longer written into HTML attributes. |
| Dead code | Removed unused helpers in step 2 (`roleOf`, `epById`, `firstIdGet`, `firstAdminEp`, `KIND_PRIO`). |

### Decisions

- **Runtime language/tooling:** TypeScript 5.9 (not 7.x, which is the new native compiler with breaking changes), Vitest 4, ESLint 9. Pinned exact versions.
- **Apps stay vanilla JS** and import typed modules from `src/`, bundled by esbuild. This keeps the UI unchanged while making the engine typed and testable. Cost: the apps now need `npm run build` (or `npm start`).
- **No domain words in the engine.** Inference relies on REST structure plus generic grammar, and records evidence.
- **`security` declared nowhere means public** (the spec's meaning), flagged in the detail text. The previous code assumed protected.

## Open items / remaining blockers

1. **Step 2 execution and findings are still the prototype.** It runs in the browser, approval is client-side only, confirmation repeats only the last request and compares status codes only, mock findings are labelled CONFIRMED, and HTTP 200 alone is treated as exposure (audit BUG-01…08, BUG-10, BUG-11, SEC-01, SEC-02, SEC-04, SEC-05). Not touched in this phase by design.
2. ~~Step 2 `fillPath` still fills only the first path parameter (BUG-09, step 2 part).~~ Fixed in "Small foundation blockers".
3. Step 2 has not adopted the typed contracts (`TestCase`, `TestResult`, `Finding`, `Evidence`). Only rendering was migrated.
4. External `$ref` (remote/file) is not supported: it produces a warning.
5. ~~Step 1 still shows a static "🟢 Authorized Sandbox" label regardless of state.~~ Fixed in "Small foundation blockers". Step 2's banner still uses the older "🟢 AUTHORIZED SANDBOX ONLY" wording (its live-run approval checkbox is separate and unchanged).
5a. No end-to-end browser automation (Playwright) yet; graph pointer interactions were verified manually.
6. No backend, persistence, CI pipeline or Docker files yet.
7. Planning docs from the audit (`docs/TARGET_ARCHITECTURE.md`, `docs/FULL_IMPLEMENTATION_PLAN.md`) were not produced.

## Next suggested phase

Replace step 2's analyzer and finding logic with the typed contracts: explicit finding states, `simulated` results that can never be CONFIRMED, dedupe, and schema-driven request bodies from the new parser. This is still static and unit-testable.
