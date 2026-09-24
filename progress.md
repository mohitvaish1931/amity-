# Progress

## 2026-09-24: CI runs Playwright E2E (committed, not pushed; not yet run on GitHub)

Scope: CI and browser QA only.

| Item | Detail |
|---|---|
| Workflow | After **Build**: `Install Playwright Chromium` (`npx playwright install --with-deps chromium`), then `E2E (Playwright)` (`npm run test:e2e` with `PW_CHANNELS=chromium`, `E2E_SKIP_BUILD=1`), then `Upload Playwright report` (HTML report + traces, **only when E2E fails**). The test-report artifact now also carries `reports/e2e-junit.xml`. The summary table has an E2E row. The timeout rose from 15 to 25 minutes. |
| No duplicate build | `scripts/e2e-server.mjs` honours `E2E_SKIP_BUILD=1`: it reuses the `dist/` from the Build step, or exits 1 with a clear message if there is none (verified). |
| Browser | Playwright's own Chromium on the runner, so no preinstalled Chrome or Edge is needed. Locally on Windows, still installed Chrome + Edge. |
| Failure handling | The E2E step failing fails the job. Playwright config in CI adds `html` and `junit` reporters. `reuseExistingServer: false`. The server is a single process that Playwright stops. |
| Invariant tests | `tests/ci/workflow.test.ts` +2: build → Chromium install → E2E order and gating, E2E env (skip build, chromium), failure-only report upload, CI reporters, gitignored report folders, E2E summary row. |

### Also fixed: flaky jsdom test that made the previous CI run red

- CI run 36036528693 (`a244f83`) failed on `constitution-panel.test.ts` "highlights a law's scope…". The test waited a fixed 30 ms for a highlight that arrives after an asynchronous React render. The GitHub runner was slower.
- Fix, test code only: the harness gained `waitFor(predicate)` polling. The constitution-panel test and the twin-graph law-filter test now wait for the highlight to render instead of sleeping. No app code changed.
- Verification: the full unit suite passed 263/263 three runs in a row.

### Local results

- `npm run check`: typecheck ✅ lint ✅ **263/263** ✅ build ✅
- `npm run test:e2e` (builds itself): **8/8** ✅
- `CI=1 E2E_SKIP_BUILD=1 npm run test:e2e` (CI mode, reusing `dist/`): **8/8** ✅; wrote `reports/e2e-junit.xml` and `playwright-report/index.html`
- Port 4178 was free after every run.
- Workflow YAML parses; its invariants are tested. `actionlint` was not run (it would need a binary download).

### Limitations

- **Not verified on GitHub yet.** The Chromium-channel run (`PW_CHANNELS=chromium`) has not been executed anywhere yet. Locally only Chrome/Edge channels ran, because installing Playwright's Chromium means a browser download.
- No cache for Playwright browsers in CI, so each run downloads Chromium and its system dependencies. That's simpler, but slower.
- E2E still covers Step 1 only, on Chromium only.

## 2026-09-24: Phase: Playwright end-to-end tests ✅

Scope: browser QA of the existing Step 1 frontend. No security testing, scanning or target interaction.

| Item | Detail |
|---|---|
| Playwright | `@playwright/test` 1.63.0 (pinned). `npm run test:e2e`. |
| Browsers | Installed **Google Chrome 153.0.8010.53** and **Microsoft Edge 153.0.4234.48** via Playwright's `chrome`/`msedge` channels (no Playwright browser download). Bundled Chromium on non-Windows platforms; override with `PW_CHANNELS`. |
| Server | `scripts/e2e-server.mjs` builds `dist/` and serves it on 127.0.0.1:4178 in one Node process. `reuseExistingServer: false`, so the tests never depend on a dev server. After each run, port 4178 is free and no e2e/server node process remains (checked). |
| Tests (`e2e/step1.spec.ts`, 4 × 2 browsers = 8) | **Demo flow:** load demo, build, then check the graph appears. Node count, per-type counts and edge count must equal the model-derived values. Click a resource node, then check the panel heading and relationship count. Open its object-authorization law and check its statement, invariant, confidence and every provenance ref. Highlight its scope and check the highlighted node ids equal `lawHighlight()`, every other node is dimmed, and the card is focused. Finally, no console or page errors, and only local app assets requested. **Empty model:** empty state before a build; a spec without operations gives 0 endpoints and 0 laws. **Non-demo:** the marketplace fixture's graph and laws are model-derived, with no demo terms. **Invalid:** `Invalid spec: Invalid JSON…` alert, and no graph. |
| Expected values | `e2e/expected.ts` computes the graph and constitution from the model libraries in Node, so no counts are hardcoded. |
| Test ids added | `twin-graph`, `twin-node` (+ `data-node-type`), `law-card`, `law-focus`. `twin-panel` and React Flow's `rf__edge-*` already existed. No behaviour change. |
| Favicon | Both apps declare `<link rel="icon" href="data:,">`. Without it the browser requested `/favicon.ico`, a 404 that shows up as a console error. |

### Results

- `npm test` 261/261 ✅ · `npm run typecheck` ✅ · `npm run lint` ✅ · `npm run build` ✅ · `npm run test:e2e` **8/8** ✅ (0 flaky)
- Fixed while writing the tests: the invalid-model test deadlocked because the `alert()` dialog handler was registered after the click (test code, not app code).

### Limitations

- E2E is not part of `npm run check` or GitHub Actions yet. CI would need `npx playwright install --with-deps chromium`.
- Only Step 1 is covered end to end. Step 2 is still covered by the jsdom app tests only.
- Chromium-based browsers only (Chrome, Edge). Firefox and WebKit are not run, as they would require Playwright browser downloads.
- Pointer drag, zoom and pan of the graph are not asserted (clicks and highlighting are).

## 2026-09-24: Phase: Security Constitution engine ✅

Scope: static, model-level security reasoning only. No runtime testing, requests or scanning. Details in [docs/SECURITY_CONSTITUTION.md](docs/SECURITY_CONSTITUTION.md).

### Done (verified by running it)

| Item | Evidence |
|---|---|
| Contracts: `LawCategory` (6 categories), `LawRule` (typed machine rules), `LawScope` (+identities), `Provenance`, `ConfidenceRationale`, `TestStrategy` (`executable: false`), `SecurityConstitution`; `Role.privilegeEvidence` | `src/contracts` |
| `generateSecurityConstitution(model, config)`: pure and deterministic, with per-category derivation, key-based dedup (merges provenance, scope and signals), confidence rules over evidence signals, deterministic ids | `tests/constitution/constitution.test.ts` (38 tests, all 12 required areas plus demo and legacy) |
| Permission name matching (resource, operation, own/foreign qualifier), labelled as a heuristic | same suite |
| Step 2 compatibility: `toLegacyLaws` gives one legacy law per legacy category, in historical order | Demo still plans **22** cases; sample drift test green |
| Step 1: ad-hoc `buildLaws` removed; the Constitution panel shows id, category, severity, confidence, statement, machine rule, scope, provenance, confidence signals and test strategy; "Highlight scope in graph" drives the Security Twin | `tests/apps/constitution-panel.test.ts` (5 tests); manual check of the production build |
| Graph uses constitution laws (statement, provenance, confidence score; GOVERNS edges to identities too); external `focusLaw` | graph + app tests updated |
| Export carries both `constitution` and legacy `laws` | constitution-panel test |
| `npm run check` | typecheck ✅ lint ✅ **261/261** ✅ build ✅ |

Demo result: 7 laws.
- **HIGH:** Order ownership, the admin refund restriction, bearer authentication.
- **MEDIUM:** Invoice and Order data exposure.
- **LOW:** User object access (no ownership field), User data exposure (PERSONAL only, no ownership).

### Quality review (hostile pass), with fixes

| Severity | Issue found | Fix |
|---|---|---|
| P1 | The User object law claimed `ownership:config` provenance and the Order owners, though User has no ownership field (the audit's BUG-08 pattern, fabricated provenance) | The ownership map now applies only to resources with an ownership field. Mutation test confirms the test catches a regression. |
| P1 | The state-transition law counted `POST /stores/{id}/listings` (create a child) as a Listing transition | A transition endpoint must address the same resource by id. Mutation test confirms the test catches a regression. |
| P1 | Invoice data exposure said "entitlement undefined" although Invoice is only reachable through `/orders/{id}` | Inherited entitlement, with `relationship:Invoice→Order` provenance and `rule.inheritedFrom` |
| P1 | Merging deny permissions from several roles kept only the first role in the statement | Denies are grouped before the law is built |
| P2 | Admin law provenance omitted the denied roles; "X accept…" grammar | Fixed |
| n/a | Scan for demo vocabulary in `src/constitution`: only in comments | — |
| n/a | Network check of the production build: only the 6 local requests (page, CSS, bundle, 2 demo samples); no console errors | — |

### Limitations

- Permission-to-endpoint matching is a name heuristic, so those laws are capped at MEDIUM.
- The ownership map is not typed by resource. It is applied only to owned resources, with an ambiguity note when several exist.
- Sensitivity is a name heuristic unless an analyst overrides it, so data-exposure laws only reach HIGH with an override.
- Allowed state transitions are not expressible in OpenAPI, so state-transition laws are at most MEDIUM.
- Test strategies are specifications and are not executed.
- The Step 1 bundle grew to 586 KiB (constitution engine + panel).

## 2026-09-24: CI green on GitHub ✅

Run [36009994438](https://github.com/mohitvaish1931/amity-/actions/runs/36009994438) on `99775ec` passed every step (npm ci, typecheck, lint, test, build) after the esbuild fix described below.

## 2026-09-24: CI foundation ✅ (first GitHub run failed; fix verified locally, awaiting a new run)

Scope: CI and dev tooling only. No application behaviour changed.

| Item | Detail |
|---|---|
| `.github/workflows/ci.yml` | On `push` and `pull_request`: checkout → setup Node (from `.nvmrc`, npm cache) → `npm ci` → typecheck → lint → `npm run test:ci` → build. Checks run whenever install succeeded, so every stage reports; any failure fails the job. JUnit report uploaded as `test-report`; stage table written to the run summary. `permissions: contents: read`, `persist-credentials: false`, concurrency cancels superseded runs, 15-minute timeout. |
| Action pinning | `actions/checkout`, `actions/setup-node` and `actions/upload-artifact` are pinned to the commit SHAs of their `v7` tags (resolved with `git ls-remote` on 2026-09-24). |
| Node version | `.nvmrc` = `22`; `engines.node` = `>=22.12.0`. That's the lowest version all dependencies support (Vite needs `^20.19 \|\| >=22.12`), and Node 20 is past end-of-life. |
| Scripts | `check` = `typecheck && lint && test && build` (unchanged). New `test:ci` = the same `vitest run`, plus GitHub annotations and a JUnit file in `reports/` (gitignored). |
| `.gitattributes` | `* text=auto eol=lf`, CRLF only for `.bat`/`.cmd`/`.ps1`, explicit `binary` for images, fonts, archives and PDFs. `git add --renormalize .` changed no existing files (all 81 were already LF in the index). |
| `tests/ci/workflow.test.ts` | 9 tests that keep the workflow honest: triggers, read-only permissions, `npm ci` only, stage order and gating, SHA pinning, no secrets, Node version consistency, report + summary, and `check` composition. |

### Verified locally

- `npm ci` (clean install from the lockfile; 0 vulnerabilities) then `npm run check`: typecheck ✅ lint ✅ **218/218** tests ✅ build ✅
- `npm run test:ci`: 218/218, `reports/junit.xml` written and ignored by git.
- A throwaway failing test under `GITHUB_ACTIONS=true` produced a `::error file=…,line=…` annotation and exit code 1. The file was deleted afterwards.

### First GitHub run: failed at `npm ci`, then fixed

- Run [36008148009](https://github.com/mohitvaish1931/amity-/actions/runs/36008148009) on `38b3a29`: checkout ✅, setup Node ✅, **`npm ci` ❌**, all checks skipped.
- Cause, reproduced locally with a fresh clone and `npx npm@10 ci`: `Missing: @esbuild/*@0.28.2 from lock file`.
  - Vite 8 (under Vitest) has an optional peer `esbuild ^0.27 || ^0.28`, and the direct dependency was `esbuild 0.25.12`.
  - The lockfile was written by npm 11, which leaves the unmet optional peer alone. GitHub's Node 22 bundles **npm 10**, which requires a matching esbuild entry and aborts.
- Fix: direct `esbuild` upgraded to **0.28.2**. It satisfies Vite's peer, so only one esbuild version is left in the tree.
  - Verified on a copy of the working tree: `npx npm@10 ci` ✅ then `npm run check` ✅ (218/218). Locally, `npm ci` (npm 11) ✅ then `npm run check` ✅.
- The workflow now prints `node`/`npm` versions before install, so version-related failures are visible in the log.
- `actionlint` was not run: installing it means downloading a binary, which I avoided.

## 2026-09-24: Sandbox policy messaging aligned ✅

- Step 2's banner no longer says "🟢 AUTHORIZED SANDBOX ONLY". It now reads `🛡 POLICY: test only sandbox targets you are authorized to test · production testing is prohibited`, matching Step 1. Both apps state the policy and neither claims that authorization has been verified. No authorization-confirmed state was added.
- Regression tests (`tests/apps/foundation-blockers.test.ts`, "Step 2 sandbox policy messaging"): the rendered page, before and after planning, and the page source contain no authorization claim. Both tests fail against the old banner.
- `npm test` 209/209 ✅ · typecheck ✅ · lint ✅ · build ✅

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
5. ~~Step 1 still shows a static "🟢 Authorized Sandbox" label regardless of state.~~ Fixed in "Small foundation blockers"; Step 2's banner aligned in "Sandbox policy messaging aligned". (Step 2's live-run approval checkbox is separate and unchanged.)
5a. No end-to-end browser automation (Playwright) yet; graph pointer interactions were verified manually.
6. No backend, persistence or Docker files yet. (CI workflow added in "CI foundation"; not yet run on GitHub.)
7. Planning docs from the audit (`docs/TARGET_ARCHITECTURE.md`, `docs/FULL_IMPLEMENTATION_PLAN.md`) were not produced.

## Next suggested phase

Replace step 2's analyzer and finding logic with the typed contracts: explicit finding states, `simulated` results that can never be CONFIRMED, dedupe, and schema-driven request bodies from the new parser. This is still static and unit-testable.
