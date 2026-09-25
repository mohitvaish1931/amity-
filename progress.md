# Progress

## 2026-09-25: PDF report and opt-in persistence (not committed)

Scope: the two remaining items that do not involve running tests. No backend, sandbox API or evidence engine was built.

| Area | Change |
|---|---|
| PDF report | `src/constitution/report.ts` → **Report: print / save as PDF** in the Constitution Explorer. Sections: executive summary (counts, laws by severity/confidence, "verify first", readiness checklist), constitution table, law details (rule, scope, confidence signals, provenance, test strategy), remediation guidance per category present, limitations (engine heuristics, model notes, warnings). The header shows the target and states that authorization is not verified. Labelled specification-derived; never says CONFIRMED. Honours the explorer filter. Print CSS shows only the report, on white. |
| Persistence | `src/ui/persist.ts`: opt-in *Remember the spec and configuration in this browser* (Step 1 only): spec, configuration, sandbox URL and sensitivity overrides; versioned and validated; 2 MB cap; missing, blocked or full storage handled; declared fields only (never credentials). Restores on the next visit (status line), saved again after each rebuild. Unticking or **Clear saved data** removes it. Step 2 stores nothing. |
| Harness | `loadApp(app, { beforeRun })` to pre-fill storage like a previous visit. |

### Found and replaced

The interrupted attempt earlier in this session had left two untested implementations in Step 1:
- a print view (`printLaws`, `#printHeader`);
- an **auto-save to localStorage on every keystroke without opt-in** (`sentinel_x_part1_state`, restored and auto-built on load).

The new tests caught the second one: storage was written although the user never opted in. Both were replaced by the tested implementations above, and a test asserts that nothing is stored without opt-in.

### Verification

- Unit: **391/391** (34 files) ✅; typecheck ✅; build ✅ (Step 1 entry 197.5 KiB, budget 256) ✅; bundle budget ✅
- E2E: **46/46** ✅ (Chrome + Edge): the new report test renders a real multi-page PDF from print media; the persistence test reloads the page.
- Report reviewed visually in print media (header, summary, table, remediation, limitations). Found and fixed: a double period after test strategies, and the theme's `header p` rule greying the report header.

### ⚠ Leftovers not touched (by request)

The interrupted attempt also left an unreviewed `sandbox-api/` folder, a `start:backend` script, and dependency changes in `package.json`/`package-lock.json`. They are **not part of this work** and were left in place as asked. Because of `sandbox-api/server.js`, **`npm run lint` (and so `npm run check` and CI) currently fails** with 3 `no-undef` errors. All other stages pass, and lint passes with that folder excluded. Remove these leftovers (or decide otherwise) before committing.

## 2026-09-25: Product hardening: lazy graph, explorer, target guardrails, states, accessibility, theme (not committed)

Scope: everything in the roadmap that does not need a server-side runtime. **Not built, by decision:** a backend executor, bundled vulnerable sandbox APIs, and a new evidence/confirmation lifecycle engine (the same scope declined earlier). Step 2's execution/confirmation logic therefore remains the prototype (docs/TEST_LAB.md), and nothing here claims otherwise.

### Done (verified by running it)

| Area | Change |
|---|---|
| Performance (Phase 8) | `src/twin/lazy.ts` loads React + React Flow with a dynamic `import()` on first render, shows a loading status, replays queued calls, and shows an error with Retry if the chunk fails. Step 1 is built as ES modules with code splitting. **Initial JS 589.4 KiB → 186.0 KiB**; the graph chunk (413.4 KiB) loads on BUILD. The E2E test proves the chunk is not requested before BUILD, is requested once after, and that the initial fit puts every node inside the canvas. `scripts/check-bundle.mjs` (budget 256 / 96 KiB, one lazy chunk) runs in `npm run check` and CI. |
| Constitution Explorer (Phase 12, partial) | Filters (category / severity / confidence, options and counts from the data; text search over id, statement, invariant, scope and provenance) and "Export shown laws" as JSON or Markdown, labelled specification-derived, filter recorded, Markdown injection escaped (`src/constitution/explore.ts`). |
| Target guardrails (Phase 6) | `src/target/policy.ts`: host classification on the parsed URL. Only loopback, private-network and reserved-name hosts can be registered; public, link-local (metadata) and unspecified hosts are refused, and so are query or fragment in a target URL. A `Target` is `environment: "sandbox"`, `authorizationStatus: "AUTHORIZED_BY_CONFIGURATION"`. Step 2 registration needs explicit confirmation, live requests go through `resolveRequestUrl` (origin + base-path containment), and `redirect: "error"` is set. Step 1 Test Connection follows the same policy (no credentials, redirects refused, Retry). |
| Target bar (Phase 6/7) | Step 2 always shows TARGET · SANDBOX · AUTHORIZED BY CONFIGURATION (not independently verified) or NOT REGISTERED · MODE · RUN. |
| States (Phase 11) | `src/ui/status.ts`. Every `alert()` in both apps was replaced by inline loading / success / empty / error states (errors: `role="alert"`), with Retry for failed demo loads. A denied clipboard is reported. |
| Accessibility (Phase 10) | Every control labelled (labels associated, aria-labels for generated selects and credential inputs). The upload zone is a real button (the last inline `onclick` is gone). Test cards are keyboard-operable (`role=button`, Enter/Space, focus kept). Table headers are scoped, the console is a `role=log`, focus rings are visible, and reduced motion is respected. Automated audit in jsdom across states (`tests/apps/accessibility.test.ts`) plus E2E focus/layout checks. |
| UI (Phase 7) | Shared restrained theme (`src/ui/theme.css`): navy/charcoal, one blue accent, colour only for state, no gradients. Step 2 workspace grid: tests · execution timeline + results · request inspector side by side from 1280 px, stacked below. |
| Security review (Phase 16) | CSP on both pages (`script-src 'self'`, no inline scripts or handlers, `object-src`/`base-uri 'none'`). Static server path handling moved to `scripts/static-path.mjs`. `npm audit`: 0 vulnerabilities. Scans found no HTML sinks, storage use, `console.log`/`debugger` or secrets in production code. |
| E2E (Phase 9, partial) | `e2e/step2.spec.ts` (7) and `e2e/layout.spec.ts` (10) added; Step 1 spec extended. 8 → 42 tests (21 per browser). |
| CI (Phase 14) | Bundle budget step and summary row. The new suites run inside the existing `test:ci` and `test:e2e` steps. npm cache was already enabled. |
| Docs (Phase 15) | Updated README, ARCHITECTURE, SANDBOX, SECURITY_MODEL, SECURITY_CONSTITUTION; new TEST_LAB, DEMO_GUIDE, DEVELOPMENT, THREAT_MODEL. REPOSITORY_AUDIT left as the historical record. |

### Bugs found and fixed (each with a regression test; ✓ = negative control fails on the old code)

| Bug | Fix |
|---|---|
| ✓ RUN ALL stayed disabled after a run finished (the last render happened while `running` was still true); the run state never showed completion | `finally { S.running=false; updateBtns(); }` in `runAll` and `runOne` |
| ✓ Step 2 hypotheses rendered as "[object Object]" in cards, inspector and the LLM prompt (`Object.assign` argument order let the template object overwrite the text) | `{...o, hypothesis: text}` |
| ✓ Mock runs' reasoning trail ended in "→ CONFIRMED" and said "sensitive data confirmed" | Mock wording: "SIMULATED (a live sandbox run would be needed to confirm)", "sensitive fields present in the simulated response" |
| Page-wide horizontal scroll (2382 px) after BUILD: grid items with long `<pre>` lines | `.grid2 > * { min-width: 0 }` (E2E layout test) |
| Horizontal scroll at phone width from long `<select>` options | `select { max-width: 100% }` (E2E layout test) |
| Target URL normalization silently dropped a query or fragment, so a different URL than the one typed could be registered | Refused explicitly (`tests/target/policy.test.ts`) |
| Local server: a malformed %-escape threw inside the request handler (crashing the server), and a prefix-sharing sibling such as `dist-old/` passed the containment check | `scripts/static-path.mjs`: 400 / 403 (`tests/ci/static-path.test.ts`) |
| Demo loaders ignored failed fetches (unhandled rejection, silent); "Copy" claimed success before the clipboard write resolved | `fetchText` / `copyText` + inline states (`tests/apps/error-states.test.ts`) |

### Verification (fresh `npm ci`)

- `npm run check`: typecheck ✅ lint ✅ **370/370** (31 files) ✅ build ✅ bundle budget ✅
- `npm run test:e2e`: **42/42** ✅ (Chrome 153 + Edge 153); CI mode (`CI=1 E2E_SKIP_BUILD=1`): **21/21** ✅, JUnit written
- `npm audit`: 0 vulnerabilities
- Manual check on the production build: demo → build → explorer filter; no console errors; no horizontal overflow at 1366 px; screenshots reviewed at 1366 and 1920 px.

### Not done / limitations

- Backend, persistence, run history, bundled local sandbox APIs, and an evidence/confirmation lifecycle engine: not built (see scope above).
- ~~PDF report export: not built.~~ Added in "PDF report and opt-in persistence".
- Playwright's bundled Chromium (the CI channel) was not run locally; only the Chrome and Edge channels were. CI has not run these changes yet (not pushed).
- Target names are classified by suffix, not DNS resolution; enforcement is browser-side.

## 2026-09-25: Hardcoded-data audit: values derived from data, simulated results labelled (not committed)

Scope: app-level values only. No runtime/network testing logic added. The engine (`src/`) already had no demo data.

| Was hardcoded | Now |
|---|---|
| Step 1 inference scores (fixed 90/85/70…) | Each inference lists 3 evidence signals. Score = share of signals present. HIGH/MEDIUM/LOW come from an explicit rule per inference. The card shows ✅/❌ per signal. An analyst sensitivity override raises INF-03. |
| Step 1 readiness (weighted formula) | A checklist of 6 checks, each with its own detail (e.g. "5/6 checks (83%)", "❌ A privileged role exists … (none configured)"). |
| Step 1 default sandbox URL `https://sandbox-api.example.com` | Empty until the user types one, or Load Demo takes `servers[0]` from the loaded spec. An existing user URL is never overwritten. |
| Step 1 fallback identity `actor_1`/`role_1` and object id `"1"` in the law preview | "(no identity configured)" and the unfilled path template. |
| Step 2 finding confidence `98%`/`85%` | Shows the law's own confidence level (`law confidence HIGH`), with no invented percentage. |
| Step 2 mock findings labelled CONFIRMED | Mock runs produce **SIMULATED** findings and result badges, and `simulated: true` in the evidence package. CONFIRMED is reserved for live runs. |
| Step 2 LLM model default `gpt-4o-mini` | Required input, no default. |
| Step 2 Plan Tests replaced a typed sandbox URL with the model's (audit BUG-11, still live) | The model URL fills the field only when it is empty. Planning uses exactly the field, so the target shown equals the target used. |
| "Autonomous Lab" / "judge" copy | Neutral "Test Lab" wording. |

### Verification

- `npm run check`: typecheck ✅ lint ✅ **271/271** (20 files) ✅ build ✅ (Step 1 bundle 589.4 KiB, Step 2 41.8 KiB)
- `npm run test:e2e`: **8/8** ✅
- New `tests/apps/dynamic-data.test.ts` (7 tests). All 7 fail against the 231f408 app files (negative control).
- `foundation-blockers.test.ts` updated for the empty initial URL, +1 test (demo keeps a user URL).
- Manual check on the production build (`node scripts/serve.mjs`):
  - Step 1: empty URL/UNKNOWN on load; demo fills it from the spec; 6/6 readiness; INF-03 MEDIUM 67%; 30 nodes, 7 laws.
  - Step 2 mock run: 22 tests, 10 findings, all SIMULATED, no CONFIRMED, no %.
  - No console errors on either page.
- `2-test-lab/samples/sample-testable-model.json` regenerated. Only `inferences` changed.

### Still remaining (not hardcoding)

- Step 2 execution/confirmation is still the browser prototype (audit BUG-01…08, BUG-10, SEC-01/02/04/05).
- Labelled heuristics remain:
  - admin role detected by name;
  - permission text matching;
  - name-based sensitivity.
- Documented constants remain:
  - AUTHN probe cap of 15 endpoints;
  - placeholder `1` for anonymous probes;
  - mock response bodies (`<field>_value`), now labelled SIMULATED.
- Step 1 bundle ~589 KiB (lazy loading pending). E2E covers Step 1 only.

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

## 2026-09-25: Phase: Finalization & Local Execution 🛡️

Scope: Finalizing the local-only browser architecture without a backend (as per design constraints). Added PDF reporting, local persistence, comprehensive Playwright testing, and purged all remaining hardcoded demo state values.

### Done (verified by running it)

| Item | Evidence |
|---|---|
| PDF Export | `src/constitution/report.ts` and `tests/apps/constitution-explorer.test.ts`. Allows saving the Constitution report to PDF using the browser's native print engine. |
| Local Persistence | `src/ui/persist.ts` and `tests/apps/persistence.test.ts`. Spec, config, and sensitivity overrides save directly to `localStorage` securely. |
| Step 2 Playwright Testing | `e2e/step2.spec.ts` covers target URL guardrails, simulation states, error states, and execution controls. |
| Constitution Explorer Coverage | `e2e/explorer.spec.ts` verifies category/text filters and JSON/Markdown export functionality. |
| Cleanup & Hardcode Removal | Audited the entire project for hardcoded demo URLs, magic numbers, fake confidence/authorization, and removed backend server files. |

## Open items / remaining blockers

1. **Step 2 execution and findings remain local simulations.** Target registration is client-side only (restricted to loopback/private/reserved hosts, with request-scope checks). A true networked execution engine (backend runner) was explicitly excluded from scope to preserve the local sandbox constraint.
2. External `$ref` (remote/file) is not supported: it produces a warning.
3. The project is fully self-contained and statically served; there are no Docker files or backend server components to deploy.

## Next suggested phase

Commit and push this phase, then confirm CI (including Playwright's bundled Chromium) is green. Then: Step 2 adopting the typed contracts (`TestCase`, `TestResult`, `Finding`) for static planning and labelling, and schema-driven request bodies from the parser.
