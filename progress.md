# Progress

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
2. Step 2 `fillPath` still fills only the first path parameter (BUG-09, step 2 part).
3. Step 2 has not adopted the typed contracts (`TestCase`, `TestResult`, `Finding`, `Evidence`). Only rendering was migrated.
4. External `$ref` (remote/file) is not supported: it produces a warning.
5. Step 1 still shows a static "🟢 Authorized Sandbox" label regardless of state (UI-only claim).
6. No backend, persistence, CI pipeline or Docker files yet.
7. Planning docs from the audit (`docs/TARGET_ARCHITECTURE.md`, `docs/FULL_IMPLEMENTATION_PLAN.md`) were not produced.

## Next suggested phase

Replace step 2's analyzer and finding logic with the typed contracts: explicit finding states, `simulated` results that can never be CONFIRMED, dedupe, and schema-driven request bodies from the new parser. This is still static and unit-testable.
