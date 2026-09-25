# Architecture

Status as of the product-hardening phase (2026-09-25). This describes what exists in the repository today.

## Layers

```
            spec text (JSON / YAML)
                     │
        src/openapi  │  loadSpecText → normalizeSpec
                     ▼
            NormalizedSpec (typed)                 errors/warnings, never throws
                     │
        src/model    │  buildApiModel
                     ▼
            ApiModel: endpoints (+ action, resource, evidence), resources
                      (fields + sensitivity, ownership, identifiers, relations)
                     │
                     │  toLegacyView  (stable shape for the existing apps)
                     ▼
   src/constitution        generateSecurityConstitution(model, config) → SecurityConstitution
                           (laws: statement + machine rule + scope + provenance + confidence + test strategy)
                           toLegacyLaws() → Step 2 contract (BOLA/ADMIN/DATA/AUTHN/ROLE/POLICY)
                     │
   1-security-twin/app.js  twin · inferences · Constitution panel · dashboard ──► testable-security-model.json
                           (export carries both `constitution` and legacy `laws`)
            │                                                                              │
            │ ApiModel + config identities/roles/ownership + laws                          │
            ▼                                                                              │
   src/twin/graph.ts       buildTwinGraph  → TwinNode[] / TwinEdge[] (pure, provenance)     │
   src/twin/layout.ts      layoutTwinGraph → positions (pure, deterministic)               │
   src/twin/lazy.ts        loads the graph code on first use (code-split chunk)              │
   src/twin/*.tsx          React Flow island mounted into #twinGraph                       │
                                                                                            │
   2-test-lab/app.js       planner + prototype executor ◄──────────────────────────────────┘
                           live requests only to a registered target (src/target/policy.ts)

   src/constitution/explore.ts  filter + JSON/Markdown export of laws (Constitution Explorer)
   src/ui/safe-html.ts     html`` / setHtml / joinHtml, used by every render function in both apps
   src/ui/status.ts        loading / success / empty / error / retry states (no alert())
   src/ui/theme.css        shared restrained theme, bundled into each app's app.css
   src/contracts           types shared by all of the above
```

## Modules

| Path | Responsibility |
|---|---|
| `src/contracts/index.ts` | All shared types: `ApiModel`, `Endpoint`, `Parameter`, `SchemaInfo`, `Field`, `AuthRequirement`, `Resource`, `ResourceField`, `Relationship`, `Identity`, `Role`, `SecurityLaw` (+ `LawRule`, `LawScope`, `Provenance`, `ConfidenceRationale`, `TestStrategy`), `SecurityConstitution`, `TestCase`, `TestResult`, `Finding` (`SUSPECTED`/`OBSERVED`/`CONFIRMED`), `Evidence`. No behaviour. |
| `src/openapi/load.ts` | Parses JSON or YAML (alias count capped), validates the root object, identifies the format (`openapi-3.0`, `openapi-3.1`, `swagger-2.0`). |
| `src/openapi/refs.ts` | Local JSON-pointer `$ref` resolution with cycle detection. External refs produce a warning. |
| `src/openapi/schema.ts` | `SchemaFlattener`: turns a schema into `Field[]` with dotted paths (`holder.email`) and `[]` for arrays (`members[].ssn`). Handles `allOf` merge, `oneOf`/`anyOf` variants (branch-only fields are tagged), nullable forms, enums/const, recursion markers, and a depth cap. |
| `src/openapi/security.ts` | Collects security schemes (OAS 3 and Swagger 2) and resolves each operation's effective `AuthRequirement` (`required` / `optional` / `public`, with source and AND/OR alternatives). |
| `src/openapi/normalize.ts` | Walks paths and operations: merges path-level and operation-level parameters, resolves `$ref` parameters/bodies/responses, converts Swagger 2 `body`/`formData` into request bodies, applies `consumes`/`produces`, synthesizes undeclared path params, and reads servers. |
| `src/model/naming.ts` | Tokenizing, singularizing, PascalCase. Generic grammar only. |
| `src/model/sensitivity.ts` | Token-based field classification (PUBLIC / PERSONAL / INTERNAL / SENSITIVE) with a reason string. |
| `src/model/resources.ts` | Action inference, resource inference from weighted evidence (schema 4, path 3, operationId 2, tag 1), and resource assembly: fields, ownership field, identifiers, relationships. |
| `src/model/legacy-view.ts` | Maps `ApiModel` to the endpoint/resource shapes the browser apps and the `testable-security-model.json` contract already use. Applies analyst sensitivity overrides. |
| `src/twin/graph.ts` | Pure transformation from model + configuration + laws (+ optional findings) to `TwinGraph`. Node types: identity, role, endpoint, resource, field, law. Edge types: `HAS_ROLE`, `OWNS`, `REQUIRES_ROLE`, `READS`, `WRITES`, `RETURNS`, `RELATES_TO`, `HAS_FIELD`, `EXPOSES`, `GOVERNS`, `VIOLATES`. Relationships between the same pair are merged into one edge, and edges to unknown entities are dropped. Every edge carries provenance. Also has `describeNode`, `describeEdge` and `lawHighlight` for the UI. |
| `src/twin/layout.ts` | Deterministic layered layout: rows by entity type, barycenter ordering to reduce crossings, wrapping of long rows, no overlaps. |
| `src/twin/SecurityTwinGraph.tsx` | React Flow view: custom node shapes per type, detail panel (metadata, relationships, relevant laws, provenance), field filter (key / all / none), law highlighting, fit view, reset layout, minimap for large graphs, and an error boundary so a graph failure never breaks the page. |
| `src/twin/lazy.ts` | `createLazyTwinView(el)`: loads `mount.tsx` (React + React Flow) with a dynamic `import()` on the first `render`/`focusLaw`, shows a loading status, replays the latest calls once loaded, and shows an error with a Retry button if the chunk fails to load. |
| `src/twin/styles.ts` | Imports the graph CSS eagerly (small), so the lazily loaded chunk needs no stylesheet of its own. |
| `src/twin/mount.tsx` | `mountSecurityTwinGraph(el)` lets the vanilla Step 1 app render the React island: `render(input)` on build/rebuild (the graph is recomputed only then), and `focusLaw(id)` highlights a law's scope and zooms to it (used by the Constitution panel). |
| `src/constitution/generate.ts` | Security Constitution engine: derives laws per category from the model and configuration, deduplicates them by key (merging provenance, scope and signals), rates confidence from evidence signals, and orders and numbers them deterministically. See docs/SECURITY_CONSTITUTION.md. |
| `src/constitution/permissions.ts` | Matches free-text permission names from the configuration to resources, operations and own/foreign qualifiers by whole tokens (a labelled heuristic). |
| `src/constitution/explore.ts` | Constitution Explorer: `filterLaws` (category, severity, confidence, text over id/statement/invariant/scope/provenance), `exportConstitutionJson` and `exportConstitutionMarkdown`. Exports are labelled specification-derived, record the filter, and escape spec-supplied text (Markdown/HTML injection). |
| `src/constitution/legacy.ts` | `toLegacyLaws`: one legacy law per legacy category for Step 2, pointing back to the constitution laws it summarizes. |
| `src/paths/index.ts` | The only path-template filler: `fillPath` (exact-name, encoded, strict by default; `onMissing: "keep"` for display), `pathParamNames`, `lastPathParam`, `MissingPathParameterError`, `InvalidPathParameterError`. Used by both apps. |
| `src/target/authorization.ts` | `TargetAuthorizationState` (`UNKNOWN` / `CONFIGURED` / `CONFIRMED`) derived from the configured URL and an optional authorization record. Step 1 renders its target label from this. |
| `src/target/policy.ts` | Sandbox target policy: `classifyHost` (loopback, private-network, reserved names such as `.test`/`.internal`, link-local, unspecified, public) on the parsed URL, `assessTargetHost`, `registerTarget` → `Target` (`environment: "sandbox"`, `authorizationStatus: "AUTHORIZED_BY_CONFIGURATION"`), `findTarget`, and `resolveRequestUrl`, which keeps every request on the target's origin and under its base path. Public, link-local (cloud metadata) and unspecified hosts cannot be registered. |
| `src/ui/status.ts` | `showStatus(el, kind, message, {details, retry})` with `role="alert"` for errors and `role="status"` otherwise; `fetchText` (HTTP errors become readable errors) and `copyText` (reports a denied clipboard instead of claiming success). |
| `src/ui/theme.css` | Shared design tokens and components (navy/charcoal surfaces, one blue accent, green/red/amber only for state, visible focus rings, reduced-motion support). |
| `src/ui/safe-html.ts` | Escape-by-default templating. Plain strings are always escaped. Only `html```-built fragments reach `innerHTML`, through `setHtml`. |
| `1-security-twin/app.js` | UI on top of the model: twin, inferences, the Constitution panel (from `src/constitution`) and the legacy law view for Step 2. Rebuilds from spec text on every change, so warnings never accumulate. |
| `2-test-lab/app.js` | UI plus the prototype planner, executor and finding logic. Live mode requires a registered target and sends requests only inside it (redirects refused). Mock runs are labelled SIMULATED everywhere, including the reasoning trail. See docs/TEST_LAB.md. |
| `scripts/build.mjs` | Bundles each app (esbuild, minified) into `dist/<app>/` with its HTML, CSS and samples. Step 1 is built as ES modules with code splitting (`chunks/`); Step 2 as one IIFE. |
| `scripts/check-bundle.mjs` | Bundle budget after a build: Step 1 entry ≤ 256 KiB, Step 2 ≤ 96 KiB, and exactly one lazily imported graph chunk. Part of `npm run check` and CI. |
| `scripts/static-path.mjs` | Maps a request URL to a file inside `dist/`: 400 for undecodable paths, 403 for anything outside the root (including prefix-sharing siblings such as `dist-old/`). |
| `scripts/serve.mjs` | Static server for `dist/` on 127.0.0.1, using `static-path.mjs`. |
| `scripts/app-harness.mjs` | Loads a real app bundle into jsdom for tests. `fetch` serves only the app's own files, and any other URL throws. |
| `scripts/e2e-server.mjs` | Builds `dist/` and serves it in one Node process: the Playwright `webServer`, so stopping it leaves no orphan. |
| `playwright.config.ts`, `e2e/` | End-to-end tests on the production build in real browsers (Chrome + Edge channels on Windows, bundled Chromium elsewhere). `e2e/expected.ts` computes the expected graph/constitution from the model libraries. The tests use stable `data-testid` attributes (`twin-graph`, `twin-node` with `data-node-id`/`data-node-type`, React Flow's `rf__edge-*`, `twin-panel`, `law-card`, `law-focus`). |
| `scripts/regen-sample.mjs` | Regenerates the step 2 demo model by running step 1 in the harness. |

## Build and runtime

- The apps are plain JavaScript ES modules that import TypeScript from `src/`. esbuild bundles them; the Step 1 page loads `app.js` as `type="module"` and fetches the graph chunk only when the Security Twin is first rendered.
- No backend exists yet. Everything runs in the browser.
- Dependencies (runtime, bundled): `yaml`, `react` + `react-dom` 19, `@xyflow/react` 12 (React Flow, used only by the Security Twin graph). Dev: TypeScript 5.9 (strict, `jsx: react-jsx`), Vitest 4, ESLint 9 + typescript-eslint, esbuild, jsdom.
- Step 1 page load: `app.js` 186 KiB + `app.css` 26 KiB. The graph chunk (React + React Flow, 413 KiB) loads on BUILD. Before code splitting the page loaded 589 KiB of JS up front. Step 2: `app.js` 49 KiB + `app.css` 7 KiB.
- Both pages carry a Content-Security-Policy: scripts only from their own origin, no inline scripts or handlers, `object-src 'none'`, `base-uri 'none'`.
- The test harness gives jsdom the layout APIs React Flow needs (`ResizeObserver`, `DOMMatrixReadOnly`, element sizes), so graph tests render real nodes and edges. It bundles without splitting, so the dynamic import is inlined there.

## Design rules

1. Parser and model code are pure functions over plain data and never throw on user input. Failures become `errors` or `warnings`.
2. No domain vocabulary in the engine. Inference uses HTTP/REST structure and generic grammar, and records its evidence (`resourceEvidence`, `sensitivityReason`).
3. One source of types (`src/contracts`). Apps consume the model through `toLegacyView`, so the export contract stays stable.
4. Rendering never concatenates untrusted strings into HTML. ESLint forbids `innerHTML`/`outerHTML`/`insertAdjacentHTML` in the apps, and tests check it too.
