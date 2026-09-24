# Architecture

Status as of the foundation-hardening phase (2026-09-24). This describes what exists in the repository today.

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
   1-security-twin/app.js  twin · inferences · laws (+ appliesTo scope) · dashboard ──► testable-security-model.json
            │                                                                              │
            │ ApiModel + config identities/roles/ownership + laws                          │
            ▼                                                                              │
   src/twin/graph.ts       buildTwinGraph  → TwinNode[] / TwinEdge[] (pure, provenance)     │
   src/twin/layout.ts      layoutTwinGraph → positions (pure, deterministic)               │
   src/twin/*.tsx          React Flow island mounted into #twinGraph                       │
                                                                                            │
   2-test-lab/app.js       planner (unchanged prototype logic) ◄───────────────────────────┘

   src/ui/safe-html.ts     html`` / setHtml / joinHtml, used by every render function in both apps
   src/contracts           types shared by all of the above
```

## Modules

| Path | Responsibility |
|---|---|
| `src/contracts/index.ts` | All shared types: `ApiModel`, `Endpoint`, `Parameter`, `SchemaInfo`, `Field`, `AuthRequirement`, `Resource`, `ResourceField`, `Relationship`, `Identity`, `Role`, `SecurityLaw`, `TestCase`, `TestResult`, `Finding` (`SUSPECTED`/`OBSERVED`/`CONFIRMED`), `Evidence`. No behaviour. |
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
| `src/twin/mount.tsx` | `mountSecurityTwinGraph(el)` lets the vanilla Step 1 app render the React island. The graph is recomputed only when the app passes a new model (on build/rebuild). |
| `src/ui/safe-html.ts` | Escape-by-default templating. Plain strings are always escaped. Only `html```-built fragments reach `innerHTML`, through `setHtml`. |
| `1-security-twin/app.js` | UI plus twin, inference and law builders on top of the model. Rebuilds from spec text on every change, so warnings never accumulate. |
| `2-test-lab/app.js` | UI plus the prototype planner, executor and finding logic. Only rendering was changed in this phase. |
| `scripts/build.mjs` | Bundles each app (esbuild, IIFE, minified) into `dist/<app>/` with its HTML, CSS and samples. |
| `scripts/serve.mjs` | Static server for `dist/` on 127.0.0.1 with path-traversal protection. |
| `scripts/app-harness.mjs` | Loads a real app bundle into jsdom for tests. `fetch` serves only the app's own files, and any other URL throws. |
| `scripts/regen-sample.mjs` | Regenerates the step 2 demo model by running step 1 in the harness. |

## Build and runtime

- The apps are plain JavaScript ES modules that import TypeScript from `src/`. esbuild bundles each one into a single script.
- No backend exists yet. Everything runs in the browser.
- Dependencies (runtime, bundled): `yaml`, `react` + `react-dom` 19, `@xyflow/react` 12 (React Flow, used only by the Security Twin graph). Dev: TypeScript 5.9 (strict, `jsx: react-jsx`), Vitest 4, ESLint 9 + typescript-eslint, esbuild, jsdom.
- Step 1's bundle includes React and React Flow (about 556 KiB minified JS plus 20 KiB CSS). CSS imported from `src/` is emitted as `dist/1-security-twin/app.css`.
- The test harness gives jsdom the layout APIs React Flow needs (`ResizeObserver`, `DOMMatrixReadOnly`, element sizes), so graph tests render real nodes and edges.

## Design rules

1. Parser and model code are pure functions over plain data and never throw on user input. Failures become `errors` or `warnings`.
2. No domain vocabulary in the engine. Inference uses HTTP/REST structure and generic grammar, and records its evidence (`resourceEvidence`, `sensitivityReason`).
3. One source of types (`src/contracts`). Apps consume the model through `toLegacyView`, so the export contract stays stable.
4. Rendering never concatenates untrusted strings into HTML. ESLint forbids `innerHTML`/`outerHTML`/`insertAdjacentHTML` in the apps, and tests check it too.
