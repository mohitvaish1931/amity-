# Development

## Requirements

Node.js ≥ 22.12 (`.nvmrc`: 22). Install with `npm ci`.

## Commands

| Command | What it does |
|---|---|
| `npm start` | Build, then serve `dist/` on http://127.0.0.1:8000 (`PORT` to change). |
| `npm run build` | Production bundles in `dist/`. Step 1 is ES modules with code splitting; Step 2 is one IIFE. |
| `npm run check` | typecheck → lint → unit tests → build → bundle budget. Run before every commit; CI runs the same stages. |
| `npm test` / `npm run test:watch` | Vitest (offline; jsdom harness for app tests). |
| `npm run test:e2e` | Playwright on the production build (Chrome + Edge on Windows, bundled Chromium elsewhere; `PW_CHANNELS` overrides, `E2E_SKIP_BUILD=1` reuses `dist/`). |
| `npm run check:bundle` | Bundle budget on an existing `dist/` (`scripts/check-bundle.mjs`). |
| `npm run sample:regen` | Regenerate Step 2's demo model from Step 1 (a test fails if it drifts). |

## Where things go

- **Engine code** goes in `src/`: typed, pure, and free of any particular API's vocabulary. The apps (`1-security-twin/app.js`, `2-test-lab/app.js`) are thin UIs over it.
- **Rendering**: only through `html```/`setHtml` (`src/ui/safe-html.ts`). ESLint bans `innerHTML` in the apps, and the CSP bans inline scripts and handlers, so wire events in JS.
- **Operation feedback**: use `showStatus` (`src/ui/status.ts`), not `alert()`. Give every failure a message and, when retrying makes sense, a Retry.
- **Styles**: shared tokens and components in `src/ui/theme.css`; app-specific rules in `<app>/styles.css`. Colour states (green/red/amber) only for results.
- **Browser storage**: only through `createWorkspaceStore` (`src/ui/persist.ts`), opt-in, never credentials. App tests can pre-fill storage with `loadApp(app, { beforeRun: (w) => w.localStorage.setItem(...) })`.
- **Targets**: anything that sends a request to a user-supplied URL must go through `src/target/policy.ts` (`assessTargetHost` / `registerTarget` / `resolveRequestUrl`).

## Tests

| Folder | Scope |
|---|---|
| `tests/openapi`, `tests/model`, `tests/constitution`, `tests/twin`, `tests/paths`, `tests/target`, `tests/ui` | Pure modules. |
| `tests/apps` | The real app bundles in jsdom (`scripts/app-harness.mjs`): flows, XSS, accessibility, error states, target guardrails, data-derived values. |
| `tests/ci` | The CI workflow, code splitting, bundle budget, static-server path handling. |
| `e2e` | Real browsers on the production build: Step 1 flows, Step 2 flows and guardrails, responsive layout and focus. |

Conventions:
- Expected values are computed from the libraries, never copied from the screen.
- Every bug fix gets a regression test, and for behaviour fixes a negative control (the test fails on the old code). progress.md records them.
- Tests never touch the network. The harness `fetch` serves only the app's own files, and live-mode tests stub `fetch` or abort requests with `page.route`.
- Wait for asynchronous UI with `app.waitFor(...)` or Playwright's auto-waiting, not fixed sleeps.

## Extending

- **A new law category**: add it to `LawCategory` in `src/contracts`, derive it in `src/constitution/generate.ts` with provenance and confidence signals, map it in `legacy.ts` if Step 2 should plan it, and add fixtures in `tests/constitution`. The explorer and exports pick it up automatically.
- **A new graph node or edge type**: `src/twin/graph.ts` (pure) plus a node style in `twin.css`. The E2E expectations come from `e2e/expected.ts`, so they follow automatically.
- **A new status or error path**: `showStatus` with the right kind, plus a case in `tests/apps/error-states.test.ts`.
