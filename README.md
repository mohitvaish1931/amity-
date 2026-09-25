# Sentinel X

OpenAPI security modelling for **authorized sandbox APIs only**. Step 1 turns an OpenAPI/Swagger spec plus a small config (users, roles, ownership) into an API model, a Security Twin and a set of security laws. Step 2 plans authorization test cases from that model.

> Pipeline: **OpenAPI → API model → Security Twin → Security Constitution → test specification** (static), then Step 2's planner and a prototype executor: mock runs labelled SIMULATED, and live runs only against a sandbox target you register on this machine or a private network. See [progress.md](progress.md) for exactly what is and is not implemented, and [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md) for a deterministic, offline demo.

## Folder structure

```
amity/
├── README.md
├── package.json, tsconfig.json, eslint.config.js, vitest.config.ts, .nvmrc, .gitattributes
├── .github/workflows/ci.yml    CI: `npm run check` pipeline + Playwright E2E
│
├── src/                        typed, tested core (shared by both apps)
│   ├── contracts/              shared types: ApiModel, Endpoint, Resource, SecurityLaw, Finding, Evidence…
│   ├── openapi/                parser: JSON/YAML → normalized spec ($ref, composition, security semantics)
│   ├── model/                  security model: resources, actions, field sensitivity, ownership
│   ├── twin/                   Security Twin graph: pure transform + layout, React Flow view (lazy-loaded)
│   ├── constitution/           Security Constitution engine + Explorer (filter, JSON/Markdown export)
│   ├── paths/                  fillPath: the single path-template filler (strict, encoded)
│   ├── target/                 authorization state + sandbox target policy (registration, request scope)
│   └── ui/                     safe-html templating, operation status states, shared theme
│
├── 1-security-twin/            STEP 1 browser app: spec → twin → constitution → testable model
│   ├── index.html, app.js, styles.css
│   └── samples/                demo spec + demo config
│
├── 2-test-lab/                 STEP 2 browser app: testable model → planned test cases → mock/live runs
│   ├── index.html, app.js, styles.css
│   └── samples/                demo model (generated from step 1)
│
├── scripts/                    build, bundle budget, local server, jsdom harness, sample regeneration
├── tests/                      Vitest suites + OpenAPI fixtures (A–M)
├── e2e/                        Playwright end-to-end tests (real browsers, production build)
└── docs/                       architecture, security model, sandbox policy, audit
```

## Install

Requires Node.js 22.12 or newer (see `.nvmrc`).

```bash
npm ci
```

## Run

```bash
npm start
```

This builds both apps into `dist/` and serves them at http://127.0.0.1:8000/:

- Step 1: http://127.0.0.1:8000/1-security-twin/ → **Load Demo Swagger + Config**, then **BUILD SECURITY TWIN**, then download `testable-security-model.json`. **Report: print / save as PDF** produces the Security Constitution report; *Remember…* keeps your inputs in this browser (opt-in).
- Step 2: http://127.0.0.1:8000/2-test-lab/ → **Load Demo Model** (or paste the JSON from step 1), then **PLAN TESTS**, then **RUN ALL** (Mock mode: results are SIMULATED).

The apps import TypeScript from `src/`, so they must be built. Opening the source `index.html` directly no longer works.

## Test, typecheck, lint, build

```bash
npm test            # Vitest: parser, model, XSS regression, app-level tests
npm run typecheck   # tsc --noEmit (strict)
npm run lint        # ESLint (bans innerHTML in the apps)
npm run build       # production bundles in dist/
npm run check       # typecheck → lint → test → build → bundle budget
npm run check:bundle  # bundle budget on an existing dist/
npm run test:e2e    # Playwright end-to-end tests (builds + serves dist/ itself)
```

### End-to-end browser tests (Playwright)

```bash
npm run test:e2e
```

This builds the production bundles and serves `dist/` on `127.0.0.1:4178` (`scripts/e2e-server.mjs`, a single Node process that Playwright starts and stops), then drives both apps in real browsers (23 tests per browser):
- Step 1: the demo flow (build the twin with the graph lazy-loaded only on BUILD and fitted into view, click a resource node, open a law, highlight its scope), plus empty, non-demo and invalid models;
- Step 2: plan, keyboard selection, a mock run labelled SIMULATED, refused targets (public host, metadata IP, invalid URL), a live run blocked for an unregistered URL, and a live run against a registered loopback target whose requests are aborted in the browser (shown as ERROR, no findings);
- layout: no horizontal scroll at 390, 1280, 1366 and 1920 px wide, visible keyboard focus, the three-column Step 2 workspace on wide screens;
- report: print media shows only the report and the browser renders a multi-page PDF; persistence: remembered inputs survive a reload and Clear saved data forgets them.

Expected node, edge and highlight counts are computed from the model libraries, never hardcoded. The tests assert there are no console errors (including CSP violations) and that only the app's own local assets are requested.

- Windows: runs on the installed **Google Chrome** and **Microsoft Edge** (`chrome` and `msedge` channels), so no Playwright browser download is needed.
- Other platforms: uses Playwright's bundled Chromium. Install it once with `npx playwright install chromium`.
- Override with `PW_CHANNELS`, e.g. `PW_CHANNELS=chromium` or `PW_CHANNELS=chrome`. The port can be changed with `E2E_PORT`.

`E2E_SKIP_BUILD=1` reuses an existing `dist/` instead of building again. CI does this.

The E2E suite is not part of `npm run check` (it needs a browser), but it **runs in GitHub Actions** (see below).

### Continuous integration

`npm run check` is the verification pipeline: **typecheck → lint → test → build → bundle budget**, stopping at the first failure. Run it before every commit.

The same pipeline, **plus browser E2E**, runs in GitHub Actions ([.github/workflows/ci.yml](.github/workflows/ci.yml)) on every push and pull request:

```
npm ci → typecheck → lint → unit tests → production build → bundle budget → install Playwright Chromium → E2E (on that build)
```

- Node.js comes from [`.nvmrc`](.nvmrc) (22 LTS; `package.json` requires `>=22.12.0`).
- Dependencies are installed with `npm ci`, exactly as locked in `package-lock.json`.
- Typecheck, lint, test (`npm run test:ci`) and build run as separate steps. Each one runs once install succeeds, so one failure never hides another, and any failure fails the workflow.
- E2E runs `npm run test:e2e` with `PW_CHANNELS=chromium` and `E2E_SKIP_BUILD=1`. It uses Playwright's own Chromium (`npx playwright install --with-deps chromium`), so no preinstalled Chrome or Edge is needed. It tests the build from the Build step, so nothing is built twice. An E2E failure fails the workflow, and the Playwright HTML report and traces are uploaded as the `playwright-report` artifact.
- Failing tests show up as file/line annotations. JUnit reports (`reports/junit.xml` for unit tests, `reports/e2e-junit.xml` for E2E) are uploaded as the `test-report` artifact, and the run summary lists each stage's result.
- No secrets or credentials are used. Actions are pinned to commit SHAs, and the job has read-only repository permissions.

`tests/ci/workflow.test.ts` checks these rules, so a workflow edit that breaks them fails `npm test`.

Line endings are normalized to LF by [`.gitattributes`](.gitattributes).

After changing step 1's model logic, regenerate the step 2 demo model (a test fails if it drifts):

```bash
npm run sample:regen
```

## What the parser supports

OpenAPI 3.0 / 3.1 and Swagger 2.0, as JSON or YAML: local `$ref` everywhere (schemas, parameters, request bodies, responses, path items, security schemes), recursive and mutually recursive schemas, `allOf`/`oneOf`/`anyOf`, nested objects, arrays, `nullable` (3.0, 3.1 type arrays, Swagger `x-nullable`), enums, path/query/header/cookie parameters with path-level + operation-level merging, multiple path parameters, content types, and correct security semantics (root inheritance, operation override, `[]` = public, `[{}]` = optional auth, AND/OR requirements). Malformed input produces errors or warnings, never a crash.

## Performance

The Step 1 page loads 197.5 KiB of JS (down from 589 KiB). The Security Twin graph (React + React Flow, 413 KiB) is a separate chunk fetched only when the twin is first rendered, with a loading state and Retry if it fails. `scripts/check-bundle.mjs` fails the build check if the entry grows past 256 KiB or the graph stops being lazy.

## Path parameters and target state

- **Path templates** are filled only by `fillPath` in `src/paths`. It matches parameters by exact name, percent-encodes each value as one segment, rejects dot-segments and empty values, and throws `MissingPathParameterError` for anything missing. Step 2 fills an object id into an endpoint's last parameter. Endpoints needing other values it doesn't have are skipped, with the reason shown in the planner.
- **Target authorization** shown in Step 1 is derived state. A valid URL is only *Sandbox target configured, authorization status unknown*. *Authorization confirmed* needs a matching authorization record, which nothing in the apps produces yet.
- **Sandbox targets** (`src/target/policy.ts`): only loopback, private-network and reserved-name hosts can be registered. Public hosts, link-local addresses (cloud metadata) and `0.0.0.0` are refused. A registered target is *authorized by configuration*: the operator's statement, which is not independently verified. Every live request must stay on the registered origin and base path, and redirects are refused. Step 1's Test Connection follows the same policy. See [docs/SANDBOX.md](docs/SANDBOX.md).

## Current limitations

- External (remote/file) `$ref` values are reported, not fetched.
- Resource and sensitivity inference are heuristics with recorded evidence, not ground truth.
- Step 2's execution and confirmation logic runs completely locally within the browser. Mock results are clearly SIMULATED, and while CONFIRMED is reserved for live runs against an authorized local sandbox, there is no backend API runner included. This is an explicit design choice to preserve the static, self-contained architecture of the tool. See [docs/TEST_LAB.md](docs/TEST_LAB.md).

## Docs

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): modules and data flow
- [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md): how the model is derived, plus the app safety rules
- [docs/SECURITY_CONSTITUTION.md](docs/SECURITY_CONSTITUTION.md): how security laws, provenance and confidence are derived
- [docs/SANDBOX.md](docs/SANDBOX.md): the authorized-sandbox-only policy and its current enforcement
- [docs/TEST_LAB.md](docs/TEST_LAB.md): Step 2 workflow, executor modes, result states and known weaknesses
- [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md): the offline, deterministic demo procedure
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md): commands, conventions, tests and how to extend
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): threats to the tool and its users, mitigations and residual risk
- [docs/REPOSITORY_AUDIT.md](docs/REPOSITORY_AUDIT.md): the original audit (historical record)
