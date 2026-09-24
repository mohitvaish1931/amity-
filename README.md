# Sentinel X

OpenAPI security modelling for **authorized sandbox APIs only**. Step 1 turns an OpenAPI/Swagger spec plus a small config (users, roles, ownership) into an API model, a Security Twin and a set of security laws. Step 2 plans authorization test cases from that model.

> Pipeline so far: **OpenAPI → API model → Security Twin → Security Constitution → test specification**, all static; no runtime testing. See [progress.md](progress.md) for exactly what is and is not implemented.

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
│   ├── twin/                   Security Twin graph: pure transform + layout, React Flow view
│   ├── constitution/           Security Constitution engine: laws + provenance + confidence + test specs
│   ├── paths/                  fillPath: the single path-template filler (strict, encoded)
│   ├── target/                 target authorization state (UNKNOWN / CONFIGURED / CONFIRMED)
│   └── ui/safe-html.ts         escape-by-default HTML templating used by both apps
│
├── 1-security-twin/            STEP 1 browser app: spec → twin → constitution → testable model
│   ├── index.html, app.js, styles.css
│   └── samples/                demo spec + demo config
│
├── 2-test-lab/                 STEP 2 browser app: testable model → planned test cases
│   ├── index.html, app.js, styles.css
│   └── samples/                demo model (generated from step 1)
│
├── scripts/                    build, local server, jsdom harness, sample regeneration
├── tests/                      Vitest suites + OpenAPI fixtures (A–M)
├── e2e/                        Playwright end-to-end tests (real browsers, production build)
└── docs/                       architecture, security model, sandbox policy, audit
```

## Install

Requires Node.js 22.12 or newer (see `.nvmrc`).

```bash
npm install
```

## Run

```bash
npm start
```

This builds both apps into `dist/` and serves them at http://127.0.0.1:8000/:

- Step 1: http://127.0.0.1:8000/1-security-twin/ → **Load Demo Swagger + Config**, then **BUILD SECURITY TWIN**, then download `testable-security-model.json`.
- Step 2: http://127.0.0.1:8000/2-test-lab/ → **Load Demo Model** (or paste the JSON from step 1), then **PLAN TESTS**.

The apps import TypeScript from `src/`, so they must be built. Opening the source `index.html` directly no longer works.

## Test, typecheck, lint, build

```bash
npm test            # Vitest: parser, model, XSS regression, app-level tests
npm run typecheck   # tsc --noEmit (strict)
npm run lint        # ESLint (bans innerHTML in the apps)
npm run build       # production bundles in dist/
npm run check       # all four, in order
npm run test:e2e    # Playwright end-to-end tests (builds + serves dist/ itself)
```

### End-to-end browser tests (Playwright)

```bash
npm run test:e2e
```

This builds the production bundles and serves `dist/` on `127.0.0.1:4178` (`scripts/e2e-server.mjs`, a single Node process that Playwright starts and stops), then drives Step 1 in real browsers:
- the demo flow: build the twin, click a resource node, open a law, highlight its scope;
- empty, non-demo and invalid models.

Expected node, edge and highlight counts are computed from the model libraries, never hardcoded. Each test also asserts there are no console errors and that only the app's own local assets are requested.

- Windows: runs on the installed **Google Chrome** and **Microsoft Edge** (`chrome` and `msedge` channels), so no Playwright browser download is needed.
- Other platforms: uses Playwright's bundled Chromium. Install it once with `npx playwright install chromium`.
- Override with `PW_CHANNELS`, e.g. `PW_CHANNELS=chromium` or `PW_CHANNELS=chrome`. The port can be changed with `E2E_PORT`.

`E2E_SKIP_BUILD=1` reuses an existing `dist/` instead of building again. CI does this.

The E2E suite is not part of `npm run check` (it needs a browser), but it **runs in GitHub Actions** (see below).

### Continuous integration

`npm run check` is the verification pipeline: **typecheck → lint → test → build**, stopping at the first failure. Run it before every commit.

The same pipeline, **plus browser E2E**, runs in GitHub Actions ([.github/workflows/ci.yml](.github/workflows/ci.yml)) on every push and pull request:

```
npm ci → typecheck → lint → unit tests → production build → install Playwright Chromium → E2E (on that build)
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

## Path parameters and target state

- **Path templates** are filled only by `fillPath` in `src/paths`. It matches parameters by exact name, percent-encodes each value as one segment, rejects dot-segments and empty values, and throws `MissingPathParameterError` for anything missing. Step 2 fills an object id into an endpoint's last parameter. Endpoints needing other values it doesn't have are skipped, with the reason shown in the planner.
- **Target authorization** shown in Step 1 is derived state. A valid URL is only *Sandbox target configured, authorization status unknown*. *Authorization confirmed* needs a matching authorization record, which nothing in the apps produces yet.

## Current limitations

- External (remote/file) `$ref` values are reported, not fetched.
- Resource and sensitivity inference are heuristics with recorded evidence, not ground truth.
- Step 2's test execution and finding logic are unchanged from the prototype. The audit issues there (browser-side execution, weak confirmation, mock findings labelled CONFIRMED) are still open. See [progress.md](progress.md).

## Docs

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): modules and data flow
- [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md): how the model is derived, plus the app safety rules
- [docs/SECURITY_CONSTITUTION.md](docs/SECURITY_CONSTITUTION.md): how security laws, provenance and confidence are derived
- [docs/SANDBOX.md](docs/SANDBOX.md): the authorized-sandbox-only policy and its current enforcement
- [docs/REPOSITORY_AUDIT.md](docs/REPOSITORY_AUDIT.md): the original audit
