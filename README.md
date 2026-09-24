# Sentinel X

Zero-trust API security testing prototype, built for a 24-hour hackathon. Runtime tests are meant to run **only against sandbox APIs you are authorized to test**.

## Folder structure

```
amity/
├── README.md                  ← you are here
│
├── 1-security-twin/           STEP 1: understand the API
│   ├── index.html             UI (open this)
│   ├── app.js                 all logic: spec parser, twin, security laws
│   ├── styles.css
│   ├── README.md
│   └── samples/               demo input
│       ├── sample-swagger.json    demo OpenAPI spec
│       └── sample-config.json     demo users, roles, ownership
│
├── 2-test-lab/                STEP 2: test the API
│   ├── index.html             UI (open this)
│   ├── app.js                 all logic: test planner, runner, findings
│   ├── styles.css
│   ├── README.md
│   └── samples/
│       └── sample-testable-model.json   demo input (= output of step 1)
│
└── docs/
    └── REPOSITORY_AUDIT.md    what works, what is simulated, known bugs, plan
```

## How the two steps connect

```
OpenAPI spec + config ──► 1-security-twin ──► testable-security-model.json ──► 2-test-lab ──► findings + evidence-package.json
```

| Folder | What it does |
|---|---|
| [`1-security-twin/`](1-security-twin/) | Reads an OpenAPI/Swagger spec and a config (users, roles, ownership). Builds the API inventory, security twin and security laws, and exports `testable-security-model.json`. |
| [`2-test-lab/`](2-test-lab/) | Imports that model, plans test cases, runs them (mock or live sandbox), and exports confirmed findings as `evidence-package.json`. |
| [`docs/`](docs/) | Engineering docs, starting with the [repository audit](docs/REPOSITORY_AUDIT.md). |

## Run

No install or build is needed; both steps are static web apps. Python is only used as a local file server.

**Step 1: Security Twin**

```bash
cd 1-security-twin
python -m http.server 8000
```

Open http://localhost:8000, click **Load Demo Swagger + Config**, then **BUILD SECURITY TWIN**, and download `testable-security-model.json`.

**Step 2: Test Lab**

```bash
cd 2-test-lab
python -m http.server 8001
```

Open http://localhost:8001, click **Load Demo Model** (or paste the JSON from step 1), then **PLAN TESTS** and **RUN ALL**.

## Status

Early prototype. See [`docs/REPOSITORY_AUDIT.md`](docs/REPOSITORY_AUDIT.md) for what currently works, what is simulated, known bugs and the implementation plan.
