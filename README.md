# Sentinel X

Zero-trust API security testing prototype, built for a 24-hour hackathon. Runtime tests are meant to run **only against sandbox APIs you are authorized to test**.

## Code

| Folder | What it is | Main files |
|---|---|---|
| [`part1/`](part1/) | **Security Twin Builder**: OpenAPI/Swagger → API discovery → security twin → security constitution → testable security model (JSON) | [`app.js`](part1/app.js), [`index.html`](part1/index.html), [`sample-swagger.json`](part1/sample-swagger.json), [`sample-config.json`](part1/sample-config.json) |
| [`part2/`](part2/) | **Test Lab**: imports Part 1's model → plans test cases → runs them (mock or live sandbox) → findings → evidence package | [`app.js`](part2/app.js), [`index.html`](part2/index.html), [`sample-testable-model.json`](part2/sample-testable-model.json) |
| [`docs/`](docs/) | Engineering docs | [`REPOSITORY_AUDIT.md`](docs/REPOSITORY_AUDIT.md) |

## Run

No install or build is needed; both parts are static web apps.

```bash
cd part1
python -m http.server 8000
```

Open http://localhost:8000, click **Load Demo Swagger + Config**, then **BUILD SECURITY TWIN**, and download `testable-security-model.json`.

```bash
cd part2
python -m http.server 8001
```

Open http://localhost:8001, click **Load Demo Model** (or paste Part 1's JSON), then **PLAN TESTS** and **RUN ALL**.

## Status

This is an early prototype. See [`docs/REPOSITORY_AUDIT.md`](docs/REPOSITORY_AUDIT.md) for what currently works, what is simulated, known bugs and the implementation plan.
