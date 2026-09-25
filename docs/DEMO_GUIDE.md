# Demo Guide

A deterministic walkthrough that needs no internet, no API keys and no external services. Every value on screen is derived from the bundled demo spec and configuration, so you can replace them with your own to show that nothing is hardcoded.

## Setup (fresh clone)

```bash
npm ci
npm run check
npm start
```

`npm run check` runs typecheck, lint, 360+ unit tests, the production build and the bundle budget. `npm start` rebuilds and serves `dist/` at http://127.0.0.1:8000/ (use `PORT=9000 npm start` for another port).

Optional, to show the browser tests:

```bash
npm run test:e2e
```

## Part 1: Security Twin (http://127.0.0.1:8000/1-security-twin/)

1. **Load Demo Swagger + Config**. The status line confirms the load. The sandbox URL is filled from the spec's `servers`, and the target label says *Sandbox target configured · Authorization status unknown* (configuring is not authorizing).
2. **BUILD SECURITY TWIN**. The status line reads "Built from the spec: 5 endpoints, 4 resources, 7 laws". The graph code downloads only now (lazy loading).
3. **Dashboard**: readiness is a 6-item checklist, not a formula. Remove the admin identity from the identities editor and click **Apply config → rebuild** to see it drop to 5/6 with the failing check named.
4. **Inference & Confidence**: each claim lists its evidence signals (✅/❌). INF-03 is MEDIUM until an analyst confirms a sensitivity classification. Change a field in the **Data Sensitivity** table and apply to raise it.
5. **Security Twin graph**: click a resource node to see its relationships, laws and provenance.
6. **Security Constitution**: filter by category, severity or confidence, or search (e.g. `customerId`). Open a law to see its machine rule, scope, provenance, confidence signals and test strategy. **Highlight scope in graph** zooms the graph to exactly that law's scope. **Export shown laws** as JSON or Markdown; the export says it is specification-derived.
7. **Testable Security Model**: **Download JSON** for Part 2.

## Part 2: Test Lab (http://127.0.0.1:8000/2-test-lab/)

1. **Load Demo Model** (or paste the JSON from Part 1), then **PLAN TESTS**. 22 cases are planned. The target bar shows the target, *NOT REGISTERED*, *Mock (simulated)* and the run state.
2. Select test cases with the mouse or keyboard. The request inspector shows the hypothesis, mutation and exact request.
3. **RUN ALL** in Mock mode. Results and findings are labelled **SIMULATED**, with the law's confidence level and no percentages.
4. **Download Evidence Package** to show the exported findings are marked `SIMULATED` / `simulated: true`, with the registered targets (if any) and no credentials. Then, optionally, switch Mock behavior to *Secure*, click **Reset results** and run again to see the laws satisfied.
5. **Guardrails**: switch Executor to *Live* and type `https://api.github.com` or `http://169.254.169.254`. Registration is refused with the reason, and RUN ALL sends nothing: every executable case ends as ERROR ("not a registered target"), and policy-review cases are SKIPPED.

## What the demo does not show

Real vulnerability confirmation. Mock runs are simulations, and live mode only runs against a sandbox you register on this machine or your private network. See docs/TEST_LAB.md for the prototype's limitations.
