# Sentinel X — Part 1: Security Twin Builder (v4 data-driven)

## Run
`app.js` imports the typed parser/model from `../src`, so it is bundled first. From the repository root:
```
npm install
npm start
# -> http://127.0.0.1:8000/1-security-twin/
```

## Flow (matches design)
1. Connect: Upload spec + paste configuration (or Load Demo), set Sandbox URL, Test Connection.
2. Click BUILD SECURITY TWIN.
3. Dashboard: readiness for Part 2.
4. API Discovery: EP-001… method/path/auth/resource/action table (OpenAPI 3.0/3.1 + Swagger 2.0, JSON or YAML; parser in `src/openapi`, see docs/ARCHITECTURE.md).
5. Enhanced API Model: resources/fields/relations + inferred ownershipField + sensitivity reasons.
6. Identity & Ownership: 100% from configuration — no hardcoded users/roles/permissions.
7. Sensitivity Engine: heuristic + reason + manual override → rebuild.
8. Dynamic Twin: roles/resources/endpoints all from spec+config; node = Identity·Role·Resource·Ownership·Endpoint·Sensitivity·AllowedActions.
9. Inference Engine: INF-01..05 with evidence + score + what raises confidence.
10. Constitution + Testable Laws: LAW-xxx with category/severity/confidence/invariant + Given/When/Expect tests.
11. Outputs: copy/download `testable-security-model.json` (version `part1-v4-datadriven`) — input contract for Part 2.

## Data-driven rule
`app.js` and `src/` contain zero instance data (no names, ids, roles, permissions, ownership, paths, or domain nouns).
Demo instance data lives only in `samples/sample-swagger.json` + `samples/sample-config.json`.
Proof: Seller/Support + Product/tenantId spec produces Seller laws with zero demo strings.

## Sandbox restriction
The banner states the policy (authorized sandbox targets only). The target label is derived state, not a claim:
`UNKNOWN` (no/invalid URL), `CONFIGURED` (valid URL, authorization unknown) or `CONFIRMED` (only with a matching
authorization record, which nothing produces yet). The exported JSON carries `sandboxOnly:true` and `targetAuthorization`.

## Files
- `index.html`, `styles.css`, `app.js`
- `samples/sample-swagger.json`, `samples/sample-config.json` (demo data)
