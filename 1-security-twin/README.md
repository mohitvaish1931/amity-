# Sentinel X — Part 1: Security Twin Builder (v4 data-driven)

## Run
No build needed. Open `index.html` in a browser, or serve:
```
cd 1-security-twin
python -m http.server 8000
# -> http://localhost:8000/
```

## Flow (matches design)
1. Connect: Upload spec + paste configuration (or Load Demo), set Sandbox URL, Test Connection.
2. Click BUILD SECURITY TWIN.
3. Dashboard: readiness for Part 2.
4. API Discovery: EP-001… method/path/auth/resource/action table (OpenAPI 3.x + Swagger 2.0, $ref, allOf).
5. Enhanced API Model: resources/fields/relations + inferred ownershipField + sensitivity reasons.
6. Identity & Ownership: 100% from configuration — no hardcoded users/roles/permissions.
7. Sensitivity Engine: heuristic + reason + manual override → rebuild.
8. Dynamic Twin: roles/resources/endpoints all from spec+config; node = Identity·Role·Resource·Ownership·Endpoint·Sensitivity·AllowedActions.
9. Inference Engine: INF-01..05 with evidence + score + what raises confidence.
10. Constitution + Testable Laws: LAW-xxx with category/severity/confidence/invariant + Given/When/Expect tests.
11. Outputs: copy/download `testable-security-model.json` (version `part1-v4-datadriven`) — input contract for Part 2.

## Data-driven rule
`app.js` contains zero instance data (no names, ids, roles, permissions, ownership, paths).
Demo instance data lives only in `sample-swagger.json` + `sample-config.json`.
Proof: Seller/Support + Product/tenantId spec produces Seller laws with zero demo strings.

## Sandbox restriction
Banner `AUTHORIZED SANDBOX ONLY` is always visible. `sandboxOnly:true` is in exported JSON.

## Files
- `index.html`, `styles.css`, `app.js`
- `samples/sample-swagger.json`, `samples/sample-config.json` (demo data)
