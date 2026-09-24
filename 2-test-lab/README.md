# Sentinel X — Part 2: Autonomous Lab (v2)

## Run
From the repository root (the app is bundled with `src/ui/safe-html.ts`):
```
npm install
npm start
# -> http://127.0.0.1:8000/2-test-lab/
```

## Flow (consumes Part 1, feeds Part 3)
1. Import `testable-security-model.json` (Part 1 → Download, or Load Demo Model = `sample-testable-model.json`).
2. PLAN TESTS (heuristic): laws → conditions → cases across **all** eligible endpoints
   (BOLA baseline/boundary/anon + sequence per ID endpoint, ADMIN deny/allow per admin endpoint,
   DATA leak per ID endpoint, AUTHN anonymous per protected endpoint).
3. Targets: priority-ranked endpoints (object-ID, admin, sensitive, write, auth-required).
4. Preview: heuristic hypothesis + mutation + expected + curl + RUN TEST.
5. Execute: Mock Sandbox (Vulnerable/Secure, data-driven) or Live Sandbox (below).
   Sequence tests execute every step in order — each step gets its own request,
   response and step verdict (step 1 doubles as the baseline for step 2).
6. Analyze: status + ownership + sensitive-field leak + baseline similarity → Expected vs Actual.
7. Confirm: repeat → ownership → sensitivity checks (false-positive filter) → PASS / VIOLATION / REJECTED.
8. Matrix: identities × own/foreign, per ID endpoint. Findings: FINDING-xxx with reproduction
   + full sequence proof chains (Step 1 → Step 2 → final result with per-step request,
   response, ownership, sensitive fields and step verdicts).
9. Export `evidence-package.json` → Part 3 (includes sequence proofs, auth/approval record,
   hypothesis sources, and unexecuted LLM ideas if any).

## Live-run honesty rules (v2 corrections)
- **Authentication is real:** per-identity credentials you paste (Bearer / API-key).
  The lab sends proper auth headers and blocks live cases with no credential configured.
  The old demo-only identity header is gone; `X-Sentinel-Test` is tracing only, never auth.
  Secrets stay in browser memory and are never written to findings or evidence.
- **Cookies use the browser jar (with limits stated in the UI):** browsers forbid scripts
  from setting the `Cookie` header, so pasted cookie values are **unsupported for
  cross-origin execution** — the lab never sends a `Cookie` header. Cookie mode uses
  `credentials: include` (your login cookies, so log in to the sandbox in this browser
  first) and the sandbox must opt into CORS credentials (exact origin, no wildcard).
  Anonymous tests always use `credentials: omit` so they stay anonymous. For
  cross-origin sandboxes prefer Bearer/API-key, Mock mode, or a same-origin proxy.
  Unexpected 401s on cookie runs are caveated as possible cookie setup, not findings.
  Cookie live runs additionally require ticking the support acknowledgement
  (sandbox supports CORS credentials + you are logged in) — otherwise they are blocked.
- **Sandbox approval is explicit:** live runs require ticking the authorization checkbox and
  approving the exact URL. The old substring hint is display-only, never a pass.
- **Coverage is complete:** every eligible endpoint gets cases (demo: 4 laws → 22 cases),
  not just the first candidate. AUTHN caps at 15 protected endpoints with a note.
- **Planner is heuristic, not an AI agent:** hypotheses are deterministic templates labelled
  `heuristic`. Optionally: reword hypotheses, or ask your own OpenAI-compatible endpoint for
  extra test **ideas** (displayed only with source `llm`, `executed: false` — never
  auto-executed; recreate manually if valid). Planning, execution and verdicts always
  stay deterministic, which is acceptable for MVP.

## Demo
- Mock + Vulnerable → 10 confirmed (BOLA ×3 endpoints, sequence, BFLA, data leaks), rest pass.
- Mock + Secure → 22 pass, zero false violations.
- No hardcoded shop data: endpoints/identities/ownership/fields all come from the imported model.

## Files
- `index.html`, `app.js`, `styles.css`
- `samples/sample-testable-model.json` (demo data, generated from Part 1 demo)
