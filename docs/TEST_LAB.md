# Test Lab (Step 2)

Step 2 turns Step 1's `testable-security-model.json` into planned authorization test cases and can run them in two modes. This page describes what it does today, including its known weaknesses.

## Workflow

1. **Receive the model**: paste it, upload it, or **Load Demo Model**. Status: loading → loaded, with Retry on failure.
2. **Plan tests**: a deterministic heuristic planner expands each law into cases across all eligible endpoints (object ownership, anonymous access, admin functions, sensitive data, sequences, policy review). Endpoints whose extra path parameters have no values are skipped, with the reason shown. Status: "Planned N test cases from M laws", or an explanation when the model is empty or invalid.
3. **Review**: the workspace shows test cases (left), the execution timeline and results (centre) and the request inspector (right) side by side from 1280 px wide, stacked below that. Test cards are selectable by click or keyboard (Enter/Space).
4. **Run** one test or all tests in the selected executor mode. The target bar at the top always shows the target, its registration state, the mode and the run progress.
5. **Findings** and the **evidence package** export (JSON).

## Executor modes

| Mode | What happens | How results are labelled |
|---|---|---|
| Mock (default) | Responses are generated locally from the model: `vulnerable` violates the laws, `secure` satisfies them. No network. | Every result and finding is **SIMULATED**. The reasoning trail ends in "SIMULATED (a live sandbox run would be needed to confirm)", and mock responses contain placeholder values (`<field>_value`). |
| Live | `fetch` from the browser to the **registered** target only (see docs/SANDBOX.md), with the operator's per-identity credentials as real auth headers. | Results come from real responses. A request that fails (unreachable, CORS, redirect, timeout) is an **ERROR** result and never a finding. |

## Result states (per test)

| State | Meaning |
|---|---|
| PASS | The response matched the expected outcome. |
| VIOLATION | The response contradicted the expected outcome and passed the prototype's confirmation checks (a repeat request, ownership from the model's ownership map, sensitive fields or data returned). In mock mode this is a simulated violation. |
| REJECTED | Confirmation filtered the result out as a likely false positive (e.g. not a foreign object, no data returned). |
| ERROR | The request could not be made or completed, e.g. no registered target, no credential for the identity, network failure. |
| SKIPPED | Policy-review cases with no executable endpoint. |

Findings are built from violations. Their status is **SIMULATED** for mock runs and **CONFIRMED** only for live runs. Each finding shows the law's own confidence level (HIGH/MEDIUM/LOW), never a made-up percentage.

## Current constraints (Local Execution Only)

These audit items are inherent constraints of the local-only browser architecture. By design, Step 2 is not a fully networked backend runtime engine:

- Execution runs entirely in the browser, so enforcement is client-side.
- Confirmation is heuristic: it compares status codes and looks for field names, and HTTP 200 on a foreign object is treated as exposure without comparing the data to the owner's baseline in depth.
- Request bodies for writes are minimal placeholders, not schema-driven.
- There is no backend persistence; everything lives in page memory (except basic config inputs).
- The evidence package includes response bodies as received, with no redaction beyond credentials.

## Tests

- Unit/app tests: `tests/apps/target-guardrails.test.ts` (registration, refusals, run state, live-request scope, connection check), `tests/apps/dynamic-data.test.ts` (SIMULATED labelling, hypotheses as text, URL never overwritten), `tests/apps/error-states.test.ts`, `tests/apps/accessibility.test.ts`, `tests/apps/foundation-blockers.test.ts`.
- E2E: `e2e/step2.spec.ts` (plan, keyboard selection, a mock run labelled SIMULATED, refused targets, a live run blocked for an unregistered URL, and a live run against a registered loopback target whose requests are aborted in the browser, so the unreachable-sandbox case shows as ERROR with no findings) and `e2e/layout.spec.ts`.
