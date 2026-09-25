# Threat Model (the Sentinel X tool itself)

What could go wrong when someone uses Sentinel X, and what the code does about it. Scope: the two browser apps, the build/serve scripts and CI.

## Assets

- The operator's sandbox credentials (per-identity tokens/keys).
- The operator's trust in results: a finding or confidence level must mean what it says.
- Systems the operator is not authorized to test.
- The operator's machine (local dev server, build).

## Threats and mitigations

| # | Threat | Mitigation | Residual risk |
|---|---|---|---|
| T1 | A hostile spec, config or model injects script (names are rendered everywhere) | Escape-by-default rendering (`safe-html`), ESLint ban on HTML sinks, CSP `script-src 'self'` with no inline scripts or handlers, escaped Markdown export. XSS suite with crafted inputs; CSP test. | `style-src` allows inline styles (needed by React Flow and existing markup). |
| T2 | Tests hit a system the operator is not authorized to test (target confusion, typo, spec `servers`) | Target policy: public, link-local and unspecified hosts cannot be registered; explicit confirmation; the target bar shows the exact URL; registration is exact-URL; the model never overwrites a typed URL. | Names are classified by suffix, not resolved (a `.internal` name could point anywhere your DNS says). |
| T3 | SSRF-style pivot to internal metadata services (`169.254.169.254`) | Link-local is refused in Step 2 registration and in Step 1 Test Connection; alternative IPv4 spellings are normalized first. | IPv4-mapped IPv6 is treated as public (refused), not decoded. |
| T4 | A request escapes the registered target (path tricks, redirects) | `resolveRequestUrl` joins by string and checks origin and base path; `redirect: "error"`. | Browser-side enforcement only. |
| T5 | Credential leakage | Credentials live in memory, are set as DOM properties (never markup), are omitted from findings, evidence and console, are sent only to the registered target, and use `credentials: "omit"` except for the explicit cookie-jar scheme. | The optional LLM feature sends test wording (ids, paths) to the operator's own endpoint with the operator's key. |
| T6 | Misleading results (simulated data shown as proof, invented confidence) | Mock output is SIMULATED everywhere; CONFIRMED only for live runs; confidence comes from named signals; exports say "specification-derived"; unreachable sandboxes are ERROR, never findings. | Step 2's confirmation logic is still a prototype (see TEST_LAB.md). |
| T7 | Silent failures hide problems | Inline loading/success/empty/error states with Retry; a clipboard failure is reported. | – |
| T8 | Local dev server exposure or crash | Binds 127.0.0.1; serves only `dist/`; 400 for undecodable paths (no crash), 403 outside the root. | – |
| T9 | Supply chain | Exact dependency versions, `npm ci` from the lockfile, CI actions pinned to SHAs, read-only CI permissions, no secrets in CI; `npm audit`: 0 vulnerabilities (2026-09-25). | New advisories after that date. |
| T10 | Data left in the browser | Persistence is opt-in, Step 1 only, declared fields only (never credentials), validated on load, and cleared by unticking or **Clear saved data**. Step 2 persists nothing. | Anyone with access to the same browser profile can read a remembered spec and configuration. |

## Out of scope

Server-side execution, server-side persistence and multi-user access control. None of these exist; the only storage is the opt-in browser storage in T10.
