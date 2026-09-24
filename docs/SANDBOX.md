# Sandbox Policy

Sentinel X is for **authorized sandbox environments only**: APIs you own or have explicit permission to test, never public or production systems.

## Policy

1. Runtime requests may only target a sandbox the operator has explicitly authorized.
2. Scope never expands automatically. Hosts found in specs (`servers`), redirects or responses are not added to scope.
3. Credentials are supplied per test identity by the operator. They are never logged, exported or rendered into page markup.
4. Static analysis (steps 1 and 2 planning) needs no target at all and makes no network requests.

## Current state (foundation-hardening phase)

No new runtime or network capability was added in this phase. What exists today:

| Area | State |
|---|---|
| Target authorization label (Step 1) | Rendered from `TargetAuthorizationState`. A valid URL is only `CONFIGURED` ("Authorization status unknown"). `CONFIRMED` requires a matching authorization record, and no component produces one yet. |
| Step 1 (Security Twin) | Static analysis only. The optional **Test Connection** button sends one GET to the entered URL. When the URL does not look like a sandbox, the warning now says exactly that, instead of falsely claiming "production blocked". |
| Step 2 planning | Static. Builds test cases from the model and makes no requests. |
| Step 2 execution (prototype) | Unchanged. It runs in the browser, is gated by a per-URL approval checkbox, and supports a local mock mode. The audit's issues with it are still open (browser-side execution, client-side-only approval, weak confirmation; see docs/REPOSITORY_AUDIT.md). |
| Tests | Fully offline. The jsdom harness (`scripts/app-harness.mjs`) throws on any fetch outside the app's own files. |
| Local server | `scripts/serve.mjs` serves only `dist/`, on 127.0.0.1. |

## Planned (not implemented)

A server-side runtime with an explicit target allowlist, per-target rate limits, request timeouts, response redaction, and a local sandbox API with deterministic fixtures. Until that exists, treat step 2 live execution as a prototype.
