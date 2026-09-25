# Sandbox Policy

Sentinel X is for **authorized sandbox environments only**: APIs you own or have explicit permission to test, never public or production systems.

## Policy

1. Runtime requests may only target a sandbox the operator has explicitly registered and stated they are authorized to test.
2. Scope never expands automatically. Hosts found in specs (`servers`), redirects or responses are not added to scope.
3. Credentials are supplied per test identity by the operator. They are never logged, exported or rendered into page markup.
4. Static analysis (Step 1 and Step 2 planning) needs no target at all and makes no network requests.

## Target policy (`src/target/policy.ts`)

A host is classified from the **parsed** URL. Sandbox-sounding words such as "sandbox", "staging" or "test" in a public hostname mean nothing, and alternative IPv4 spellings are normalized first (for example `http://2130706433/` = 127.0.0.1).

| Host class | Examples | Can be registered |
|---|---|---|
| loopback | `localhost`, `*.localhost`, `127.0.0.0/8`, `[::1]` | yes |
| private-network | `10/8`, `172.16/12`, `192.168/16`, `fc00::/7` | yes |
| reserved-name | `.test`, `.example`, `.invalid`, `.localhost`, `.local`, `.home.arpa`, `.internal` | yes (assumed to point at your own environment) |
| link-local | `169.254/16` (includes cloud metadata services), `fe80::/10` | **no** |
| unspecified | `0.0.0.0`, `::` | **no** |
| public | everything else, including `example.com` and IPv4-mapped IPv6 | **no** |

A target URL must be `http(s)`, with no embedded credentials, query or fragment.

A registered target is a `Target`:

```json
{ "id": "TGT-1", "name": "127.0.0.1:9000", "baseUrl": "http://127.0.0.1:9000", "origin": "http://127.0.0.1:9000",
  "basePath": "", "environment": "sandbox", "authorizationStatus": "AUTHORIZED_BY_CONFIGURATION",
  "hostClass": "loopback", "registeredAt": "2026-09-25T10:00:00.000Z" }
```

`AUTHORIZED_BY_CONFIGURATION` means the operator ticked "I confirm I am authorized…". Sentinel X does not verify that statement, and the UI says so ("not independently verified").

## Enforcement today

| Area | Behaviour |
|---|---|
| Step 1 target label | Rendered from `TargetAuthorizationState`. A valid URL is only `CONFIGURED` ("Authorization status unknown"). |
| Step 1 Test Connection | Refuses any host the target policy does not accept, without sending anything. Otherwise sends one GET with no credentials and redirects refused, and offers Retry on failure. Reachability is not authorization. |
| Step 2 target registration | Only registrable hosts show a registration control, which needs an explicit confirmation checkbox. Refused hosts show the reason. A registration covers that exact normalized URL only. |
| Step 2 target bar | Always visible: TARGET (the exact URL a run would use), SANDBOX · AUTHORIZED BY CONFIGURATION or NOT REGISTERED, MODE, and RUN state. |
| Step 2 live execution | Blocked unless the current URL is a registered target. Each request URL is built by `resolveRequestUrl`, which refuses anything off the target's origin or outside its base path (`..`, encoded `..`, backslashes, relative paths). `redirect: "error"` stops a redirect from leaving the target. |
| Step 2 URL handling | The model's `sandboxBaseUrl` only fills an empty field. A URL the user typed is never replaced, and planning uses exactly the field's value (audit BUG-11). |
| Mock mode | Simulates responses locally. Results and findings are labelled SIMULATED, and the reasoning trail never says "CONFIRMED". |
| Tests | Fully offline. The jsdom harness throws on any fetch outside the app's own files. The live-mode tests replace `fetch` (unit) or abort requests inside the browser (`page.route`, E2E), so nothing is sent. |
| Local server | `scripts/serve.mjs` binds to 127.0.0.1 and serves only `dist/` (400 for undecodable paths, 403 outside the root). |
| Content-Security-Policy | Scripts only from the page's own origin. `connect-src` allows http(s) because the operator supplies the sandbox URL; the target policy above is what restricts it. |

## Limitations

- Hostnames are classified by name. A browser cannot resolve DNS, so a `.internal` name that your DNS points at a public address would be accepted.
- Enforcement runs in the browser. There is no server-side allowlist, rate limiting or response redaction, so treat Step 2 live execution as a prototype.
- Registration is per page session (memory only). Nothing is persisted.
