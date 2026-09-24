# Sentinel X — Repository Audit

**Date:** 2026-09-24
**Update:** this is the point-in-time audit of the original prototypes. The parser (BUG-15*, BUG-16, BUG-17), warning (BUG-14) and XSS (SEC-03, SEC-09) findings were fixed in the foundation-hardening phase; see `progress.md` and `tests.json` for per-issue status. File paths below have been updated to the current layout.
**Scope:** everything under `C:\Users\mohit\Downloads\amity` (11 files, ~2,160 lines).
**Method:** I read every file, ran syntax and type checks, served both apps locally and drove them in a real browser. I also ran Part 2 live mode against a **local-only** audit sandbox (`127.0.0.1:9100`, a scratch file that is not in this repo) that I wrote to probe its analyzer. Where this document says something was *verified*, I executed it. Where it says *code-read*, I did not execute it.

> Nothing in this audit touched a public or production system. One accidental exception is disclosed under BUG-11: the app itself redirected 22 requests to `https://sandbox-api.example.com`. That is an IANA-reserved example domain, and every one of those requests failed at the network level.

---

## 0. Repository facts

| Item | Finding |
|---|---|
| Layout | `1-security-twin/` (Part 1) and `2-test-lab/` (Part 2), each with a `samples/` folder. Originally nested as `part1/part1/` and `part2/part2/`; renamed and reorganized on 2026-09-24. Code logic unchanged; only the three demo-file fetch paths were updated. |
| Languages | Vanilla browser JavaScript, HTML and CSS. |
| Package manager / dependencies | **None.** No `package.json`, no lockfile, no third-party code. |
| Build | **None.** Static files, opened directly or served with `python -m http.server`. |
| Typecheck | **None configured.** I ran `tsc --noEmit --allowJs --checkJs` as a proxy: Part 1 had 19 errors and Part 2 had 35, all DOM-typing noise (`.value` on `HTMLElement`, `mode: string`). None of them is a logic bug. |
| Tests | **None.** No test files, framework or fixtures. |
| Lint / CI | None. |
| Backend | **None.** All logic, including security-test execution, runs in the browser. |
| Part 3 | Referenced in the UI and the evidence export ("→ Part 3"), but **does not exist**. |
| Version control | **This folder has no repository of its own.** `git` resolves upward to `C:\Users\mohit\.git`, a repository rooted at the user's home directory, and that repository's `config` is **corrupt** (the file is all null bytes). Every `git` command fails with `fatal: bad config line 1 in file .git/config`. The environment banner's "clean, branch main" status is not trustworthy. |
| Stray config | `C:\Users\mohit\package.json` declares `"type": "module"`, so any `.js` Node script under the home directory runs as ESM. This will bite future tooling. |

### File inventory

| File | Lines | Role |
|---|---|---|
| `1-security-twin/app.js` | 535 | Spec parser, resource/field inference, twin, inferences, laws, testable-model export, sandbox reachability check, all rendering |
| `1-security-twin/index.html` | 67 | Single-page UI (Connect → Dashboard → Discovery → Model → Identity → Sensitivity → Twin → Inference → Constitution → Outputs) |
| `1-security-twin/styles.css` | 33 | Styles |
| `1-security-twin/samples/sample-swagger.json` | 86 | Demo OpenAPI 3.0 "shop" spec (5 operations, 3 schemas) |
| `1-security-twin/samples/sample-config.json` | 12 | Demo identities, permission matrix and ownership map |
| `1-security-twin/README.md` | 33 | Claims and usage |
| `2-test-lab/app.js` | 571 | Model import, heuristic planner, mock and live executors, analyzer, confirmation, findings, evidence package, optional LLM wording and ideas |
| `2-test-lab/index.html` | 63 | UI |
| `2-test-lab/styles.css` | 31 | Styles |
| `2-test-lab/samples/sample-testable-model.json` | 669 | Part 1's demo output. **Verified byte-equivalent** to what Part 1 generates today (SHA-256 prefix `0e7d368e005fddc4` over laws, endpoints, resources and twin). |
| `2-test-lab/README.md` | 59 | Claims and usage |

---

## 1. Current architecture

```
┌──────────────────────── Browser tab A (Part 1) ────────────────────────┐
│ textarea(spec JSON) + 3 config textareas (identities/permissions/own.) │
│   → parseSpec → buildResources → buildTwin → buildInferences           │
│   → buildLaws(+lawTestsFor) → buildDashboard → buildTestableModel      │
│   → render*() via innerHTML                                             │
│   → Download testable-security-model.json                               │
│ testSandbox(): browser fetch GET <any URL>  (no approval gate)          │
└──────────────────────────────────┬──────────────────────────────────────┘
                                   │ manual file download / paste
┌──────────────────────────────────▼──── Browser tab B (Part 2) ─────────┐
│ loadModel → planTests (category templates)                              │
│   → execTest: mockRequest (in-page simulation)                          │
│             | liveRequest (browser fetch → sandbox; CORS-dependent)     │
│   → analyze (status + top-level key names) → confirm (repeat + map)     │
│   → buildFindings → evidencePackage → Download evidence-package.json    │
│ optional: browser fetch → user-supplied OpenAI-compatible LLM endpoint  │
└─────────────────────────────────────────────────────────────────────────┘
State: global in-memory objects (STATE, S). No persistence, no backend, no auth, no history.
```

The two parts are coupled only through the exported JSON contract (`version: "part1-v4-datadriven"`).

### Data flow: OpenAPI → findings (traced and verified)

1. **Input.** A JSON-only spec (YAML fails with a `JSON.parse` error, verified). Config is three free-form JSON textareas.
2. **`parseSpec`** walks `paths` × methods and produces `EP-nnn` records: `{method, path, auth, authDetail, resource, action, params[], bodyRef, respRef}`. Auth comes from operation security → global security → "has securitySchemes" → default-deny.
3. **`inferResource`** uses a `/admin` prefix → `"Admin"`, otherwise a **hardcoded keyword list** (`invoice, order, user, refund, payment, product, customer, account`), otherwise the first static path segment.
4. **`buildResources`** turns each `components.schemas` / `definitions` entry into a resource. Only **top-level** properties are read, with `allOf` merged and only the first branch of `oneOf`/`anyOf`. Each field is classified by name regex. The ownership field is chosen by name regex (`customerId|ownerId|userId|tenantId|…`).
5. **`buildTwin`** joins endpoints and resources with config roles, permissions and ownership. The admin role is the first role whose name contains "admin".
6. **`buildInferences`**: five fixed claims (`INF-01..05`) with hardcoded scores (90/60/55/65/30).
7. **`buildLaws`**: up to six fixed templates (BOLA, ADMIN, DATA, AUTHN-protected, AUTHN-open, ROLE), each with prose Given/When/Expect tests.
8. **Export** `testable-security-model.json`, then a manual hand-off to Part 2.
9. **`planTests`** (Part 2) **re-derives** test cases from each law's `category`. It ignores Part 1's `law.tests` and `expectedBehavior`. It pairs a base identity with the **global** ownership map (`objectId → ownerId`) and applies that same map to every ID endpoint.
10. **`execTest`** calls `mockRequest` (a deterministic in-page simulation of a "vulnerable" or "secure" server) or `liveRequest` (browser `fetch` to `sandboxUrl + path`, with a Bearer or API-key header from in-memory credentials).
11. **`analyze`**: 200/201 counts as allow, 401/403/404 as deny, and anything else falls into a catch-all *violation* branch. "Sensitive fields found" means top-level response **key names** that match any flagged field name from any resource.
12. **`confirm`**: re-send **only the final request**, compare **status code only**, check the **asserted** config ownership map, then mark CONFIRMED.
13. **`buildFindings`** gives every confirmed result a `FINDING-nnn` with `status: "CONFIRMED"` and a confidence taken from the **law's** confidence (98/85/70). No deduplication.
14. **`evidencePackage`** exports JSON with findings, results and full response bodies.

---

## 2. Current working features (verified by execution)

| # | Feature | How I verified it |
|---|---|---|
| W1 | Part 1 loads demo spec and config and builds 5 endpoints, 4 resources and 4 laws | Browser; ran `demoBtn` and `buildBtn` handlers |
| W2 | OpenAPI 3 basic parsing: methods, path/query/header params, global→operation security, `security: []` = public | Browser, custom spec |
| W3 | Swagger 2.0 basics: `host + basePath + schemes` → server URL; `securityDefinitions`; typed path params | Browser, custom spec |
| W4 | `$ref` to `components/schemas` / `definitions`, and `allOf` merge | Browser |
| W5 | Heuristic field sensitivity with manual override that triggers a rebuild | Code plus UI render; override path code-read |
| W6 | Config-driven identities, roles, permissions and ownership (no identities hardcoded in `app.js`) | Code-read plus build |
| W7 | Testable-model export is deterministic and matches the shipped sample | SHA-256 comparison |
| W8 | Part 2 plans 22 cases from 4 laws across all eligible endpoints | Browser |
| W9 | Mock "Vulnerable" gives 10 violations; mock "Secure" gives 22 PASS and 0 findings (README claims reproduced) | Browser |
| W10 | Live mode really sends HTTP requests with per-identity `Authorization: Bearer` headers; anonymous tests send no credential | Local audit sandbox request log (38 requests, identities resolved correctly) |
| W11 | Live mode is blocked until the exact URL is approved via checkbox and button | Browser (`ERROR: Live run blocked…`) |
| W12 | Live mode blocks identity tests with no credential configured | Code-read |
| W13 | Sequence tests execute each step in order, with per-step request, response and verdict | Sandbox log: step 1 `/orders/101`, step 2 `/orders/102` |
| W14 | **Credentials are kept out of the evidence package** | Grepped the exported evidence JSON for `tok-a`, `tok-b`, `tok-admin`: absent |
| W15 | A real BOLA on `GET /orders/{id}` was detected against the live local sandbox | Sandbox returned a foreign order; Part 2 flagged it |
| W16 | Evidence package download and copy; reproduction `curl` with placeholder auth | Browser |

---

## 3. Current mocked / simulated / hardcoded / UI-only features

| Feature | Classification | Detail |
|---|---|---|
| "Autonomous Lab" | **Mislabelled** | The planner is deterministic templates keyed on law category, as the README admits. There is no agent, no loop and no follow-up. |
| Mock Sandbox | **Simulated** | `mockRequest` fabricates 200 or 403 bodies from the model (`field_value` strings). In "vulnerable" mode every identity request succeeds. |
| Mock findings | **Fabrication risk** | Mock results become `status: "CONFIRMED"` findings at 98% or 85% confidence, marked only by `authScheme: "simulated-identity (mock)"` (verified). |
| Confidence scores | **Hardcoded** | Inference scores, law scores and finding confidence (98/85/70 mapped from law confidence) do not come from evidence. |
| Part 2 readiness % | **Hardcoded formula** | An arbitrary weighted formula. |
| `🟢 Authorized Sandbox` label (Part 1 Connect card) | **UI-only** | A static span that is always shown whether or not anything was authorized. |
| `AUTHORIZED SANDBOX ONLY` banner | **UI-only** | Nothing enforces it. `sandboxOnly: true` is a constant in the export. |
| "Production blocked" (Part 1 Test Connection) | **False claim** | The request is sent anyway (verified, BUG-12). |
| Resource keyword list | **Hardcoded demo domain** | `invoice, order, user, refund, payment, product, customer, account` in the engine. This contradicts the README's "zero instance data" claim for the core engine. |
| Classifier exceptions | **Hardcoded demo domain** | `n!=="customerid" && n!=="orderid"`. |
| Admin detection | **Hardcoded convention** | A role name containing "admin" plus a path prefix `/admin`. |
| LLM features | **Optional and display-only** | Reword and "ideas" call an OpenAI-compatible endpoint from the browser. Ideas are never executed. **Not verified: no key was available.** |
| Security Twin "graph" | **UI-only ASCII art** | The twin is a JSON object. The diagram is a fixed text template. |
| Constitution "executable test strategy" | **Prose only** | `law.tests` holds prose. Part 2 does not consume it (BUG-24). |
| Part 3 (remediation, reporting) | **Missing** | Only referenced in text. |

### Where runtime testing is fake, browser-only, simulated or hardcoded

1. `2-test-lab/app.js:170` `mockRequest`: fully simulated responses.
2. `2-test-lab/app.js:197` `liveRequest`: real, but **browser-only** (`fetch`, `mode: "cors"`). It needs the target to send CORS headers (my sandbox sent `Access-Control-Allow-Origin: *`). A normal API without CORS gives `Failed to fetch`, and cookie auth cannot work cross-origin.
3. `2-test-lab/app.js:211`: non-GET bodies are the hardcoded `{"id": <objectId|"1">}` regardless of schema (verified in the sandbox log).
4. `2-test-lab/app.js:141`: AUTHN cases fill every path with the literal `"1"`.
5. `2-test-lab/app.js:269` `confirm`: the "repeat" re-sends only the final request of a sequence.
6. `1-security-twin/app.js:498` `testSandbox`: browser GET to any URL. A CORS failure is reported as "unreachable".
7. `2-test-lab/app.js:350` `buildFindings`: confidence comes from law metadata, not from runtime.

---

## 4. Bugs and logical flaws

Severity: **C** = produces wrong security conclusions, **H** = major functional defect, **M** = incorrect but bounded, **L** = minor.

| ID | Sev | Status | Description | Location |
|---|---|---|---|---|
| BUG-01 | C | **Verified** | **HTTP 200 alone is treated as data exposure and BOLA.** A secure endpoint that soft-denies with `200 {"error":"forbidden"}` produced 3 "CONFIRMED" findings (BOLA, Sequence, Excessive Data Exposure). | `analyze` L256, `confirm` L278 |
| BUG-02 | C | **Verified** | **Any status outside {200, 201, 401, 403, 404} counts as a violation**, and the reason text is wrong ("expected ALLOW, got 400"). ADMIN and AUTHN results then pass `confirm` because they carry no ownership check. A `400` validation error produced 3 "CONFIRMED" findings (2× Broken Function-Level Authorization, 1× Authentication). 204, 3xx, 405 and 5xx behave the same way. | `analyze` L263, `confirm` L275 |
| BUG-03 | C | **Verified** | **A failed positive control is reported as a vulnerability.** The admin's own allowed request (T-014) returned 400 and was reported as "Broken Function-Level Authorization". | `analyze`, `buildFindings` |
| BUG-04 | C | **Verified** | **Sequence confirmation does not rerun the sequence.** The sandbox log shows `101 → 102 → 102`; only the last step was repeated. | `confirm` → `execTest(test)` L272 |
| BUG-05 | C | **Verified** | **Mock-mode findings are labelled `CONFIRMED` at 98% confidence** and exported as evidence. | `buildFindings` L357 |
| BUG-06 | H | Code-read | Finding confidence comes from the law's static confidence, not from evidence. | `buildFindings` L350 |
| BUG-07 | H | **Verified** | **No deduplication.** One real BOLA on `/orders/{id}` was reported 3 times (BOLA, SEQUENCE, DATA). AUTHN probes duplicate across LAW-001 and LAW-004. | `planTests`, `buildFindings` |
| BUG-08 | C | **Verified** | **The ownership map is global, not per resource.** Order IDs `101/102` were used against `GET /users/{id}`, which returned 404, so the users BOLA test "passed" without testing anything. | `planTests` L89, `sample-config.json` |
| BUG-09 | H | **Verified** | `fillPath` replaces only the first `{param}`: `/tenants/101/projects/{projectId}`. | Both `app.js` files |
| BUG-10 | H | **Verified** | Request bodies are not schema-driven: `POST /admin/refund` got `{"id":"1"}` instead of `{"orderId":…}`. | `liveRequest` L211 |
| BUG-11 | H | **Verified** | **Plan Tests silently overwrites the user-entered sandbox URL** with the model's `sandboxBaseUrl`. The approval widget then shows and approves that URL. During the audit this sent 22 live requests to `https://sandbox-api.example.com` (reserved, non-resolving; all failed) instead of the URL I had typed. It is a **target-confusion hazard**. | `loadModel` L55-56 vs `planBtn` handler L553 |
| BUG-12 | H | **Verified** | Part 1 "Test Connection" prints "production blocked" for a non-sandbox URL and **still sends the request**. | `testSandbox` L502-507 |
| BUG-13 | M | **Verified** | The `isSandboxLike` regex matches `contest-prod.com`, `latest.bank.com` and `example-payments.com`. It is only a hint in Part 2, but it is the only check in Part 1. | Both `app.js` files |
| BUG-14 | L | **Verified** | Part 1 warnings duplicate on each rebuild (1 → 3 after two "Apply config"). | `buildResources` L164 |
| BUG-15a | H | **Verified** | Parameter `$ref` is not resolved; the parameter name becomes `undefined`. | `parseSpec` L114 |
| BUG-15b | H | **Verified** | `responses.$ref`, `requestBody.$ref`, array responses (`items.$ref`) and inline body or response schemas all come out as `null`. | `parseSpec` L116-120 |
| BUG-15c | H | **Verified** | `security: [{}]` (anonymous allowed) is treated as auth-required. AND/OR semantics of security requirements are lost. | `authInfo` L87-93 |
| BUG-15d | H | **Verified** | `oneOf`/`anyOf` use only the first branch (`Dog.secretBone` missed). | `getSchemaProps` L70 |
| BUG-15e | H | **Verified** | Nested object and array fields are never classified (`owner.apiToken`, `members[].ssn` missed). | `buildResources` |
| BUG-15f | M | **Verified** | Swagger 2 body params are detected only if the *operation* declares `consumes`; global `consumes` is ignored. | `parseSpec` L117 |
| BUG-15g | M | **Verified** | YAML specs are rejected. | `build` |
| BUG-15h | M | Code-read | Path-level and operation-level params are concatenated without override or dedupe by `(name, in)`. Only the first request media type is read; content types are never recorded. Remote and relative `$ref` are unsupported. | `parseSpec` |
| BUG-16 | H | **Verified** | Resource inference: `/orders/{id}/invoice` maps to `Order`, so the `Invoice` resource ends up with no endpoints. `/tenants/{t}/projects/{p}` maps to `Tenant`. The keyword list is hardcoded. | `inferResource` L32-40 |
| BUG-17 | M | **Verified** | Classifier false positives: `customerId`, `username` and `filename` are marked PERSONAL. Because `customerId` is "PERSONAL", its mere presence counts as a "sensitive leak". | `classifyField` L49-55 |
| BUG-18 | H | Code-read | Response leak detection looks only at top-level keys and key names (not values, not null checks), matched against flagged names from **any** resource. | `analyze` L241-243 |
| BUG-19 | M | Code-read | The admin surface is detected only by role name `/admin/i` and path prefix `/admin`. | Part 1 L13-18, L42 |
| BUG-20 | M | Code-read | The DATA test's "foreign" object is chosen relative to `ownership[0]`, not to the actor. | `planTests` L129 |
| BUG-21 | M | Code-read | The BOLA baseline "own" object falls back to `ownership[0]` when the base identity owns nothing, so a "baseline" can target a foreign object. | `planTests` L89 |
| BUG-22 | M | **Verified** | AUTHN probes use the literal ID `"1"` (`/orders/1`), which returns 404 when the object doesn't exist and says nothing about auth. | `planTests` L141 |
| BUG-23 | L | Code-read | Part 1 cannot tell "CORS blocked" apart from "unreachable". | `testSandbox` |
| BUG-24 | H | Code-read | Part 2 ignores Part 1's per-law `tests` and `expectedBehavior`, so the constitution does not drive execution. | `planTests` |
| BUG-25 | L | Code-read | Readiness and inference scores are arbitrary constants. | Part 1 |
| BUG-26 | M | Code-read | ROLE-law permissions are free-text labels ("View Own Order") never bound to endpoints, so ROLE falls back to the admin endpoints. | Part 1 `privilegedActions`, Part 2 L145 |
| BUG-27 | L | Code-read | 204 counts as neither allow nor deny. `runOne` silently ignores clicks while a run is active. | `analyze`, `runOne` |

**Live-run scorecard against the local audit sandbox (verified):** 9 findings marked "CONFIRMED". **3 true positives**, which were **one** unique vulnerability reported three times. **6 false positives.** Precision by unique issue is 1 of 7 (about 14%).

---

## 5. Security risks

### 5.1 Security-sensitive code review

| Area | Current behaviour | Risk |
|---|---|---|
| **Credential handling** | Per-identity tokens live in `S.auth.creds` (browser memory). They are re-rendered into `<input type=password value="…">` attributes with an escaper that is not attribute-safe. The LLM API key sits in memory and is sent from the browser. Tokens are **excluded from evidence** (verified ✓). | Credentials are reachable by any script in the page, including the XSS in SEC-03. |
| **Target validation** | Part 1: **none**. Part 2: an exact-string match against a client-side approval list, which BUG-11 can pre-fill. Any URL can be approved, including production, and nothing records who approved it or when (lost on reload). There is no scheme, host or IP policy and no redirect policy (`fetch` follows redirects to any host by default). | Scope can expand without real authorization, and nothing server-side enforces the allowlist. |
| **Request execution** | Browser `fetch`. State-changing methods (`POST /admin/refund`, `POST /orders`) are sent with no destructive-operation policy. There is no global rate budget: `runAll` sleeps a fixed 120 ms, `runOne` has no delay, and confirmation doubles traffic. | Unintended state changes on the target; uncontrolled load. |
| **Response logging** | Full response bodies are stored in results and exported in `evidence-package.json` **without redaction**. My sandbox's fake payment token `tok_fake` appeared in the export (verified). | PII and secret leakage through the evidence artifacts. |
| **Secret leakage** | Request credentials are redacted (✓). Response secrets, `Set-Cookie` and tokens in bodies are not. The `curl` reproduction uses placeholders (✓). | As above. |
| **Unsafe command execution** | No `eval`, `Function`, `child_process` or shell. **But** `innerHTML` is used everywhere with `esc()`, which escapes only `&` and `<`, not `"`, `'` or `>`. | **Stored XSS** (SEC-03). |

### 5.2 Risk register

| ID | Sev | Status | Risk |
|---|---|---|---|
| SEC-01 | Critical | Verified | **Security tests run in the browser** against external targets. This violates the stated principle. It depends on the target's CORS configuration, keeps secrets in page memory, and cannot enforce policy. |
| SEC-02 | Critical | Verified | **No enforced target allowlist.** Part 1 fetches any URL; Part 2 has a client-side checkbox; BUG-11 can pre-fill the wrong target. |
| SEC-03 | High | **Verified (exploited in both parts)** | **Stored XSS.** Part 1: a spec property name with `"` injects `onfocus`, and it fired. Part 2: an imported model's `law.category` injects `<img onerror>`, it fired, and it had access to `S.auth.creds`. Model and spec files are shared artifacts, so this is a credential-exfiltration path. |
| SEC-04 | High | Verified | State-changing requests (POST admin refund, POST orders) are executed with no safety classification or opt-in. |
| SEC-05 | High | Verified | Response bodies are unredacted in UI, memory and exported evidence. |
| SEC-06 | Medium | Code-read | The LLM API key is in the browser, and the API model (endpoints, sensitive field names) is sent to an arbitrary user-supplied endpoint. There is no prompt-injection boundary on spec text sent to the LLM. |
| SEC-07 | Medium | Code-read | No rate or concurrency budget, no global kill switch. |
| SEC-08 | Medium | Code-read | No SSRF controls: redirects, private IP ranges, cloud metadata (`169.254.169.254`). This becomes critical once execution moves server-side unless it is designed in. |
| SEC-09 | Medium | Code-read | No authorization audit trail (who approved which target, when, with what scope). |
| SEC-10 | Low | Code-read | No Content-Security-Policy; inline event-handler injection is possible. |
| SEC-11 | Medium (process) | Verified | The project is not under version control, and the home-directory repository `C:\Users\mohit\.git` is corrupt and would, if repaired, cover the entire home folder. That risks lost work and accidentally committing personal files. |

---

## 6. PS requirement coverage matrix

Scoring: **1.0** real and verified · **0.75** mostly works with gaps · **0.5** partial · **0.25** heuristic, UI-only or simulated · **0** missing.

### A. OpenAPI / Swagger: 3.75 / 11 = **34%**
| Requirement | Score | Evidence |
|---|---|---|
| OpenAPI 3.x | 0.5 | JSON only; basic operations (W2); many gaps (BUG-15) |
| Swagger 2.0 | 0.5 | Basics work (W3); global `consumes` broken; `formData` ignored |
| `$ref` resolution | 0.25 | Schemas only; params, responses and requestBodies unresolved; no remote refs |
| allOf / oneOf / anyOf | 0.5 | allOf ✓; oneOf/anyOf first branch only |
| Nested schemas | 0 | Top-level only (verified) |
| Arrays | 0 | Array responses and items ignored (verified) |
| Request/response schemas | 0.25 | Only the `$ref` name captured; never used to generate requests or validate responses |
| Security inheritance | 0.5 | global → op ✓; `[{}]` wrong; AND/OR lost; scheme type unused |
| Operation-level overrides | 0.75 | Works, including `security: []` |
| Path/query/header params | 0.5 | Captured; `$ref` params broken; only the first path param is used at runtime |
| Content types | 0 | Not recorded |

### B. Security Twin: 4.25 / 10 = **42.5%**
| Requirement | Score | Evidence |
|---|---|---|
| Identities | 0.5 | Config-only; not verified against the runtime |
| Roles | 0.5 | Config-only; admin by name regex |
| Endpoints | 0.75 | Solid for simple specs |
| Actions | 0.5 | HTTP method → CRUD label |
| Resources | 0.5 | Keyword heuristic; wrong for nested paths |
| Objects | 0.25 | One global `objectId → owner` map across resources |
| Fields | 0.5 | Top-level only |
| Relationships | 0.25 | `$ref` property names only |
| Ownership | 0.25 | Name regex plus an asserted map; never observed at runtime |
| Trust boundaries | 0.25 | Only auth-required vs open |

### C. Security Constitution: 1.5 / 4 = **37.5%**
| Requirement | Score | Evidence |
|---|---|---|
| Machine-readable laws | 0.5 | JSON, but six fixed templates; invariants are display strings |
| Provenance | 0.5 | Source strings, not structured references |
| Confidence | 0.25 | Hardcoded |
| Executable test strategy | 0.25 | Prose Given/When/Expect, ignored by Part 2 |

### D. Runtime Sandbox: 2.6 / 9 = **29%**
| Requirement | Score | Evidence |
|---|---|---|
| Backend-side execution | 0 | None |
| Explicit target allowlisting | 0.25 | Client-side only; Part 1 bypasses it; BUG-11 |
| Multiple identities | 0.5 | Verified (W10) |
| Authentication injection | 0.5 | Bearer and API key verified; cookie cross-origin impossible; no login flows or token refresh |
| OpenAPI-driven request generation | 0 | Path substitution only; hardcoded body |
| Response capture | 0.5 | Status, content-type and body; no headers |
| Timeouts | 0.5 | 10 s client abort |
| Safe rate controls | 0.1 | Fixed 120 ms sleep in `runAll` only |
| Secret redaction | 0.25 | Request credentials ✓; responses ✗ |

### E. Vulnerability detection: 1.1 / 6 = **18%**
| Requirement | Score | Evidence |
|---|---|---|
| BOLA / IDOR | 0.5 | Real true positive (W15), but false-positive-prone and uses the global ownership map |
| Broken Function-Level Authorization | 0.25 | 400 treated as a violation (BUG-02, BUG-03) |
| Excessive data exposure | 0.1 | 200 counts as exposure; key names only (BUG-01, BUG-18) |
| Rate-limit weakness | 0 | None |
| Authentication / configuration issues | 0.25 | Anonymous probe only; false positive on 4xx/5xx; no header, CORS or TLS checks |
| Undocumented / shadow endpoints | 0 | None |

### F. Intelligence: 0.2 / 5 = **4%**
| Requirement | Score | Evidence |
|---|---|---|
| AI security-law inference | 0 | Templates only |
| AI test planning | 0.1 | LLM "ideas" are display-only |
| Semantic mutation | 0.1 | ID swap, auth strip, role swap only |
| Follow-up testing | 0 | None |
| Multi-step attack-path discovery | 0 | Fixed two-step own→foreign template |

### G. Evidence: 2.0 / 7 = **29%**
| Requirement | Score | Evidence |
|---|---|---|
| Request/response | 0.5 | No request or response headers; bodies unredacted |
| Expected vs observed | 0.5 | Present, with wrong reasons in the catch-all branch |
| Reproduction | 0.5 | `curl` present; sequences not reproducible as a unit |
| Repeated confirmation | 0.25 | Status-only repeat; sequence not rerun |
| Finding provenance | 0.25 | Law, test and `hypothesisSource` present; mock vs live not reflected in status |
| Evidence-backed confidence | 0 | Taken from law metadata |
| SUSPECTED / OBSERVED / CONFIRMED states | 0 | Only CONFIRMED exists |

### H. Remediation: 0.1 / 5 = **2%**
| Requirement | Score |
|---|---|
| Remediation guidance | 0 |
| Original-test preservation | 0.1 (tests serialized in evidence, not replayable) |
| Fix verification | 0 |
| Legitimate-flow regression testing | 0 |
| Before/after security state | 0 |

### I. Advanced: 0 / 8 = **0%**
Attack graph, observed blast radius, security drift, scan history, counterfactual fix simulation, CI/CD gate, security passport and natural-language command center: **all missing**.

### Totals
| Metric | Value |
|---|---|
| Item-weighted coverage | 15.5 / 65 = **23.8%** |
| Category-averaged coverage | (34 + 42.5 + 37.5 + 29 + 18 + 4 + 29 + 2 + 0) / 9 = **21.8%** |
| **Reported PS coverage** | **≈ 23%** |

---

## 7. Missing components

1. **Backend API service**: projects, scans, targets, credentials and results, with persistence.
2. **Runtime worker / executor**: the only component allowed to talk to targets. Allowlist, SSRF guard, rate and concurrency budget, timeouts, redirect policy, method policy, redaction.
3. **Target authorization registry**: explicit, scoped, expiring and audited authorization records.
4. **Credential vault**: encrypted at rest, referenced by ID, never returned to clients, redaction dictionary.
5. **Robust OpenAPI normalizer**: full dereferencing (local and remote), YAML, composition, nested and array schemas, security requirement semantics, content types, parameter merge.
6. **Schema-driven request generator**: valid bodies, query and headers for each operation, plus mutation operators.
7. **Twin v2**: a graph of identities, roles, resources, objects, fields and relationships, with ownership **observed at runtime** and trust boundaries.
8. **Constitution v2**: structured, executable laws (typed oracle plus test template) with provenance and confidence that the executor consumes directly.
9. **Differential oracles** per vulnerability class, with positive and negative controls, and outcomes limited to INCONCLUSIVE, PASS, OBSERVED or CONFIRMED.
10. **Finding state machine and dedupe**: SUSPECTED → OBSERVED → CONFIRMED / REJECTED / INCONCLUSIVE; SIMULATED can never be confirmed.
11. **Evidence store**: full redacted request and response with headers, content hashes, replay bundles, sequence bundles.
12. **AI security agent**: law inference, test planning, semantic mutation, follow-ups, with schema-validated output, bounded loops, and hypotheses only.
13. **Rate-limit, auth/config and shadow-endpoint probes** (bounded, opt-in).
14. **Attack-path engine and observed blast radius.**
15. **Remediation, fix verification and regression engine.**
16. **Scan history, drift, passport signing, CI gate CLI.**
17. **Natural-language command center** mapped onto the same guarded commands.
18. **Demo sandbox application**: vulnerable and fixed modes, kept separate from the core engine.
19. **Test suite, CI, lint, typecheck, version control.**
20. **Part 3** (reporting and remediation), which is referenced but absent.

---

## 8. Proposed migration order

1. **Stabilize the workspace.** Create a project-local git repository, a monorepo scaffold and CI. Freeze today's behaviour with a **golden parity test** (Part 1 demo output hash `0e7d368e005fddc4`) so the port can be checked for regressions.
2. **Move execution server-side first.** Before adding detection features, build the executor, allowlist, vault and redaction. **Disable browser live mode** once the backend path exists (SEC-01, SEC-02).
3. **Port Part 1 pure logic** into a typed `core` package and fix the parser (BUG-15, BUG-16) behind the parity test, updating the golden file deliberately and recording each diff.
4. **Rebuild the analyzer as oracles plus a state machine.** This fixes BUG-01 to BUG-08, and SIMULATED can no longer be confirmed.
5. **Schema-driven request generation, runtime ownership discovery and Twin v2.**
6. **AI layer** (hypotheses only), then **remediation and verification**, then **advanced features**.
7. **Replace both static UIs** with one web app that talks only to the backend. Fix XSS by construction: framework escaping plus CSP.

---

## 9. Recommended implementation phases (summary)

| Phase | Name | Exit criterion |
|---|---|---|
| **P1** | **Foundation and Safe Runtime Spine** | Backend executes an authorized scan against the demo sandbox. Non-allowlisted hosts are refused. Secrets never appear in logs, DB or evidence. Parity test green. |
| P2 | Spec depth, Twin v2 and request generation | All BUG-15 and BUG-16 cases pass; valid request bodies for every operation in the fixtures |
| P3 | Oracles, evidence and the finding state machine | Demo sandbox: exact expected finding set; **0 false positives** on the trap endpoints (soft-deny 200, validation 400) |
| P4 | AI security agent | AI output schema-validated; AI-only hypotheses can never reach CONFIRMED |
| P5 | Remediation, fix verification and regression | Fixed-mode sandbox: original exploit denied **and** positive controls pass → VERIFIED_FIXED |
| P6 | Attack paths, blast radius, history, drift, passport, CI gate | CI CLI exits non-zero on a confirmed High; signed passport verifies |
| P7 | Unified UI, NL command center, demo hardening | Playwright end-to-end passes; security review of the final diff |

Details, hour budgets and cut lines are in `docs/FULL_IMPLEMENTATION_PLAN.md`.

---

## 10. Verification strategy

- **Parity:** a golden test locks the current Part 1 output before refactoring. Any change to the golden file must be intentional and listed in the PR.
- **Unit:** normalizer, twin, constitution, oracles, state machine and redaction are pure functions with table-driven tests, including every BUG-xx reproduction from this audit.
- **Spec corpus:** Petstore v2 and v3, the demo spec, the edge-case spec used in this audit (param/response/requestBody `$ref`, `security: [{}]`, oneOf, nested, arrays, multi-param paths), plus YAML variants.
- **Integration against the demo sandbox** (vulnerable and fixed modes) with an exact expected findings manifest, including the audit's **trap endpoints**:
  - soft-deny `200 {"error":…}` must not produce a finding;
  - validation-before-auth `400` must be INCONCLUSIVE, not a violation;
  - a failed positive control must be INCONCLUSIVE, not a vulnerability;
  - a real BOLA must be CONFIRMED exactly once.
- **Safety tests (must never regress):** executor refuses non-allowlisted hosts, off-allowlist redirects, private or metadata IPs not explicitly registered, disallowed methods, budget overrun, expired authorization. DNS-rebinding test.
- **Secret-leak tests:** seed known secret values, run a full scan, then grep logs, DB, evidence, UI responses and passport for them. They must be absent.
- **No-fabrication tests:** the mock or simulated executor can never produce OBSERVED or CONFIRMED. AI hypotheses without runtime evidence stay SUSPECTED. A sequence finding's confirmation log must show the full step list executed again.
- **XSS regression:** replay the two payloads that worked in this audit. They must render inert.
- **End-to-end:** Playwright drives upload → authorize → scan → findings → fix verify → passport.
- **CI:** typecheck, lint, unit, integration (sandbox in a container) and the safety suite on every PR.

All audit checks and planned suites are tracked in `tests.json`.
