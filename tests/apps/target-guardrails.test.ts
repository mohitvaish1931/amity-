// Step 2 target guardrails in the real bundle: only registrable hosts can become targets, registration is explicit,
// the displayed target is the one used, and live requests stay inside it. No request leaves the test process:
// fetch is replaced by a recorder that simulates an unreachable sandbox.
import { afterEach, describe, expect, it } from "vitest";
import { loadApp, type LoadedApp } from "../../scripts/app-harness.mjs";
import { readRepoFile } from "../helpers";

let app: LoadedApp | undefined;
afterEach(() => {
  app?.close();
  app = undefined;
});

const typeUrl = (a: LoadedApp, value: string) => {
  a.setValue("sandboxUrl", value);
  a.$("sandboxUrl").dispatchEvent(new a.window.Event("input"));
};
const bar = (a: LoadedApp) => a.$("targetBar").textContent!.replace(/\s+/g, " ");

async function planned(mode: "mock" | "live") {
  const a = await loadApp("2-test-lab");
  a.click("demoModelBtn");
  await a.settle();
  (a.$("execMode") as unknown as HTMLSelectElement).value = mode;
  a.click("planBtn");
  return a;
}

function register(a: LoadedApp, url: string) {
  typeUrl(a, url);
  (a.$("approveChk") as unknown as HTMLInputElement).checked = true;
  a.click("approveBtn");
}

/** Records every request the app attempts and fails it like an unreachable sandbox. */
function recordFetch(a: LoadedApp) {
  const calls: { url: string; init: RequestInit }[] = [];
  a.window.fetch = (async (url: string, init: RequestInit) => {
    calls.push({ url: String(url), init });
    throw new TypeError("Failed to fetch (sandbox unavailable)");
  }) as typeof fetch;
  return calls;
}

describe("Step 2 target status bar", () => {
  it("shows target, environment, mode and run state, and never claims verified authorization", async () => {
    app = await loadApp("2-test-lab");
    expect(bar(app)).toMatch(/TARGET none/);
    expect(bar(app)).toMatch(/NOT REGISTERED/);
    expect(bar(app)).toMatch(/MODE Mock \(simulated, vulnerable\)/);
    expect(bar(app)).toMatch(/RUN no tests planned/);
    app.close();
    app = await planned("mock");
    expect(bar(app)).toMatch(/RUN 0\/22 tests run/);
    register(app, "http://127.0.0.1:9000");
    expect(bar(app)).toMatch(/TARGET http:\/\/127\.0\.0\.1:9000 SANDBOX · AUTHORIZED BY CONFIGURATION \(not independently verified\)/);
    expect(app.document.body.textContent).not.toMatch(/Authorization confirmed|authorization verified/i);
  });
});

describe("Step 2 run state", () => {
  it("shows the finished state and re-enables RUN ALL when a run completes", async () => {
    app = await planned("mock");
    app.click("runAllBtn");
    await app.waitFor(() => /RUN running \(/.test(bar(app!)));
    await app.waitFor(() => app!.document.querySelectorAll("#findings .test").length > 0, { timeout: 15000 });
    await app.waitFor(() => !(app!.$("runAllBtn") as unknown as HTMLButtonElement).disabled, { timeout: 2000 });
    expect(bar(app)).toMatch(/RUN 22\/22 tests run/);
  });
});

describe("Step 2 target registration", () => {
  it.each([
    ["https://api.github.com", /Public internet host/],
    ["https://sandbox-api.example.com", /Public internet host/],
    ["http://169.254.169.254", /metadata/],
    ["http://0.0.0.0:8080", /Unspecified address/],
    ["ftp://127.0.0.1", /Not a valid http\(s\) URL/],
    ["http://127.0.0.1:9000/?next=x", /query or fragment/],
  ])("refuses %s and offers no way to register it", async (url, reason) => {
    app = await planned("live");
    typeUrl(app, url);
    expect(app.document.querySelector('[data-testid="target-refused"]')!.textContent).toMatch(reason);
    expect(app.$("approveBtn")).toBeNull();
    expect(bar(app)).toMatch(/NOT REGISTERED/);
  });

  it("requires the explicit confirmation before registering", async () => {
    app = await planned("live");
    typeUrl(app, "http://localhost:4010");
    app.click("approveBtn");
    expect(app.$("targetStatus").textContent).toMatch(/Tick the confirmation checkbox first/);
    expect(app.$("targetStatus").getAttribute("role")).toBe("alert");
    expect(app.document.querySelector('[data-testid="target-registered"]')).toBeNull();
    (app.$("approveChk") as unknown as HTMLInputElement).checked = true;
    app.click("approveBtn");
    expect(app.document.querySelector('[data-testid="target-registered"]')!.textContent).toMatch(
      /Registered sandbox target TGT-1: http:\/\/localhost:4010 · authorized by configuration \(your statement, not independently verified\)/,
    );
  });

  it("a registration applies to that exact URL only", async () => {
    app = await planned("live");
    register(app, "http://127.0.0.1:9000");
    typeUrl(app, "http://127.0.0.1:9001");
    expect(bar(app)).toMatch(/TARGET http:\/\/127\.0\.0\.1:9001 NOT REGISTERED/);
    expect(app.document.querySelector('[data-testid="target-registered"]')).toBeNull();
  });
});

describe("Step 2 live execution guard", () => {
  // Preflight: the whole run is refused before any case starts, with the reason next to the Run button.
  it("blocks live runs against an unregistered URL without sending anything", async () => {
    app = await planned("live");
    const calls = recordFetch(app);
    typeUrl(app, "https://api.github.com");
    app.click("runAllBtn");
    await app.settle();
    expect(calls).toEqual([]);
    expect(app.$("runStatus").textContent).toMatch(/Live run blocked: https:\/\/api\.github\.com is not a registered target.*Nothing was sent/);
    expect(app.$("runStatus").getAttribute("role")).toBe("alert");
    expect(bar(app)).toMatch(/RUN 0\/22 tests run/);
    expect(app.$("results").textContent).not.toMatch(/CONFIRMED|VIOLATION/);
    expect(app.document.querySelectorAll("#findings .test")).toHaveLength(0);
  });

  it("blocks a live run with an empty target URL and says so", async () => {
    app = await loadApp("2-test-lab");
    const calls = recordFetch(app);
    const m = JSON.parse(readRepoFile("2-test-lab/samples/sample-testable-model.json"));
    delete m.sandboxBaseUrl; // no model suggestion, so the field stays empty
    app.setValue("modelText", JSON.stringify(m));
    (app.$("execMode") as unknown as HTMLSelectElement).value = "live";
    app.$("execMode").dispatchEvent(new app.window.Event("change"));
    app.click("planBtn");
    expect(app.$("sandboxUrl").value).toBe("");
    expect(app.$("modelStatus").textContent).toMatch(/names no sandbox URL/);
    app.click("runAllBtn");
    await app.settle();
    expect(calls).toEqual([]);
    expect(app.$("runStatus").textContent).toMatch(/enter the sandbox base URL/);
    expect(bar(app)).toMatch(/TARGET none/);
  });

  it("says where a model-suggested target URL came from, and never replaces a typed one", async () => {
    app = await loadApp("2-test-lab");
    app.click("demoModelBtn");
    await app.settle();
    app.click("planBtn");
    expect(app.$("modelStatus").textContent).toMatch(/Target URL taken from the model/);
    app.close();
    app = await loadApp("2-test-lab");
    typeUrl(app, "http://127.0.0.1:9000");
    app.click("demoModelBtn");
    await app.settle();
    app.click("planBtn");
    expect(app.$("sandboxUrl").value).toBe("http://127.0.0.1:9000");
    expect(app.$("modelStatus").textContent).not.toMatch(/taken from the model/);
  });

  it("locks the target and mode while a run is in progress", async () => {
    app = await planned("live");
    register(app, "http://127.0.0.1:9000");
    recordFetch(app);
    app.click("runAllBtn");
    await app.waitFor(() => /RUN running \(/.test(bar(app!)));
    for (const id of ["sandboxUrl", "execMode", "mockMode", "planBtn"]) expect((app.$(id) as unknown as HTMLInputElement).disabled).toBe(true);
    await app.waitFor(() => bar(app!).includes("22/22 tests run"), { timeout: 15000 });
    await app.waitFor(() => !(app!.$("sandboxUrl") as unknown as HTMLInputElement).disabled);
  });

  it("shows the normalized base URL a live request uses, and flags results from a different target", async () => {
    app = await planned("live");
    register(app, "http://127.0.0.1:9000/");
    expect(app.document.querySelector('[data-testid="target-url"]')!.textContent).toBe("http://127.0.0.1:9000");
    const calls = recordFetch(app);
    app.click("runAllBtn");
    await app.waitFor(() => bar(app!).includes("22/22 tests run"), { timeout: 15000 });
    expect(calls.every((c) => c.url.startsWith("http://127.0.0.1:9000/"))).toBe(true);
    typeUrl(app, "http://127.0.0.1:9001");
    expect(app.document.querySelector('[data-testid="results-target"]')!.textContent).toMatch(/results below came from http:\/\/127\.0\.0\.1:9000/);
  });
});

describe("Step 2 simulated results", () => {
  it("never present a mock response as a request to the sandbox URL, and carry no timing", async () => {
    app = await planned("mock");
    const calls = recordFetch(app);
    app.click("runAllBtn");
    await app.waitFor(() => bar(app!).includes("22/22 tests run"), { timeout: 15000 });
    expect(calls).toEqual([]);
    const results = app.$("results").textContent!;
    expect(results).toMatch(/\(simulated, no request sent\)/);
    expect(results).toMatch(/simulated response/);
    expect(results).not.toMatch(/sandbox-api\.example\.com/);
    expect(results).not.toMatch(/\d+ms\)/);
  });

  it("findings never invent a severity, and reproduction steps point at a placeholder, not an unused URL", async () => {
    app = await loadApp("2-test-lab");
    const m = JSON.parse(readRepoFile("2-test-lab/samples/sample-testable-model.json"));
    for (const l of m.laws) delete l.severity;
    app.setValue("modelText", JSON.stringify(m));
    app.click("planBtn");
    app.click("runAllBtn");
    await app.waitFor(() => bar(app!).includes("22/22 tests run"), { timeout: 15000 });
    await app.waitFor(() => app!.$("evidenceOut").textContent !== "—");
    const pkg = JSON.parse(app.$("evidenceOut").textContent!);
    expect(pkg.findings.length).toBeGreaterThan(0);
    for (const f of pkg.findings) {
      expect(f.severity).toBe("UNRATED");
      expect(f.status).toBe("SIMULATED");
      expect(f.reproduction.curl).toContain("<registered-sandbox-url>");
      expect(f.reproduction.curl).not.toContain("sandbox-api.example.com");
      // A placeholder header named after the identity, not the inspector's explanatory sentence.
      expect(f.reproduction.curl).toContain(`-H "Authorization: Bearer <token-for-${f.identity}>"`);
      expect(f.reproduction.curl).not.toMatch(/no credential configured/);
    }
    expect(pkg.run).toMatchObject({ mode: "mock", executedAgainst: "simulated (mock, no request sent)" });
  });

  it("sends live requests only inside the registered target, refuses redirects, and reports an unreachable sandbox as an error", async () => {
    app = await planned("live");
    register(app, "http://127.0.0.1:9000");
    const calls = recordFetch(app);
    app.click("runAllBtn");
    await app.waitFor(() => bar(app!).includes("22/22 tests run"), { timeout: 15000 });
    expect(calls.length).toBeGreaterThan(0);
    for (const c of calls) {
      expect(new URL(c.url).origin).toBe("http://127.0.0.1:9000");
      expect(c.init.redirect).toBe("error");
    }
    // Nothing was observed, so nothing may be reported as a violation or finding.
    expect(app.$("results").textContent).toMatch(/Failed to fetch \(sandbox unavailable\)/);
    expect(app.$("results").textContent).not.toMatch(/VIOLATION|CONFIRMED/);
    expect(app.document.querySelectorAll("#findings .test")).toHaveLength(0);
  });
});

describe("Step 1 connection check", () => {
  const setUrl = (a: LoadedApp, v: string) => {
    a.setValue("baseUrl", v);
    a.$("baseUrl").dispatchEvent(new a.window.Event("input"));
  };

  it("refuses non-registrable hosts without sending a request", async () => {
    app = await loadApp("1-security-twin");
    const calls = recordFetch(app);
    for (const [url, reason] of [["https://api.github.com", /Public internet host/], ["http://169.254.169.254", /metadata/]] as const) {
      setUrl(app, url);
      app.click("testBtn");
      await app.settle();
      expect(app.document.querySelector('[data-testid="connection-refused"]')!.textContent).toMatch(reason);
    }
    expect(calls).toEqual([]);
  });

  it("sends one credential-less GET to an allowed host, refuses redirects, and offers a retry when unreachable", async () => {
    app = await loadApp("1-security-twin");
    const calls = recordFetch(app);
    setUrl(app, "http://127.0.0.1:9000/");
    app.click("testBtn");
    await app.waitFor(() => !!app!.$("retryConn"));
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ url: "http://127.0.0.1:9000", init: { method: "GET", credentials: "omit", redirect: "error" } });
    expect(app.$("sandboxStatus").textContent).toMatch(/Unreachable, redirected or blocked by CORS/);
    app.click("retryConn");
    await app.settle();
    expect(calls).toHaveLength(2);
  });
});
