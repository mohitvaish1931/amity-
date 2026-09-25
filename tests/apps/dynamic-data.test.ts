// Guards against hardcoded values: Step 1 inferences/readiness must follow the data, and Step 2 must never
// present simulated (mock) output as confirmed or with fabricated confidence percentages.
import { afterEach, describe, expect, it } from "vitest";
import { loadApp, type LoadedApp } from "../../scripts/app-harness.mjs";
import { readRepoFile } from "../helpers";

let app: LoadedApp | undefined;
afterEach(() => {
  app?.close();
  app = undefined;
});

async function buildWith(mutate?: (cfg: { identities: { id: string; name: string; role: string }[]; permissions: Record<string, unknown>; ownership: Record<string, string> }) => void) {
  const a = await loadApp("1-security-twin");
  a.click("demoBtn");
  await a.settle();
  if (mutate) {
    const cfg = {
      identities: JSON.parse(a.$("identitiesEditor").value),
      permissions: JSON.parse(a.$("permissionsEditor").value),
      ownership: JSON.parse(a.$("ownershipEditor").value),
    };
    mutate(cfg);
    a.setValue("identitiesEditor", JSON.stringify(cfg.identities));
    a.setValue("permissionsEditor", JSON.stringify(cfg.permissions));
    a.setValue("ownershipEditor", JSON.stringify(cfg.ownership));
  }
  a.click("buildBtn");
  await a.settle();
  return a;
}
const inference = (a: LoadedApp, id: string) =>
  [...a.document.querySelectorAll("#inferences .law")].find((d) => d.querySelector("h3")!.textContent!.startsWith(id))!;

describe("Step 1 values are derived from the model and configuration", () => {
  it("inference confidence follows the evidence signals", async () => {
    app = await buildWith();
    expect(inference(app, "INF-01").textContent).toMatch(/HIGH · 100% of signals/);
    app.close();
    app = await buildWith((c) => (c.ownership = {}));
    const inf = inference(app, "INF-01").textContent!;
    expect(inf).toMatch(/MEDIUM · 67% of signals/);
    expect(inf).toMatch(/❌ 0 configured owner identities/);
  });

  it("an analyst override raises the sensitive-field inference", async () => {
    app = await buildWith();
    expect(inference(app, "INF-03").textContent).toMatch(/MEDIUM/);
    const select = [...app.document.querySelectorAll<HTMLSelectElement>("#sensTable select")].find((s) => s.dataset.f === "phone" && s.dataset.r === "User")!;
    select.value = "PERSONAL";
    app.click("applySens");
    expect(inference(app, "INF-03").textContent).toMatch(/HIGH · 100% of signals/);
  });

  it("readiness is an explainable checklist that reacts to the configuration", async () => {
    app = await buildWith();
    expect(app.$("dashboard").textContent).toMatch(/6\/6 checks \(100%\)/);
    app.close();
    app = await buildWith((c) => (c.identities = c.identities.filter((i) => !/admin/i.test(i.role))));
    const checks = app.document.querySelector('[data-testid="readiness-checks"]')!.textContent!;
    expect(app.$("dashboard").textContent).toMatch(/5\/6 checks \(83%\)/);
    expect(checks).toMatch(/❌ A privileged role exists for administrative endpoints \(none configured\)/);
  });

  it("has no built-in scores, fallback identities or default target URL in the source", () => {
    const src = readRepoFile("1-security-twin/app.js");
    expect(src).not.toMatch(/score: ?\d/);
    expect(src).not.toMatch(/actor_1|role_1/);
    expect(src).not.toMatch(/sandbox-api\.example\.com/);
    expect(readRepoFile("1-security-twin/index.html")).not.toMatch(/id="baseUrl" value=/);
  });
});

describe("Step 2 never presents simulated output as confirmed", () => {
  it("labels mock-mode findings and results SIMULATED, with the law's confidence level and no percentages", async () => {
    app = await loadApp("2-test-lab");
    app.click("demoModelBtn");
    await app.settle();
    (app.$("execMode") as unknown as HTMLSelectElement).value = "mock";
    (app.$("mockMode") as unknown as HTMLSelectElement).value = "vulnerable";
    app.click("planBtn");
    app.click("runAllBtn");
    await app.waitFor(() => app!.document.querySelectorAll("#findings .test").length > 0, { timeout: 15000 });
    const findings = app.$("findings").textContent!;
    expect(findings).toMatch(/SIMULATED/);
    expect(findings).not.toMatch(/CONFIRMED/);
    expect(findings).not.toMatch(/\d+%/);
    expect(findings).toMatch(/law confidence (HIGH|MEDIUM|LOW)/);
    expect(app.$("results").querySelectorAll(".badge.b-SIMULATED").length).toBeGreaterThan(0);
    const evidence = JSON.parse(app.$("evidenceOut").textContent!);
    expect(evidence.findings.every((f: { status: string; simulated: boolean }) => f.status === "SIMULATED" && f.simulated)).toBe(true);
  }, 20000);

  it("never replaces the sandbox URL the user entered with the model's (audit BUG-11)", async () => {
    const modelUrl = JSON.parse(readRepoFile("2-test-lab/samples/sample-testable-model.json")).sandboxBaseUrl;
    app = await loadApp("2-test-lab");
    app.click("demoModelBtn");
    await app.settle();
    // Empty field: planning fills in the model's suggestion, visibly.
    app.click("planBtn");
    expect(app.$("sandboxUrl").value).toBe(modelUrl);
    // A URL the user typed survives re-planning and is the one previewed.
    app.setValue("sandboxUrl", "http://127.0.0.1:9000");
    app.click("planBtn");
    expect(app.$("sandboxUrl").value).toBe("http://127.0.0.1:9000");
    expect(app.$("preview").textContent).toContain("http://127.0.0.1:9000/");
    expect(app.$("preview").textContent).not.toContain(modelUrl);
  });

  it("shows each planned hypothesis as text, never as [object Object]", async () => {
    app = await loadApp("2-test-lab");
    app.click("demoModelBtn");
    await app.settle();
    app.click("planBtn");
    expect(app.$("tests").textContent).not.toContain("[object Object]");
    expect(app.$("preview").textContent).not.toContain("[object Object]");
    expect(app.$("preview").textContent).toMatch(/Hypothesis \(heuristic planner\): \S+/);
  });

  it("the reasoning trail of a mock run never claims a confirmation", async () => {
    app = await loadApp("2-test-lab");
    app.click("demoModelBtn");
    await app.settle();
    app.click("planBtn");
    app.click("runAllBtn");
    await app.waitFor(() => app!.document.querySelectorAll("#findings .test").length > 0, { timeout: 15000 });
    const results = app.$("results").textContent!;
    expect(results).toMatch(/SIMULATED \(a live sandbox run would be needed to confirm\)/);
    expect(results).not.toMatch(/→ CONFIRMED|sensitive data confirmed/);
    expect(results).toMatch(/sensitive fields present in the simulated response/);
  }, 20000);

  it("requires an explicit LLM model instead of a built-in default", async () => {
    app = await loadApp("2-test-lab");
    expect(app.$("llmModel").value).toBe("");
    const src = readRepoFile("2-test-lab/app.js");
    expect(src).not.toMatch(/gpt-4o-mini/);
    expect(src).not.toMatch(/\?98:|\?85:/);
  });
});
