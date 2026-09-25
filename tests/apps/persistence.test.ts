// Opt-in persistence in the real Step 1 bundle: nothing is stored unless the user ticks "Remember", a later visit
// restores the inputs (including sensitivity overrides), and clearing forgets everything.
import { afterEach, describe, expect, it } from "vitest";
import { loadApp, type LoadedApp } from "../../scripts/app-harness.mjs";

let app: LoadedApp | undefined;
afterEach(() => {
  app?.close();
  app = undefined;
});

const KEY = "sentinel-x:step1:workspace:v1";
const snapshot = (a: LoadedApp) => Object.fromEntries(Object.keys(a.window.localStorage).map((k) => [k, a.window.localStorage.getItem(k)!]));
const tick = (a: LoadedApp, checked: boolean) => {
  const box = a.$("rememberChk") as unknown as HTMLInputElement;
  box.checked = checked;
  box.dispatchEvent(new a.window.Event("change"));
};
async function builtDemo(a: LoadedApp) {
  a.click("demoBtn");
  await a.settle();
  a.click("buildBtn");
  await a.settle();
}

describe("Step 1 persistence", () => {
  it("stores nothing unless the user opts in", async () => {
    app = await loadApp("1-security-twin");
    await builtDemo(app);
    expect(snapshot(app)).toEqual({});
    expect((app.$("rememberChk") as unknown as HTMLInputElement).checked).toBe(false);
  });

  it("saves on opt-in and after each rebuild, and a later visit restores the inputs and overrides", async () => {
    app = await loadApp("1-security-twin");
    await builtDemo(app);
    tick(app, true);
    expect(app.$("persistStatus").textContent).toMatch(/Saved in this browser at /);
    // an analyst override is part of the saved workspace
    const select = [...app.document.querySelectorAll<HTMLSelectElement>("#sensTable select")].find((s) => s.dataset.f === "phone" && s.dataset.r === "User")!;
    select.value = "PERSONAL";
    app.click("applySens");
    const saved = snapshot(app);
    const inputs = { spec: app.$("swaggerText").value, ids: app.$("identitiesEditor").value, url: app.$("baseUrl").value };
    expect(JSON.parse(saved[KEY]!).overrides).toEqual({ "User.phone": "PERSONAL" });
    app.close();

    app = await loadApp("1-security-twin", { beforeRun: (w) => Object.entries(saved).forEach(([k, v]) => w.localStorage.setItem(k, v)) });
    expect((app.$("rememberChk") as unknown as HTMLInputElement).checked).toBe(true);
    expect(app.$("persistStatus").textContent).toMatch(/Restored the spec and configuration saved in this browser at .* Next: Build Security Twin./);
    expect(app.$("swaggerText").value).toBe(inputs.spec);
    expect(app.$("identitiesEditor").value).toBe(inputs.ids);
    expect(app.$("baseUrl").value).toBe(inputs.url);
    expect(app.$("targetAuthState").dataset.state).toBe("CONFIGURED");
    app.click("buildBtn");
    await app.settle();
    // the restored override applies: the analyst-confirmed signal raises INF-03
    const inf03 = [...app.document.querySelectorAll("#inferences .law")].find((d) => d.querySelector("h3")!.textContent!.startsWith("INF-03"))!;
    expect(inf03.textContent).toMatch(/HIGH · 100% of signals/);
  });

  it("unticking or Clear saved data forgets everything", async () => {
    app = await loadApp("1-security-twin");
    await builtDemo(app);
    tick(app, true);
    expect(Object.keys(snapshot(app))).toHaveLength(2);
    tick(app, false);
    expect(snapshot(app)).toEqual({});
    expect(app.$("persistStatus").textContent).toMatch(/Saved data removed/);
    tick(app, true);
    app.click("clearSaved");
    expect(snapshot(app)).toEqual({});
    expect((app.$("rememberChk") as unknown as HTMLInputElement).checked).toBe(false);
  });

  it("removes unreadable saved data instead of restoring it", async () => {
    app = await loadApp("1-security-twin", {
      beforeRun: (w) => {
        w.localStorage.setItem(KEY, "{broken");
        w.localStorage.setItem(`${KEY}:remember`, "1");
      },
    });
    expect(app.$("persistStatus").dataset.status).toBe("error");
    expect(app.$("persistStatus").textContent).toMatch(/could not be read and was removed/);
    expect(snapshot(app)).toEqual({});
    expect(app.$("swaggerText").value).toBe("");
  });

  it("Step 2 stores nothing in the browser (targets and credentials stay in memory)", async () => {
    app = await loadApp("2-test-lab");
    app.click("demoModelBtn");
    await app.settle();
    app.click("planBtn");
    expect(snapshot(app)).toEqual({});
  });
});
