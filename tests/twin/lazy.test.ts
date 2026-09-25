import { describe, expect, it } from "vitest";
import { JSDOM } from "jsdom";
import { createLazyTwinView } from "../../src/twin/lazy";
import type { TwinGraphInput } from "../../src/twin/graph";

function fakeModule() {
  const calls: string[] = [];
  const mod = {
    mountSecurityTwinGraph: (el: HTMLElement) => {
      calls.push("mount");
      el.textContent = "graph";
      return {
        render: (input: TwinGraphInput | null) => calls.push(`render:${input ? "model" : "null"}`),
        focusLaw: (id: string) => calls.push(`focus:${id}`),
        unmount: () => calls.push("unmount"),
      };
    },
  };
  return { calls, mod: mod as never };
}
const el = () => new JSDOM("<div id=g></div>").window.document.getElementById("g")!;
const input = {} as TwinGraphInput;

describe("createLazyTwinView", () => {
  it("does not load the graph code until it is needed", () => {
    let loads = 0;
    const view = createLazyTwinView(el(), async () => (loads++, fakeModule().mod));
    expect(view.state).toBe("idle");
    expect(loads).toBe(0);
  });

  it("shows a loading status, then replays the latest render and focus once loaded", async () => {
    const { calls, mod } = fakeModule();
    let loads = 0;
    const host = el();
    const view = createLazyTwinView(host, async () => (loads++, mod));
    view.render(null);
    view.render(input);
    view.focusLaw("LAW-003");
    expect(view.state).toBe("loading");
    expect(host.querySelector('[role="status"]')!.textContent).toMatch(/Loading Security Twin graph/);
    await view.whenReady();
    expect(loads).toBe(1);
    expect(view.state).toBe("ready");
    expect(calls).toEqual(["mount", "render:model", "focus:LAW-003"]);
    // After loading, calls go straight through.
    view.focusLaw("LAW-001");
    expect(calls.at(-1)).toBe("focus:LAW-001");
  });

  it("a new render clears a focus queued for the previous input", async () => {
    const { calls, mod } = fakeModule();
    const view = createLazyTwinView(el(), async () => mod);
    view.render(input);
    view.focusLaw("LAW-003");
    view.render(input);
    await view.whenReady();
    expect(calls).toEqual(["mount", "render:model"]);
  });

  it("reports a load failure with a retry button, and retry recovers", async () => {
    const { calls, mod } = fakeModule();
    let fail = true;
    const host = el();
    const view = createLazyTwinView(host, async () => {
      if (fail) throw new Error("chunk missing");
      return mod;
    });
    view.render(input);
    await expect(view.whenReady()).rejects.toThrow("chunk missing");
    expect(view.state).toBe("error");
    expect(host.querySelector('[role="alert"]')!.textContent).toMatch(/Could not load the Security Twin graph \(chunk missing\)/);
    fail = false;
    host.querySelector("button")!.click();
    await view.whenReady();
    expect(view.state).toBe("ready");
    expect(calls).toEqual(["mount", "render:model"]);
    expect(host.textContent).toBe("graph");
  });
});
