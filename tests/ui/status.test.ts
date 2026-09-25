import { describe, expect, it } from "vitest";
import { JSDOM } from "jsdom";
import { clearStatus, copyText, fetchText, showStatus } from "../../src/ui/status";

const el = () => new JSDOM("<div id=s></div>").window.document.getElementById("s")!;

describe("showStatus", () => {
  it("announces errors assertively and everything else politely", () => {
    const s = el();
    showStatus(s, "error", "Broken");
    expect([s.getAttribute("role"), s.getAttribute("aria-live"), s.dataset.status]).toEqual(["alert", "assertive", "error"]);
    showStatus(s, "loading", "Working");
    expect([s.getAttribute("role"), s.getAttribute("aria-live"), s.getAttribute("aria-busy")]).toEqual(["status", "polite", "true"]);
    showStatus(s, "success", "Done");
    expect(s.getAttribute("aria-busy")).toBe("false");
    clearStatus(s);
    expect(s.textContent).toBe("");
    expect(s.dataset.status).toBeUndefined();
  });

  it("escapes messages and details, and wires the retry button", () => {
    const s = el();
    let retried = 0;
    showStatus(s, "error", "<img src=x onerror=alert(1)>", { details: ["<b>one</b>", "two"], retry: () => retried++ });
    expect(s.querySelector("img")).toBeNull();
    expect(s.textContent).toContain("<img src=x onerror=alert(1)>");
    expect([...s.querySelectorAll(".status-details li")].map((li) => li.textContent)).toEqual(["<b>one</b>", "two"]);
    s.querySelector<HTMLButtonElement>(".status-retry")!.click();
    expect(retried).toBe(1);
  });
});

describe("fetchText", () => {
  const response = (ok: boolean, status: number, body = "") => ({ ok, status, text: async () => body }) as Response;

  it("returns the body of a successful response", async () => {
    expect(await fetchText("a.json", async () => response(true, 200, "{}"))).toBe("{}");
  });

  it("turns HTTP errors and network failures into readable errors", async () => {
    await expect(fetchText("a.json", async () => response(false, 404))).rejects.toThrow("a.json returned HTTP 404");
    await expect(
      fetchText("a.json", async () => {
        throw new TypeError("Failed to fetch");
      }),
    ).rejects.toThrow("could not reach a.json (Failed to fetch)");
  });
});

describe("copyText", () => {
  it("reports a denied or missing clipboard instead of claiming success", async () => {
    await expect(copyText("x", { writeText: async () => Promise.reject(new Error("denied")) })).rejects.toThrow("denied");
    await expect(copyText("x", undefined)).rejects.toThrow("clipboard is not available");
    await expect(copyText("x", { writeText: async () => {} })).resolves.toBeUndefined();
  });
});
