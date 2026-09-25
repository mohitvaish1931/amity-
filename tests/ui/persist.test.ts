import { describe, expect, it } from "vitest";
import { MAX_WORKSPACE_CHARS, createWorkspaceStore, type Workspace } from "../../src/ui/persist";

class MemoryStorage {
  map = new Map<string, string>();
  quota = Infinity;
  getItem(k: string) {
    return this.map.has(k) ? this.map.get(k)! : null;
  }
  setItem(k: string, v: string) {
    if (v.length > this.quota) throw Object.assign(new Error("full"), { name: "QuotaExceededError" });
    this.map.set(k, v);
  }
  removeItem(k: string) {
    this.map.delete(k);
  }
}
const ws = (over: Partial<Workspace> = {}): Workspace => ({
  specText: '{"openapi":"3.0.0"}',
  identities: "[]",
  permissions: "{}",
  ownership: "{}",
  baseUrl: "http://127.0.0.1:9000",
  overrides: { "User.phone": "PERSONAL" },
  ...over,
});

describe("createWorkspaceStore", () => {
  it("round-trips a workspace and records the opt-in", () => {
    const mem = new MemoryStorage();
    const store = createWorkspaceStore(() => mem);
    expect(store.remembered()).toBe(false);
    expect(store.load()).toEqual({ ok: false, reason: "empty" });
    expect(store.save(ws(), "2026-09-25T00:00:00.000Z")).toEqual({ ok: true, savedAt: "2026-09-25T00:00:00.000Z", omitted: [] });
    expect(store.remembered()).toBe(true);
    expect(store.load()).toEqual({ ok: true, data: { version: 1, savedAt: "2026-09-25T00:00:00.000Z", ...ws() } });
  });

  it("clear forgets both the data and the opt-in", () => {
    const mem = new MemoryStorage();
    const store = createWorkspaceStore(() => mem);
    store.save(ws(), "t");
    store.clear();
    expect(store.remembered()).toBe(false);
    expect(store.load()).toEqual({ ok: false, reason: "empty" });
    expect(mem.map.size).toBe(0);
  });

  it("rejects corrupt or tampered data instead of restoring it", () => {
    const mem = new MemoryStorage();
    const store = createWorkspaceStore(() => mem, "k");
    mem.setItem("k", "{not json");
    expect(store.load()).toEqual({ ok: false, reason: "corrupt" });
    mem.setItem("k", JSON.stringify({ version: 1, savedAt: "t", ...ws(), overrides: { "User.phone": "<script>" } }));
    expect(store.load()).toEqual({ ok: false, reason: "corrupt" });
    mem.setItem("k", JSON.stringify({ version: 2, savedAt: "t", ...ws() }));
    expect(store.load()).toEqual({ ok: false, reason: "corrupt" });
    mem.setItem("k", JSON.stringify({ version: 1, savedAt: "t", ...ws(), specText: 42 }));
    expect(store.load()).toEqual({ ok: false, reason: "corrupt" });
  });

  it("refuses oversized workspaces and reports a full storage", () => {
    const mem = new MemoryStorage();
    const store = createWorkspaceStore(() => mem);
    const big = store.save(ws({ specText: "x".repeat(MAX_WORKSPACE_CHARS) }), "t");
    expect(big).toMatchObject({ ok: false, reason: "too-large" });
    mem.quota = 10;
    expect(store.save(ws(), "t")).toMatchObject({ ok: false, reason: "quota", message: expect.stringContaining("QuotaExceededError") });
    expect(store.remembered()).toBe(false);
  });

  it("works when storage is missing or blocked", () => {
    const missing = createWorkspaceStore(() => null);
    expect(missing.load()).toEqual({ ok: false, reason: "unavailable" });
    expect(missing.save(ws(), "t")).toMatchObject({ ok: false, reason: "unavailable" });
    expect(missing.remembered()).toBe(false);
    expect(() => missing.clear()).not.toThrow();
    const blocked = createWorkspaceStore(() => {
      throw Object.assign(new Error("denied"), { name: "SecurityError" });
    });
    expect(blocked.load()).toEqual({ ok: false, reason: "unavailable" });
    expect(() => blocked.clear()).not.toThrow();
  });

  it("stores only the declared workspace fields, never anything else the caller passes", () => {
    const mem = new MemoryStorage();
    createWorkspaceStore(() => mem, "k").save({ ...ws(), token: "secret-token" } as Workspace, "t");
    const raw = mem.getItem("k")!;
    expect(Object.keys(JSON.parse(raw)).sort()).toEqual(["baseUrl", "identities", "overrides", "ownership", "permissions", "savedAt", "specText", "version"]);
    expect(raw).not.toContain("secret-token");
  });
});

describe("credentials in the sandbox URL", () => {
  it.each(["http://user:pass@127.0.0.1:9000", "http://token@localhost:8080/api", "https://a:b@sandbox.test"])("never stores %s, and says so", (url) => {
    const mem = new MemoryStorage();
    const store = createWorkspaceStore(() => mem, "k");
    expect(store.save(ws({ baseUrl: url }), "t")).toEqual({ ok: true, savedAt: "t", omitted: ["baseUrl"] });
    const raw = mem.getItem("k")!;
    expect(JSON.parse(raw).baseUrl).toBe("");
    expect(raw).not.toContain("@");
  });
});
