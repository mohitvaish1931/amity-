import { describe, expect, it } from "vitest";
import { assessTargetHost, classifyHost, findTarget, registerTarget, resolveRequestUrl, TargetScopeError, type Target } from "../../src/target/policy";

describe("classifyHost", () => {
  it.each([
    ["localhost", "loopback"],
    ["api.localhost", "loopback"],
    ["127.0.0.1", "loopback"],
    ["127.10.20.30", "loopback"],
    ["[::1]", "loopback"],
    ["10.1.2.3", "private-network"],
    ["172.16.0.1", "private-network"],
    ["172.31.255.255", "private-network"],
    ["192.168.1.20", "private-network"],
    ["[fd12:3456::1]", "private-network"],
    ["shop.test", "reserved-name"],
    ["orders.internal", "reserved-name"],
    ["printer.local", "reserved-name"],
    ["nas.home.arpa", "reserved-name"],
    ["169.254.169.254", "link-local"],
    ["[fe80::1]", "link-local"],
    ["0.0.0.0", "unspecified"],
    ["172.32.0.1", "public"],
    ["8.8.8.8", "public"],
    ["example.com", "public"],
    ["sandbox-api.example.com", "public"],
    ["localhost.evil.com", "public"],
    ["mytest.com", "public"],
    ["[::ffff:7f00:1]", "public"],
  ])("%s → %s", (host, cls) => {
    expect(classifyHost(host)).toBe(cls);
  });

  it("is not fooled by sandbox-sounding words that the old substring hint accepted", () => {
    for (const h of ["sandbox.bank.com", "staging.shop.io", "test-api.company.com", "mock.example.org"]) expect(classifyHost(h)).toBe("public");
  });
});

describe("assessTargetHost", () => {
  it("normalizes registrable targets and explains refusals", () => {
    expect(assessTargetHost("http://127.0.0.1:9000/api/")).toMatchObject({ baseUrl: "http://127.0.0.1:9000/api", registrable: true, hostClass: "loopback" });
    expect(assessTargetHost("https://api.github.com")).toMatchObject({ registrable: false, hostClass: "public", reason: expect.stringMatching(/Public internet host/) });
    expect(assessTargetHost("http://169.254.169.254/latest")).toMatchObject({ registrable: false, reason: expect.stringMatching(/metadata/) });
    expect(assessTargetHost("ftp://localhost")).toMatchObject({ registrable: false, hostClass: "invalid" });
    expect(assessTargetHost("http://user:pw@localhost")).toMatchObject({ registrable: false, hostClass: "invalid" });
    expect(assessTargetHost("")).toMatchObject({ registrable: false, hostClass: "invalid" });
    expect(assessTargetHost("http://localhost:3000/?x=1")).toMatchObject({ registrable: false, reason: expect.stringMatching(/query or fragment/) });
  });

  it("classifies the normalized host, so alternative IPv4 spellings cannot sneak past", () => {
    // The WHATWG URL parser turns these into dotted quads before classification.
    expect(assessTargetHost("http://2130706433/").hostClass).toBe("loopback"); // 127.0.0.1
    expect(assessTargetHost("http://0xA9FEA9FE/").hostClass).toBe("link-local"); // 169.254.169.254
    expect(assessTargetHost("http://0x08080808/").hostClass).toBe("public");
  });
});

describe("registerTarget / findTarget", () => {
  it("creates a sandbox target that is authorized by configuration only", () => {
    const r = registerTarget(" http://localhost:4000/v1/ ", { id: "TGT-1", registeredAt: "2026-09-25T00:00:00.000Z" });
    expect(r).toEqual({
      ok: true,
      target: {
        id: "TGT-1",
        name: "localhost:4000",
        baseUrl: "http://localhost:4000/v1",
        origin: "http://localhost:4000",
        basePath: "/v1",
        environment: "sandbox",
        authorizationStatus: "AUTHORIZED_BY_CONFIGURATION",
        hostClass: "loopback",
        registeredAt: "2026-09-25T00:00:00.000Z",
      },
    });
  });

  it("refuses public hosts", () => {
    const r = registerTarget("https://sandbox-api.example.com", { id: "TGT-1", registeredAt: "x" });
    expect(r.ok).toBe(false);
  });

  it("finds a target by its normalized URL only", () => {
    const t = (registerTarget("http://127.0.0.1:9000", { id: "TGT-1", registeredAt: "x" }) as { target: Target }).target;
    expect(findTarget([t], "http://127.0.0.1:9000/")).toBe(t);
    expect(findTarget([t], "http://127.0.0.1:9001")).toBeNull();
    expect(findTarget([t], "")).toBeNull();
  });
});

describe("resolveRequestUrl", () => {
  const root = (registerTarget("http://127.0.0.1:9000", { id: "a", registeredAt: "x" }) as { target: Target }).target;
  const api = (registerTarget("http://127.0.0.1:9000/api", { id: "b", registeredAt: "x" }) as { target: Target }).target;

  it("joins paths under the target", () => {
    expect(resolveRequestUrl(root, "/users/1")).toBe("http://127.0.0.1:9000/users/1");
    expect(resolveRequestUrl(api, "/orders/7?x=1")).toBe("http://127.0.0.1:9000/api/orders/7?x=1");
  });

  it.each([
    ["users/1", /must start with/],
    ["/..\\evil", /backslashes/],
    ["@evil.example/x", /must start with/],
    ["/../admin", /escapes the target base path/],
    ["/%2e%2e/admin", /escapes the target base path/],
  ])("rejects %s", (path, msg) => {
    expect(() => resolveRequestUrl(api, path)).toThrow(TargetScopeError);
    expect(() => resolveRequestUrl(api, path)).toThrow(msg);
  });

  it("a protocol-relative-looking path stays on the target host", () => {
    expect(resolveRequestUrl(root, "//evil.example/x")).toBe("http://127.0.0.1:9000//evil.example/x");
  });
});
