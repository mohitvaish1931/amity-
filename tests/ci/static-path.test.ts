import path from "node:path";
import { describe, expect, it } from "vitest";
import { resolveStaticPath } from "../../scripts/static-path.mjs";

const root = path.resolve("/srv/app/dist");

describe("resolveStaticPath (local static server)", () => {
  it("serves files inside the root", () => {
    expect(resolveStaticPath(root, "/1-security-twin/app.js")).toEqual({ ok: true, file: path.join(root, "1-security-twin", "app.js") });
    expect(resolveStaticPath(root, "/")).toEqual({ ok: true, file: root });
    expect(resolveStaticPath(root, "/a%20b.json?x=1")).toEqual({ ok: true, file: path.join(root, "a b.json") });
  });

  it("refuses paths that escape the root, including prefix-sharing sibling folders", () => {
    expect(resolveStaticPath(root, "/%2e%2e%2fdist-old/secret.txt")).toEqual({ ok: false, status: 403 });
    expect(resolveStaticPath(root, "/%2e%2e%2f%2e%2e%2fpackage.json")).toEqual({ ok: false, status: 403 });
    expect(resolveStaticPath(root, "/..%5c..%5cpackage.json").ok).toBe(path.sep === "\\" ? false : true);
  });

  it("answers 400 instead of crashing on undecodable paths", () => {
    expect(resolveStaticPath(root, "/%E0%A4%A")).toEqual({ ok: false, status: 400 });
    expect(resolveStaticPath(root, "/a%00b")).toEqual({ ok: false, status: 400 });
  });
});
