import { describe, expect, it } from "vitest";
import { MAX_MODEL_ERRORS, validateTestableModel } from "../../src/testlab/model";
import { readRepoFile } from "../helpers";

const sample = () => JSON.parse(readRepoFile("2-test-lab/samples/sample-testable-model.json")) as Record<string, unknown>;

describe("validateTestableModel", () => {
  it("accepts the committed demo model without warnings", () => {
    expect(validateTestableModel(sample())).toEqual({ ok: true, warnings: [] });
  });

  it.each([
    [null, /must be a JSON object/],
    [[], /must be a JSON object/],
    ["text", /must be a JSON object/],
    [{}, /endpoints: missing or not an array/],
    [{ endpoints: [], laws: "x" }, /laws: missing or not an array/],
    [{ endpoints: [{ method: "GET" }], laws: [] }, /endpoints\[0\]\.path: missing or does not start with "\/"/],
    [{ endpoints: [{ method: "GET", path: "users" }], laws: [] }, /endpoints\[0\]\.path/],
    [{ endpoints: [7], laws: [] }, /endpoints\[0\]: not an object/],
    [{ endpoints: [], laws: [{ category: "BOLA" }] }, /laws\[0\]\.id: missing/],
    [{ endpoints: [], laws: [{ id: "L" }] }, /laws\[0\]\.category: missing/],
    [{ endpoints: [], laws: [], testIdentities: {} }, /testIdentities: not an array/],
    [{ endpoints: [], laws: [], testIdentities: [{ role: "x" }] }, /testIdentities\[0\]\.id: missing/],
    [{ endpoints: [], laws: [], ownership: { a: "b" } }, /ownership: not an array/],
    [{ endpoints: [], laws: [], ownership: [{ objectId: "1" }] }, /ownership\[0\]: needs objectId and ownerId/],
    [{ endpoints: [], laws: [], twin: [] }, /twin: not an object/],
    [{ endpoints: [], laws: [], resources: "x" }, /resources: not an object/],
    [{ endpoints: [], laws: [], sandboxBaseUrl: 42 }, /sandboxBaseUrl: not a string/],
  ])("rejects malformed input %j", (value, message) => {
    const r = validateTestableModel(value);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.join("\n")).toMatch(message);
  });

  it("caps the list of errors", () => {
    const r = validateTestableModel({ endpoints: Array.from({ length: 30 }, () => ({})), laws: [] });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.errors).toHaveLength(MAX_MODEL_ERRORS + 1);
      expect(r.errors.at(-1)).toMatch(/…and \d+ more\./);
    }
  });

  it("warns about unplanned categories and empty models instead of failing", () => {
    const m = sample();
    (m.laws as { category: string }[])[0]!.category = "STATE_MACHINE";
    const r = validateTestableModel(m);
    expect(r).toMatchObject({ ok: true });
    if (r.ok) expect(r.warnings.join("\n")).toMatch(/category STATE_MACHINE is not planned/);
    expect(validateTestableModel({ endpoints: [], laws: [] })).toEqual({ ok: true, warnings: ["The model has no laws, so there is nothing to plan.", "The model has no endpoints."] });
  });

  it("accepts a null sandboxBaseUrl (no suggested target)", () => {
    expect(validateTestableModel({ ...sample(), sandboxBaseUrl: null }).ok).toBe(true);
  });
});
