import { describe, expect, it } from "vitest";
import { UNRATED, exportTestPlanJson, exportTestPlanMarkdown, filterOptions, filterTests, type PlanLaw, type PlannedTest, type TestPlanContext } from "../../src/testlab/plan";

const laws: PlanLaw[] = [
  { id: "LAW-001", category: "BOLA", severity: "High", confidence: "HIGH", title: "Own orders only" },
  { id: "LAW-004", category: "DATA", severity: "Medium", confidence: "MEDIUM", title: "No foreign payment data" },
  { id: "LAW-009", category: "AUTHN" }, // no severity or confidence: must stay UNRATED, never invented
];

function test(id: string, lawId: string, extra: Partial<PlannedTest> = {}): PlannedTest {
  return {
    id,
    lawId,
    category: "BOLA",
    kind: "BOLA",
    priority: 1,
    hypothesis: `h ${id}`,
    given: "authenticated as u1",
    whenText: "GET /orders/2",
    expectText: "DENY 403/404",
    target: { method: "GET", pathTemplate: "/orders/{id}", path: "/orders/2" },
    identityId: "u1",
    ...extra,
  };
}
const tests = [test("T-001", "LAW-001"), test("T-002", "LAW-001"), test("T-003", "LAW-004"), test("T-004", "LAW-009", { identityId: null, skip: true })];
const ctx: TestPlanContext = { modelVersion: "part1-v5-typed", generatedAt: "2026-01-01T00:00:00.000Z", filter: {}, target: { url: null, registered: false }, executor: "mock", totalTests: tests.length };

describe("filterTests", () => {
  it("filters by law, severity and confidence of the case's law", () => {
    expect(filterTests(tests, laws, { lawIds: ["LAW-001"] }).map((t) => t.id)).toEqual(["T-001", "T-002"]);
    expect(filterTests(tests, laws, { severities: ["Medium"] }).map((t) => t.id)).toEqual(["T-003"]);
    expect(filterTests(tests, laws, { confidences: ["HIGH"] }).map((t) => t.id)).toEqual(["T-001", "T-002"]);
    expect(filterTests(tests, laws, { confidences: [UNRATED] }).map((t) => t.id)).toEqual(["T-004"]);
    expect(filterTests(tests, laws, { lawIds: ["LAW-001"], severities: ["Medium"] })).toEqual([]);
    expect(filterTests(tests, laws, {})).toHaveLength(4);
  });
});

describe("filterOptions", () => {
  it("lists only values present among planned cases, with case counts", () => {
    expect(filterOptions(tests, laws, "id")).toEqual([{ value: "LAW-001", tests: 2 }, { value: "LAW-004", tests: 1 }, { value: "LAW-009", tests: 1 }]);
    expect(filterOptions(tests, laws, "severity")).toEqual([{ value: "High", tests: 2 }, { value: "Medium", tests: 1 }, { value: UNRATED, tests: 1 }]);
    expect(filterOptions([], laws, "confidence")).toEqual([]);
  });
});

describe("exportTestPlanJson", () => {
  it("exports specifications only, labelled as not executed", () => {
    const out = exportTestPlanJson(tests.slice(0, 3), laws, { ...ctx, filter: { lawIds: ["LAW-001", "LAW-004"] } });
    expect(out).toMatchObject({ format: "sentinel-x-test-plan-v1", basis: "specification", exportedTests: 3, totalTests: 4 });
    expect(out.disclaimer).toMatch(/Nothing in this file was executed/);
    expect(out.laws.map((l) => l.id)).toEqual(["LAW-001", "LAW-004"]);
    expect(out.tests[0]).toMatchObject({ id: "T-001", request: { method: "GET", path: "/orders/2" }, executable: true, hypothesisSource: "heuristic" });
    const text = JSON.stringify(out);
    expect(text).not.toMatch(/CONFIRMED|VIOLATION|"status"/);
    expect(out.target.note).toMatch(/not independently verified/);
  });

  it("marks non-executable cases and never invents a severity", () => {
    const out = exportTestPlanJson([tests[3]!], laws, ctx);
    expect(out.tests[0]).toMatchObject({ executable: false, identity: null });
    expect(out.laws[0]).toMatchObject({ severity: UNRATED, confidence: UNRATED });
  });
});

describe("exportTestPlanMarkdown", () => {
  it("renders a table and per-case sections with the disclaimer", () => {
    const md = exportTestPlanMarkdown(tests, laws, { ...ctx, target: { url: "http://127.0.0.1:9000", registered: true } });
    expect(md).toMatch(/^# Test specifications: model part1-v5-typed/);
    expect(md).toContain("Nothing in this file was executed");
    expect(md).toContain("registered sandbox target");
    expect(md).toContain("| T-001 | LAW-001 | BOLA | P1 | `GET /orders/2` | `u1` | DENY 403/404 |");
    expect(md).toContain("manual review");
    expect(md).toContain("### T-003 (LAW-004 · BOLA)");
  });

  it("escapes Markdown and HTML coming from the model", () => {
    const evil = test("T-9", "LAW-001", { hypothesis: "<img src=x onerror=alert(1)> [link](javascript:x)", expectText: "a | b" });
    const md = exportTestPlanMarkdown([evil], [{ ...laws[0]!, title: "**bold** <script>" }], ctx);
    expect(md).not.toContain("<img");
    expect(md).not.toContain("<script>");
    expect(md).not.toContain("[link](javascript");
    expect(md).toContain("a \\| b");
  });

  it("states when no case matches", () => {
    expect(exportTestPlanMarkdown([], laws, { ...ctx, filter: { lawIds: ["LAW-404"] } })).toMatch(/_No test case matches the filter\._/);
  });
});
