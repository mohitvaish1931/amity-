import { describe, expect, it } from "vitest";
import { exportConstitutionJson, exportConstitutionMarkdown, filterLaws, mdCode, mdText, type ExportContext } from "../../src/constitution/explore";
import type { SecurityConstitution } from "../../src/contracts";
import { marketplace } from "./helpers";

const ctx = (over: Partial<ExportContext> = {}): ExportContext => ({
  specTitle: "Marketplace",
  specVersion: "3.0.3",
  generatedAt: "2026-09-25T00:00:00.000Z",
  filter: {},
  ...over,
});

describe("filterLaws", () => {
  const c = marketplace();

  it("returns every law with an empty filter", () => {
    expect(filterLaws(c.laws)).toEqual(c.laws);
  });

  it("filters by category, severity and confidence together", () => {
    for (const law of c.laws) {
      const hits = filterLaws(c.laws, { categories: [law.category], severities: [law.severity], confidences: [law.confidence] });
      expect(hits).toContain(law);
      expect(hits.every((l) => l.category === law.category && l.severity === law.severity && l.confidence === law.confidence)).toBe(true);
    }
  });

  it("text search covers statement, scope and provenance, case-insensitively", () => {
    const law = c.laws.find((l) => l.appliesTo.resources.length)!;
    const resource = law.appliesTo.resources[0]!;
    const hits = filterLaws(c.laws, { text: `  ${resource.toUpperCase()} ` });
    expect(hits).toContain(law);
    expect(hits.every((l) => JSON.stringify([l.statement, l.invariant, l.appliesTo, l.provenance, l.id]).toLowerCase().includes(resource.toLowerCase()))).toBe(true);
    expect(filterLaws(c.laws, { text: "no-such-thing-anywhere" })).toEqual([]);
  });
});

describe("constitution export", () => {
  const c = marketplace();

  it("JSON export is labelled specification-derived, records the filter and copies the laws", () => {
    const shown = filterLaws(c.laws, { categories: ["OBJECT_AUTHORIZATION"] });
    const out = exportConstitutionJson(c, shown, ctx({ filter: { categories: ["OBJECT_AUTHORIZATION"] } }));
    expect(out.basis).toBe("specification");
    expect(out.disclaimer).toMatch(/no test was executed and no law is a confirmed vulnerability/);
    expect(out).toMatchObject({ totalLaws: c.laws.length, exportedLaws: shown.length, filter: { categories: ["OBJECT_AUTHORIZATION"] } });
    expect(out.laws).toEqual(shown);
    expect(out.laws[0]).not.toBe(shown[0]); // a copy, not the live model
    expect(JSON.parse(JSON.stringify(out))).toEqual(out);
  });

  it("Markdown export contains every law with rule, scope, provenance, confidence and test strategy", () => {
    const md = exportConstitutionMarkdown(c, c.laws, ctx());
    expect(md.split("\n")[0]).toBe("# Security Constitution: Marketplace \\(3.0.3\\)");
    expect(md).toMatch(/Specification-derived/);
    expect(md).toContain(`Laws: ${c.laws.length} of ${c.laws.length} (filter: none)`);
    for (const l of c.laws) {
      expect(md).toContain(`## ${l.id}: `);
      expect(md).toContain(mdCode(l.invariant));
      for (const p of l.provenance) expect(md).toContain(mdCode(p.ref));
      expect(md).toContain(`(${mdText(l.testStrategy.kind)}; specification only, not executed)`);
    }
    expect(md).not.toMatch(/CONFIRMED/);
  });

  it("describes the filter and handles an empty result", () => {
    const md = exportConstitutionMarkdown(c, [], ctx({ filter: { severities: ["Critical"], text: "zzz" } }));
    expect(md).toContain(`Laws: 0 of ${c.laws.length} (filter: severity Critical; text "zzz")`);
    expect(md).toContain("_No laws match the filter._");
  });

  it("escapes spec-supplied text so it cannot inject links, HTML or table cells", () => {
    const evil: SecurityConstitution = structuredClone(c);
    const law = evil.laws[0]!;
    law.statement = "Owner <img src=x onerror=alert(1)> | [click](http://evil.example) *bold*";
    law.invariant = "a `b` c";
    const md = exportConstitutionMarkdown(evil, [law], ctx({ specTitle: "[t](javascript:x)" }));
    expect(md).not.toContain("<img");
    expect(md).not.toContain("](http");
    expect(md).not.toContain("](javascript");
    expect(md).toContain("&lt;img src=x onerror=alert\\(1\\)&gt; \\| \\[click\\]\\(http://evil.example\\) \\*bold\\*");
    expect(md).toContain("``a `b` c``");
  });
});

describe("mdCode", () => {
  it("chooses a fence longer than any backtick run and pads edge backticks", () => {
    expect(mdCode("plain")).toBe("`plain`");
    expect(mdCode("x``y")).toBe("```x``y```");
    expect(mdCode("`edge")).toBe("`` `edge ``");
  });
});
