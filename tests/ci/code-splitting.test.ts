// The Step 1 page must not download the Security Twin graph (React + React Flow) before it is needed.
import { describe, expect, it } from "vitest";
import { bundleApp } from "../../scripts/app-harness.mjs";
import { readRepoFile } from "../helpers";

describe("Step 1 production bundle is code-split", () => {
  it("keeps React Flow out of the entry bundle and loads it through a dynamic import", async () => {
    // Unminified so esbuild's module path comments show which packages each file contains.
    const { js, chunks } = await bundleApp("1-security-twin", { split: true });
    expect(js).not.toMatch(/node_modules\/@xyflow\//);
    expect(js).not.toMatch(/node_modules\/react-dom\//);
    const lazy = Object.keys(chunks).filter((rel) => js.includes(`import("./${rel}")`));
    expect(lazy).toHaveLength(1);
    const graph = chunks[lazy[0]!]!;
    expect(graph).toMatch(/node_modules\/@xyflow\/react\//);
    // The entry is a fraction of the graph code it no longer carries.
    expect(js.length).toBeLessThan(graph.length);
  });

  it("serves the split entry as an ES module", () => {
    expect(readRepoFile("1-security-twin/index.html")).toContain('<script type="module" src="app.js"></script>');
  });
});
