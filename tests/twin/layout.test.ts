import { describe, expect, it } from "vitest";
import type { TwinEdge, TwinEntityType, TwinGraph, TwinNode } from "../../src/twin/graph";
import { DEFAULT_LAYOUT, layoutTwinGraph } from "../../src/twin/layout";

const node = (id: string, type: TwinEntityType): TwinNode => ({ id, type, label: id, subtitle: "", meta: {}, degree: 0 });
const edge = (source: string, target: string): TwinEdge => ({ id: `${source}->${target}`, source, target, types: ["READS"], provenance: [] });
const graph = (nodes: TwinNode[], edges: TwinEdge[] = []): TwinGraph => ({ nodes, edges, stats: { fieldsTotal: 0, fieldsShown: 0 } });

function overlaps(pos: Record<string, { x: number; y: number }>): boolean {
  const boxes = Object.values(pos);
  const { nodeWidth: w, nodeHeight: h } = DEFAULT_LAYOUT;
  return boxes.some((a, i) => boxes.some((b, j) => i < j && a.x < b.x + w && b.x < a.x + w && a.y < b.y + h && b.y < a.y + h));
}

describe("layoutTwinGraph", () => {
  it("returns no positions for an empty graph", () => {
    expect(layoutTwinGraph(graph([]))).toEqual({});
  });

  it("centres a single node", () => {
    expect(layoutTwinGraph(graph([node("a", "resource")]))).toEqual({ a: { x: -DEFAULT_LAYOUT.nodeWidth / 2, y: 0 } });
  });

  it("stacks entity types top to bottom: identity, role, endpoint, resource, field, law", () => {
    const pos = layoutTwinGraph(graph([node("l", "law"), node("f", "field"), node("r", "resource"), node("e", "endpoint"), node("ro", "role"), node("i", "identity")]));
    const ys = ["i", "ro", "e", "r", "f", "l"].map((id) => pos[id]!.y);
    expect(ys).toEqual([...ys].sort((a, b) => a - b));
    expect(new Set(ys).size).toBe(6);
  });

  it("orders nodes within a row by their connections to reduce crossings", () => {
    // endpoints e1,e2 point at resources in the opposite order to their ids
    const g = graph([node("e1", "endpoint"), node("e2", "endpoint"), node("rA", "resource"), node("rB", "resource")], [edge("e1", "rB"), edge("e2", "rA")]);
    const pos = layoutTwinGraph(g);
    expect(pos.rB!.x < pos.rA!.x).toBe(pos.e1!.x < pos.e2!.x);
  });

  it("keeps disconnected nodes and never overlaps, even for large graphs", () => {
    const nodes = [
      ...Array.from({ length: 30 }, (_, i) => node(`e${i}`, "endpoint")),
      ...Array.from({ length: 12 }, (_, i) => node(`r${i}`, "resource")),
      ...Array.from({ length: 40 }, (_, i) => node(`f${i}`, "field")),
      node("lonely", "role"),
    ];
    const edges = Array.from({ length: 30 }, (_, i) => edge(`e${i}`, `r${i % 12}`));
    const pos = layoutTwinGraph(graph(nodes, edges));
    expect(Object.keys(pos).sort()).toEqual(nodes.map((n) => n.id).sort());
    expect(overlaps(pos)).toBe(false);
    // 30 endpoints wrap into ceil(30 / maxPerRow) lines
    expect(new Set(nodes.filter((n) => n.type === "endpoint").map((n) => pos[n.id]!.y)).size).toBe(Math.ceil(30 / DEFAULT_LAYOUT.maxPerRow));
  });

  it("is deterministic", () => {
    const g = graph([node("b", "resource"), node("a", "resource"), node("e", "endpoint")], [edge("e", "a")]);
    expect(layoutTwinGraph(g)).toEqual(layoutTwinGraph(g));
  });
});
