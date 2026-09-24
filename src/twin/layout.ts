// Deterministic layered layout for the Security Twin graph.
// Rows by entity type (identity → role → endpoint → resource → field → law), ordered within a
// row by the barycenter of connected nodes in adjacent rows to reduce crossings. Long rows wrap.
import type { TwinEntityType, TwinGraph } from "./graph";

export interface LayoutOptions {
  nodeWidth: number;
  nodeHeight: number;
  gapX: number;
  gapY: number;
  /** Rows longer than this wrap onto extra lines. */
  maxPerRow: number;
}

export const DEFAULT_LAYOUT: LayoutOptions = { nodeWidth: 220, nodeHeight: 78, gapX: 36, gapY: 70, maxPerRow: 8 };

export type Positions = Record<string, { x: number; y: number }>;

const ROWS: readonly TwinEntityType[] = ["identity", "role", "endpoint", "resource", "field", "law"];

export function layoutTwinGraph(graph: TwinGraph, options: Partial<LayoutOptions> = {}): Positions {
  const o = { ...DEFAULT_LAYOUT, ...options };
  const rows = ROWS.map((t) => graph.nodes.filter((n) => n.type === t).map((n) => n.id)).filter((r) => r.length > 0);
  if (!rows.length) return {};

  const neighbours = new Map<string, string[]>();
  for (const e of graph.edges) {
    neighbours.set(e.source, [...(neighbours.get(e.source) ?? []), e.target]);
    neighbours.set(e.target, [...(neighbours.get(e.target) ?? []), e.source]);
  }

  const reorder = (row: string[], reference: string[]): string[] => {
    const index = new Map(reference.map((id, i) => [id, i]));
    const current = new Map(row.map((id, i) => [id, i]));
    const key = (id: string): number => {
      const idx = (neighbours.get(id) ?? []).map((n) => index.get(n)).filter((i): i is number => i !== undefined);
      return idx.length ? idx.reduce((a, b) => a + b, 0) / idx.length : Number.POSITIVE_INFINITY;
    };
    const keys = new Map(row.map((id) => [id, key(id)]));
    // Unconnected nodes keep their relative order after the connected ones.
    return [...row].sort((a, b) => keys.get(a)! - keys.get(b)! || current.get(a)! - current.get(b)!);
  };

  for (let i = 1; i < rows.length; i++) rows[i] = reorder(rows[i]!, rows[i - 1]!);
  for (let i = rows.length - 2; i >= 0; i--) rows[i] = reorder(rows[i]!, rows[i + 1]!);

  const positions: Positions = {};
  let y = 0;
  const stepX = o.nodeWidth + o.gapX;
  for (const row of rows) {
    for (let start = 0; start < row.length; start += o.maxPerRow) {
      const line = row.slice(start, start + o.maxPerRow);
      const width = line.length * stepX - o.gapX;
      line.forEach((id, i) => {
        positions[id] = { x: Math.round(i * stepX - width / 2), y };
      });
      y += o.nodeHeight + o.gapY;
    }
    y += o.gapY / 2; // extra separation between entity types
  }
  return positions;
}
