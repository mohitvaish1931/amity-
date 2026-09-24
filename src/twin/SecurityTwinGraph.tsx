import { Component, memo, useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import "./twin.css";
import {
  buildTwinGraph,
  describeEdge,
  describeNode,
  lawHighlight,
  type FieldMode,
  type MetaValue,
  type TwinEntityType,
  type TwinGraph,
  type TwinGraphInput,
  type TwinNode,
  type TwinRelationType,
} from "./graph";
import { DEFAULT_LAYOUT, layoutTwinGraph } from "./layout";

const TYPE_LABEL: Record<TwinEntityType, string> = {
  identity: "Identity",
  role: "Role",
  endpoint: "Endpoint",
  resource: "Resource",
  field: "Field",
  law: "Security Law",
};
const TYPE_PLURAL: Record<TwinEntityType, string> = {
  identity: "identities",
  role: "roles",
  endpoint: "endpoints",
  resource: "resources",
  field: "fields",
  law: "security laws",
};
const TYPE_ICON: Record<TwinEntityType, string> = {
  identity: "👤",
  role: "🛡",
  endpoint: "⇄",
  resource: "▣",
  field: "•",
  law: "⚖",
};
const RELATION_CLASS: Record<TwinRelationType, string> = {
  HAS_ROLE: "rel-identity",
  OWNS: "rel-owns",
  REQUIRES_ROLE: "rel-identity",
  READS: "rel-read",
  WRITES: "rel-write",
  RETURNS: "rel-read",
  RELATES_TO: "rel-relates",
  HAS_FIELD: "rel-field",
  EXPOSES: "rel-exposes",
  GOVERNS: "rel-law",
  VIOLATES: "rel-violates",
};

type Emphasis = "normal" | "highlight" | "dim";
type TwinFlowNode = Node<{ node: TwinNode; emphasis: Emphasis }, "twin">;
type Selection = { kind: "node" | "edge"; id: string } | null;

function chip(node: TwinNode): string | null {
  const m = node.meta;
  switch (node.type) {
    case "endpoint":
      return `auth: ${m.auth}`;
    case "resource":
      return m.ownershipField && m.ownershipField !== "none" ? `owner: ${m.ownershipField}` : "no ownership field";
    case "field":
      return m.ownershipField ? "ownership field" : null;
    case "law":
      return m.confidence ? `${m.confidence}${m.score !== undefined ? ` ${m.score}` : ""}` : null;
    case "role":
      return m.privileged ? "privileged" : null;
    default:
      return null;
  }
}

const TwinNodeView = memo(function TwinNodeView({ data, selected }: NodeProps<TwinFlowNode>) {
  const { node, emphasis } = data;
  const method = node.type === "endpoint" ? String(node.meta.method) : "";
  const extra = chip(node);
  return (
    <div
      className={`twin-node twin-${node.type} is-${emphasis}${selected ? " is-selected" : ""}`}
      data-node-id={node.id}
      data-sensitivity={node.type === "field" ? String(node.meta.sensitivity) : undefined}
      title={`${TYPE_LABEL[node.type]}: ${node.label}`}
    >
      <Handle type="target" position={Position.Top} isConnectable={false} />
      <div className="twin-node-head">
        <span className="twin-icon" aria-hidden="true">{TYPE_ICON[node.type]}</span>
        <span className="twin-type">{TYPE_LABEL[node.type]}</span>
        {method && <span className={`twin-method m-${method}`}>{method}</span>}
        <span className="twin-degree" title="relationships">{node.degree}</span>
      </div>
      <div className="twin-label">{node.type === "endpoint" ? String(node.meta.path) : node.label}</div>
      <div className="twin-sub">
        {node.subtitle}
        {extra && <span className="twin-chip">{extra}</span>}
      </div>
      <Handle type="source" position={Position.Bottom} isConnectable={false} />
    </div>
  );
});

const nodeTypes = { twin: TwinNodeView };

function formatMeta(v: MetaValue): string {
  if (Array.isArray(v)) return v.length ? v.join(", ") : "—";
  if (typeof v === "boolean") return v ? "yes" : "no";
  return String(v);
}

function MetaTable({ meta }: { meta: Record<string, MetaValue> }) {
  const rows = Object.entries(meta).filter(([, v]) => !(Array.isArray(v) && v.length === 0) && v !== "");
  if (!rows.length) return <p className="twin-muted">No metadata in the model.</p>;
  return (
    <table className="twin-meta">
      <tbody>
        {rows.map(([k, v]) => (
          <tr key={k}>
            <th>{k}</th>
            <td>{formatMeta(v)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function DetailsPanel({ graph, selection, onSelect }: { graph: TwinGraph; selection: Selection; onSelect: (s: Selection) => void }) {
  if (!selection) {
    return (
      <aside className="twin-panel" data-testid="twin-panel">
        <p className="twin-muted">Select a node or edge to inspect it.</p>
      </aside>
    );
  }
  if (selection.kind === "edge") {
    const d = describeEdge(graph, selection.id);
    if (!d) return null;
    return (
      <aside className="twin-panel" data-testid="twin-panel">
        <div className="twin-panel-type">Relationship</div>
        <h4>{d.edge.types.join(" · ")}</h4>
        <p>
          <button type="button" className="twin-link" onClick={() => onSelect({ kind: "node", id: d.source.id })}>{d.source.label}</button>
          {" → "}
          <button type="button" className="twin-link" onClick={() => onSelect({ kind: "node", id: d.target.id })}>{d.target.label}</button>
        </p>
        <h5>Provenance</h5>
        <ul>{d.edge.provenance.map((p) => <li key={p}>{p}</li>)}</ul>
      </aside>
    );
  }
  const d = describeNode(graph, selection.id);
  if (!d) return null;
  const rel = (list: typeof d.outgoing, dir: "→" | "←") =>
    list.map(({ edge, other }) => (
      <li key={`${dir}${edge.id}`}>
        <span className="twin-rel">{edge.types.join(" · ")}</span> {dir}{" "}
        <button type="button" className="twin-link" onClick={() => onSelect({ kind: "node", id: other.id })}>
          {other.label}
        </button>{" "}
        <span className="twin-muted">({TYPE_LABEL[other.type]})</span>
      </li>
    ));
  return (
    <aside className="twin-panel" data-testid="twin-panel">
      <div className="twin-panel-type">{TYPE_LABEL[d.node.type]}</div>
      <h4>{d.node.label}</h4>
      <p className="twin-muted">{d.node.subtitle}</p>
      <h5>Details</h5>
      <MetaTable meta={d.node.meta} />
      <h5>Relationships ({d.outgoing.length + d.incoming.length})</h5>
      {d.outgoing.length + d.incoming.length ? (
        <ul>
          {rel(d.outgoing, "→")}
          {rel(d.incoming, "←")}
        </ul>
      ) : (
        <p className="twin-muted">None in the model.</p>
      )}
      {d.node.type !== "law" && (
        <>
          <h5>Relevant laws</h5>
          {d.laws.length ? (
            <ul>
              {d.laws.map((l) => (
                <li key={l.id}>
                  <button type="button" className="twin-link" onClick={() => onSelect({ kind: "node", id: l.id })}>{l.label}</button>{" "}
                  <span className="twin-muted">{String(l.meta.title ?? "")}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="twin-muted">No law references this entity.</p>
          )}
        </>
      )}
    </aside>
  );
}

function GraphCanvas({ input }: { input: TwinGraphInput }) {
  const [fieldMode, setFieldMode] = useState<FieldMode>("key");
  const [selection, setSelection] = useState<Selection>(null);
  const [lawFilter, setLawFilter] = useState("");
  const { fitView } = useReactFlow();

  const graph = useMemo(() => buildTwinGraph({ ...input, fieldMode }), [input, fieldMode]);
  const positions = useMemo(() => layoutTwinGraph(graph), [graph]);
  const highlight = useMemo(() => (lawFilter ? lawHighlight(graph, lawFilter) : null), [graph, lawFilter]);
  const lawIds = useMemo(() => graph.nodes.filter((n) => n.type === "law").map((n) => n.label), [graph]);

  const layoutNodes = useMemo<TwinFlowNode[]>(
    () =>
      graph.nodes.map((n) => ({
        id: n.id,
        type: "twin",
        position: positions[n.id] ?? { x: 0, y: 0 },
        width: DEFAULT_LAYOUT.nodeWidth,
        height: DEFAULT_LAYOUT.nodeHeight,
        data: { node: n, emphasis: "normal" },
      })),
    [graph, positions],
  );
  const [nodes, setNodes, onNodesChange] = useNodesState<TwinFlowNode>(layoutNodes);

  // New model or field mode -> fresh layout.
  useEffect(() => setNodes(layoutNodes), [layoutNodes, setNodes]);
  // Drop a selection or law filter that no longer exists in the new graph.
  useEffect(() => {
    setSelection((s) => (s && (s.kind === "node" ? graph.nodes.some((n) => n.id === s.id) : graph.edges.some((e) => e.id === s.id)) ? s : null));
  }, [graph]);
  useEffect(() => {
    if (lawFilter && !lawIds.includes(lawFilter)) setLawFilter("");
  }, [lawIds, lawFilter]);

  const displayNodes = useMemo(
    () =>
      nodes.map((n) => {
        const emphasis: Emphasis = highlight ? (highlight.nodes.has(n.id) ? "highlight" : "dim") : "normal";
        return n.data.emphasis === emphasis && n.selected === (selection?.kind === "node" && selection.id === n.id)
          ? n
          : { ...n, selected: selection?.kind === "node" && selection.id === n.id, data: { ...n.data, emphasis } };
      }),
    [nodes, highlight, selection],
  );

  const edges = useMemo<Edge[]>(
    () =>
      graph.edges.map((e) => {
        const isSelected = selection?.kind === "edge" && selection.id === e.id;
        const emphasised = highlight?.edges.has(e.id) ?? false;
        const cls = [
          "twin-edge",
          ...e.types.map((t) => RELATION_CLASS[t]),
          highlight ? (emphasised ? "is-highlight" : "is-dim") : "",
          isSelected ? "is-selected" : "",
        ];
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          className: cls.filter(Boolean).join(" "),
          label: isSelected || emphasised ? e.types.join(" · ") : undefined,
          selected: isSelected,
          animated: e.types.includes("VIOLATES"),
          markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
          data: { types: e.types },
        };
      }),
    [graph, highlight, selection],
  );

  const resetLayout = useCallback(() => {
    setNodes(layoutNodes);
    requestAnimationFrame(() => void fitView({ padding: 0.15 }));
  }, [layoutNodes, setNodes, fitView]);

  const counts = useMemo(() => {
    const c: Partial<Record<TwinEntityType, number>> = {};
    for (const n of graph.nodes) c[n.type] = (c[n.type] ?? 0) + 1;
    return c;
  }, [graph]);

  return (
    <div className="twin-root">
      <div className="twin-toolbar">
        <label>
          Fields{" "}
          <select value={fieldMode} onChange={(e) => setFieldMode(e.target.value as FieldMode)} data-testid="twin-field-mode">
            <option value="key">sensitive + ownership</option>
            <option value="all">all</option>
            <option value="none">none</option>
          </select>
        </label>
        <label>
          Highlight law{" "}
          <select value={lawFilter} onChange={(e) => setLawFilter(e.target.value)} data-testid="twin-law-filter">
            <option value="">none</option>
            {lawIds.map((id) => (
              <option key={id} value={id}>{id}</option>
            ))}
          </select>
        </label>
        <button type="button" className="ghost" onClick={() => void fitView({ padding: 0.15 })} data-testid="twin-fit">Fit view</button>
        <button type="button" className="ghost" onClick={resetLayout} data-testid="twin-reset">Reset layout</button>
        <span className="twin-muted twin-counts" data-testid="twin-counts">
          {(Object.keys(TYPE_LABEL) as TwinEntityType[])
            .filter((t) => counts[t])
            .map((t) => `${counts[t]} ${counts[t] === 1 ? TYPE_LABEL[t].toLowerCase() : TYPE_PLURAL[t]}`)
            .join(" · ")}
          {` · ${graph.edges.length} relationships · fields shown ${graph.stats.fieldsShown}/${graph.stats.fieldsTotal}`}
        </span>
      </div>
      <div className="twin-body">
        <div className="twin-canvas">
          <ReactFlow
            nodes={displayNodes}
            edges={edges}
            nodeTypes={nodeTypes}
            onNodesChange={onNodesChange}
            onNodeClick={(_, n) => setSelection({ kind: "node", id: n.id })}
            onEdgeClick={(_, e) => setSelection({ kind: "edge", id: e.id })}
            onPaneClick={() => setSelection(null)}
            nodesConnectable={false}
            edgesFocusable
            fitView
            fitViewOptions={{ padding: 0.15 }}
            minZoom={0.1}
            maxZoom={2}
            onlyRenderVisibleElements={graph.nodes.length > 250}
            colorMode="dark"
            proOptions={{ hideAttribution: true }}
          >
            <Background gap={24} size={1} />
            <Controls showInteractive={false} />
            {graph.nodes.length > 60 && (
              <MiniMap pannable zoomable className="twin-minimap" style={{ width: 160, height: 110 }} bgColor="#0f172a" maskColor="rgba(2, 6, 23, 0.7)" nodeColor="#334155" />
            )}
          </ReactFlow>
        </div>
        <DetailsPanel graph={graph} selection={selection} onSelect={setSelection} />
      </div>
    </div>
  );
}

/** A rendering failure in the graph must not take down the rest of the page. */
class GraphErrorBoundary extends Component<{ children: ReactNode; resetKey: unknown }, { error: string | null }> {
  override state = { error: null as string | null };
  static getDerivedStateFromError(e: unknown) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
  override componentDidUpdate(prev: { resetKey: unknown }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }
  override render() {
    if (this.state.error) {
      return <div className="twin-empty" data-testid="twin-error">The graph could not be rendered: {this.state.error}</div>;
    }
    return this.props.children;
  }
}

export function SecurityTwinGraph({ input }: { input: TwinGraphInput | null }) {
  const empty = !input || ((input.endpoints?.length ?? 0) === 0 && (input.resources?.length ?? 0) === 0 && (input.identities?.length ?? 0) === 0);
  if (empty) {
    return <div className="twin-empty" data-testid="twin-empty">No model yet. Build the Security Twin to see the graph.</div>;
  }
  return (
    <GraphErrorBoundary resetKey={input}>
      <ReactFlowProvider>
        <GraphCanvas input={input} />
      </ReactFlowProvider>
    </GraphErrorBoundary>
  );
}
