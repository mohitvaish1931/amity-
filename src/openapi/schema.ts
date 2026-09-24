import type { Field, JsonPrimitive, SchemaInfo } from "../contracts";
import { isRecord } from "./load";
import { refName, type RefResolver } from "./refs";

const MAX_DEPTH = 12;
const MAX_REF_HOPS = 32;

interface Resolved {
  schema: Record<string, unknown>;
  /** $ref strings followed to reach `schema`, outermost first. */
  refs: string[];
  /** Component names for `refs`. */
  names: string[];
  /** True when following the chain would re-enter a schema that is already being expanded. */
  recursive: boolean;
}

interface PropEntry {
  node: unknown;
  stack: readonly string[];
}

interface Variant {
  kind: "oneOf" | "anyOf";
  label: string;
  props: Map<string, PropEntry>;
  required: Set<string>;
}

interface ObjectView {
  props: Map<string, PropEntry>;
  required: Set<string>;
  variants: Variant[];
}

interface TypeInfo {
  type: string;
  nullable: boolean;
}

/** Flattens OpenAPI/JSON schemas into `Field` lists. Safe on recursive and malformed schemas. */
export class SchemaFlattener {
  private depthWarned = false;

  constructor(
    private readonly resolver: RefResolver,
    private readonly warnings: string[],
  ) {}

  describe(node: unknown): SchemaInfo {
    const r = this.resolve(node, []);
    if (!r || r.recursive) return { type: "unknown", isArray: false, nullable: false, fields: [] };
    const s = r.schema;
    const ti = this.typeInfo(s, r.refs);
    const info: SchemaInfo = { type: ti.type, isArray: ti.type === "array", nullable: ti.nullable, fields: [] };
    const name = r.names.at(-1);
    if (name) info.refName = name;
    const en = enumOf(s);
    if (en) info.enum = en;

    if (info.isArray) {
      const ir = this.resolve(s.items, r.refs);
      if (ir && !ir.recursive) {
        const itemName = ir.names.at(-1);
        if (itemName) info.itemRefName = itemName;
        const itemStack = [...r.refs, ...ir.refs];
        if (isObjectLike(ir.schema)) this.emitObject(this.collect(ir.schema, itemStack, 0), "", 0, info.fields);
      }
    } else if (isObjectLike(s)) {
      this.emitObject(this.collect(s, r.refs, 0), "", 0, info.fields);
    }
    return info;
  }

  // ---------- resolution ----------

  private resolve(node: unknown, stack: readonly string[]): Resolved | null {
    let cur = node;
    const refs: string[] = [];
    const names: string[] = [];
    for (let hops = 0; hops < MAX_REF_HOPS; hops++) {
      if (cur === true) return { schema: {}, refs, names, recursive: false }; // JSON Schema "true" = any
      if (!isRecord(cur)) return null;
      const ref = cur.$ref;
      if (typeof ref !== "string") return { schema: cur, refs, names, recursive: false };
      names.push(refName(ref));
      if (stack.includes(ref) || refs.includes(ref)) return { schema: {}, refs, names, recursive: true };
      refs.push(ref);
      cur = this.resolver.resolve(ref);
      if (cur === undefined) return { schema: {}, refs, names, recursive: false };
    }
    return null;
  }

  private typeInfo(s: Record<string, unknown>, stack: readonly string[]): TypeInfo {
    let nullable = s.nullable === true || s["x-nullable"] === true;
    const t = s.type;
    if (Array.isArray(t)) {
      const types = t.filter((x): x is string => typeof x === "string");
      if (types.includes("null")) nullable = true;
      const nonNull = types.filter((x) => x !== "null");
      return { type: nonNull.length === 1 ? nonNull[0]! : nonNull.length ? "mixed" : "null", nullable };
    }
    if (typeof t === "string") return { type: t, nullable };

    const branches = [...asArray(s.oneOf), ...asArray(s.anyOf)];
    if (branches.some((b) => isRecord(b) && b.type === "null")) nullable = true;
    if (isRecord(s.properties) || asArray(s.allOf).length || isRecord(s.additionalProperties)) {
      return { type: "object", nullable };
    }
    if (s.items !== undefined) return { type: "array", nullable };
    if (branches.length) {
      const types = new Set<string>();
      for (const b of branches) {
        const r = this.resolve(b, stack);
        if (!r) continue;
        if (r.recursive || isObjectLike(r.schema)) types.add("object");
        else if (r.schema.type !== "null") types.add(this.typeInfo(r.schema, [...stack, ...r.refs]).type);
      }
      if (types.has("object")) return { type: "object", nullable };
      return { type: types.size === 1 ? [...types][0]! : types.size ? "mixed" : "unknown", nullable };
    }
    const en = enumOf(s);
    if (en?.length) {
      const first = en.find((v) => v !== null);
      if (first !== undefined) return { type: typeof first === "number" ? "number" : typeof first, nullable };
    }
    return { type: "unknown", nullable };
  }

  // ---------- object views (allOf merged, oneOf/anyOf as variants) ----------

  private collect(s: Record<string, unknown>, stack: readonly string[], depth: number): ObjectView {
    const view: ObjectView = { props: new Map(), required: new Set(), variants: [] };
    const visit = (node: Record<string, unknown>, st: readonly string[], d: number): void => {
      if (d > MAX_DEPTH) return this.warnDepth();
      if (isRecord(node.properties)) {
        for (const [k, v] of Object.entries(node.properties)) if (!view.props.has(k)) view.props.set(k, { node: v, stack: st });
      }
      for (const req of asArray(node.required)) if (typeof req === "string") view.required.add(req);
      for (const branch of asArray(node.allOf)) {
        const r = this.resolve(branch, st);
        if (r && !r.recursive) visit(r.schema, [...st, ...r.refs], d + 1);
      }
      for (const kind of ["oneOf", "anyOf"] as const) {
        asArray(node[kind]).forEach((branch, i) => {
          const r = this.resolve(branch, st);
          if (!r || r.recursive || r.schema.type === "null") return;
          const sub = this.collect(r.schema, [...st, ...r.refs], d + 1);
          const props = new Map(sub.props);
          for (const v of sub.variants) for (const [k, p] of v.props) if (!props.has(k)) props.set(k, p);
          if (!props.size) return;
          view.variants.push({ kind, label: r.names.at(-1) ?? `${kind}[${i}]`, props, required: sub.required });
        });
      }
    };
    visit(s, stack, depth);
    return view;
  }

  private emitObject(view: ObjectView, prefix: string, depth: number, out: Field[]): void {
    if (depth > MAX_DEPTH) return this.warnDepth();
    for (const [name, entry] of view.props) {
      this.emitProperty(name, entry, view.required.has(name), prefix, depth, out, undefined);
    }
    const emitted = new Set(view.props.keys());
    for (const v of view.variants) {
      for (const [name, entry] of v.props) {
        if (emitted.has(name)) continue;
        emitted.add(name);
        const inAll = view.variants.every((o) => o.props.has(name));
        const required = inAll && view.variants.every((o) => o.required.has(name));
        this.emitProperty(name, entry, required, prefix, depth, out, inAll ? undefined : `${v.kind}:${v.label}`);
      }
    }
  }

  private emitProperty(
    name: string,
    entry: PropEntry,
    required: boolean,
    prefix: string,
    depth: number,
    out: Field[],
    variant: string | undefined,
  ): void {
    const path = prefix ? `${prefix}.${name}` : name;
    const base: Field = { path, name, type: "unknown", nullable: false, required };
    if (variant) base.variant = variant;

    const r = this.resolve(entry.node, entry.stack);
    if (!r) {
      out.push(base);
      return;
    }
    const lastName = r.names.at(-1);
    if (r.recursive) {
      out.push({ ...base, type: "object", recursive: true, ...(lastName ? { ref: lastName } : {}) });
      return;
    }
    const stack = [...entry.stack, ...r.refs];
    const s = r.schema;
    const ti = this.typeInfo(s, stack);
    const field: Field = { ...base, type: ti.type, nullable: ti.nullable };
    if (typeof s.format === "string") field.format = s.format;
    const en = enumOf(s);
    if (en) field.enum = en;
    if (lastName) field.ref = lastName;
    out.push(field);

    if (ti.type === "array") {
      const ir = this.resolve(s.items, stack);
      if (!ir) return;
      const itemName = ir.names.at(-1);
      if (itemName && !field.ref) field.ref = itemName;
      if (ir.recursive) {
        field.recursive = true;
        return;
      }
      if (isObjectLike(ir.schema)) {
        this.emitObject(this.collect(ir.schema, [...stack, ...ir.refs], depth + 1), `${path}[]`, depth + 1, out);
      }
    } else if (isObjectLike(s)) {
      this.emitObject(this.collect(s, stack, depth + 1), path, depth + 1, out);
    }
  }

  private warnDepth(): void {
    if (this.depthWarned) return;
    this.depthWarned = true;
    this.warnings.push(`Schema nesting deeper than ${MAX_DEPTH} levels was truncated.`);
  }
}

function asArray(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function isObjectLike(s: Record<string, unknown>): boolean {
  return (
    s.type === "object" ||
    (Array.isArray(s.type) && s.type.includes("object")) ||
    isRecord(s.properties) ||
    asArray(s.allOf).length > 0 ||
    asArray(s.oneOf).some((b) => isRecord(b) && (isRecord(b.properties) || typeof b.$ref === "string" || b.type === "object")) ||
    asArray(s.anyOf).some((b) => isRecord(b) && (isRecord(b.properties) || typeof b.$ref === "string" || b.type === "object"))
  );
}

function enumOf(s: Record<string, unknown>): JsonPrimitive[] | undefined {
  const isPrim = (v: unknown): v is JsonPrimitive =>
    v === null || typeof v === "string" || typeof v === "number" || typeof v === "boolean";
  if (Array.isArray(s.enum)) return s.enum.filter(isPrim);
  if ("const" in s && isPrim(s.const)) return [s.const];
  return undefined;
}
