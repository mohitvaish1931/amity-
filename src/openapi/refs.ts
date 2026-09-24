import { isRecord, type SpecDocument } from "./load";

const MAX_REF_HOPS = 32;

/** Resolves local JSON-pointer $refs ("#/components/schemas/X"). External refs are reported, not fetched. */
export class RefResolver {
  private readonly reported = new Set<string>();

  constructor(
    private readonly doc: SpecDocument,
    private readonly warnings: string[],
  ) {}

  /** Resolve one $ref string. Returns undefined (and records a warning once) when it cannot be resolved. */
  resolve(ref: string): unknown {
    if (!ref.startsWith("#")) {
      this.warnOnce(ref, `External $ref "${ref}" is not supported; treated as unknown.`);
      return undefined;
    }
    const pointer = ref.slice(1);
    if (pointer === "") return this.doc;
    if (!pointer.startsWith("/")) {
      this.warnOnce(ref, `Malformed $ref "${ref}".`);
      return undefined;
    }
    let cur: unknown = this.doc;
    for (const rawSeg of pointer.slice(1).split("/")) {
      const seg = decodePointerSegment(rawSeg);
      if (Array.isArray(cur)) cur = cur[Number(seg)];
      else if (isRecord(cur)) cur = cur[seg];
      else cur = undefined;
      if (cur === undefined) break;
    }
    if (cur === undefined) this.warnOnce(ref, `Unresolved $ref "${ref}".`);
    return cur;
  }

  /**
   * Follow a chain of $ref objects (parameter, requestBody, response, path item, security scheme)
   * until a concrete object is reached. Cycles and dead ends return undefined.
   */
  deref(node: unknown): Record<string, unknown> | undefined {
    let cur = node;
    const seen = new Set<string>();
    for (let hops = 0; hops < MAX_REF_HOPS; hops++) {
      if (!isRecord(cur)) return undefined;
      const ref = cur.$ref;
      if (typeof ref !== "string") return cur;
      if (seen.has(ref)) {
        this.warnOnce(ref, `Circular $ref chain at "${ref}".`);
        return undefined;
      }
      seen.add(ref);
      cur = this.resolve(ref);
    }
    return undefined;
  }

  private warnOnce(key: string, message: string): void {
    if (this.reported.has(key)) return;
    this.reported.add(key);
    this.warnings.push(message);
  }
}

export function decodePointerSegment(seg: string): string {
  let s = seg;
  try {
    s = decodeURIComponent(seg);
  } catch {
    // keep raw segment
  }
  return s.replace(/~1/g, "/").replace(/~0/g, "~");
}

/** "#/components/schemas/Order" -> "Order" */
export function refName(ref: string): string {
  const parts = ref.split("/");
  return decodePointerSegment(parts[parts.length - 1] ?? ref);
}
