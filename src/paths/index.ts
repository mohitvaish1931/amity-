// The one place that turns OpenAPI path templates ("/orgs/{orgId}/users/{userId}") into concrete paths.

const PARAM = /\{([^{}]+)\}/g;

export class PathParameterError extends Error {
  constructor(
    message: string,
    readonly template: string,
    readonly parameters: readonly string[],
  ) {
    super(message);
    this.name = new.target.name;
  }
}

/** A template parameter has no value. `parameters` lists every missing name, in template order. */
export class MissingPathParameterError extends PathParameterError {}

/** A value cannot be used safely as a path segment. */
export class InvalidPathParameterError extends PathParameterError {}

export type PathParamValue = string | number | bigint;

export interface FillPathOptions {
  /**
   * "throw" (default): missing parameters raise MissingPathParameterError.
   * "keep": missing parameters stay as "{name}". Only for human-readable display, never for requests.
   */
  onMissing?: "throw" | "keep";
}

/** Parameter names in template order, including repeats ("/a/{x}/b/{x}" -> ["x", "x"]). */
export function pathParamNames(template: string): string[] {
  return [...template.matchAll(PARAM)].map((m) => m[1]!);
}

/** Name of the last path parameter, i.e. the object the path addresses, or null. */
export function lastPathParam(template: string): string | null {
  return pathParamNames(template).at(-1) ?? null;
}

function encodeValue(template: string, name: string, value: unknown): string {
  let text: string;
  if (typeof value === "string") text = value;
  else if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new InvalidPathParameterError(`Path parameter "${name}" must be a finite number.`, template, [name]);
    text = String(value);
  } else if (typeof value === "bigint") text = value.toString();
  else throw new InvalidPathParameterError(`Path parameter "${name}" must be a string or number, got ${value === null ? "null" : typeof value}.`, template, [name]);

  if (text === "") throw new InvalidPathParameterError(`Path parameter "${name}" must not be empty.`, template, [name]);
  // "." and ".." are dot-segments: URL parsers resolve them even when percent-encoded,
  // which would silently change the addressed path.
  if (text === "." || text === "..") throw new InvalidPathParameterError(`Path parameter "${name}" must not be a dot-segment ("${text}").`, template, [name]);
  return encodeURIComponent(text);
}

/**
 * Fill every "{name}" in `template` from `params` (matched by exact name, so "{id}" never touches "{userId}").
 * Values are percent-encoded as a single path segment ("a/b" -> "a%2Fb"). Inputs are not mutated.
 */
export function fillPath(template: string, params: Readonly<Record<string, unknown>>, options: FillPathOptions = {}): string {
  const onMissing = options.onMissing ?? "throw";
  const has = (name: string) => Object.prototype.hasOwnProperty.call(params, name) && params[name] !== undefined && params[name] !== null;

  if (onMissing === "throw") {
    const missing = [...new Set(pathParamNames(template).filter((n) => !has(n)))];
    if (missing.length) {
      throw new MissingPathParameterError(
        `Missing value${missing.length > 1 ? "s" : ""} for path parameter${missing.length > 1 ? "s" : ""} ${missing.map((m) => `"${m}"`).join(", ")} in "${template}".`,
        template,
        missing,
      );
    }
  }
  return template.replace(PARAM, (whole, name: string) => (has(name) ? encodeValue(template, name, params[name]) : whole));
}
