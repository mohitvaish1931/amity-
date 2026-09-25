// Sandbox target policy: which hosts a user may register as a test target, and a guard that keeps every request
// inside the registered target. Hosts are classified from the parsed URL (never by substring). A browser cannot
// resolve DNS, so names are classified by their suffix: a reserved/private name is trusted to point at the user's
// own environment. Public internet hosts cannot be registered at all.
import { normalizeTargetUrl } from "./authorization";

export type HostClass = "loopback" | "private-network" | "reserved-name" | "link-local" | "unspecified" | "public" | "invalid";

export interface HostAssessment {
  /** Normalized base URL (origin + path, no trailing slash), or null when invalid. */
  baseUrl: string | null;
  host: string | null;
  hostClass: HostClass;
  /** Whether this host may be registered as a sandbox target. */
  registrable: boolean;
  reason: string;
}

/** Special-use names (RFC 2606, RFC 6761, RFC 6762, RFC 8375) and ICANN's private-use `.internal`. */
const RESERVED_SUFFIXES = [".test", ".example", ".invalid", ".localhost", ".local", ".home.arpa", ".internal"];
const REGISTRABLE: ReadonlySet<HostClass> = new Set(["loopback", "private-network", "reserved-name"]);

function ipv4(host: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((p) => p <= 255) ? parts : null;
}

function classifyIpv4([a, b]: number[]): HostClass {
  if (a === 127) return "loopback";
  if (a === 0) return "unspecified";
  if (a === 169 && b === 254) return "link-local"; // includes cloud metadata endpoints
  if (a === 10 || (a === 172 && b! >= 16 && b! <= 31) || (a === 192 && b === 168)) return "private-network";
  return "public";
}

function classifyIpv6(host: string): HostClass {
  const h = host.slice(1, -1).toLowerCase(); // URL.hostname keeps IPv6 in brackets
  if (h === "::1") return "loopback";
  if (h === "::") return "unspecified";
  if (/^fe[89ab]/.test(h)) return "link-local";
  if (/^f[cd]/.test(h)) return "private-network"; // unique local addresses fc00::/7
  // Everything else, including IPv4-mapped forms, is treated as public rather than decoded.
  return "public";
}

export function classifyHost(hostname: string): HostClass {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (!host) return "invalid";
  if (host.startsWith("[")) return classifyIpv6(host);
  const v4 = ipv4(host);
  if (v4) return classifyIpv4(v4);
  if (host === "localhost" || host.endsWith(".localhost")) return "loopback";
  if (RESERVED_SUFFIXES.some((s) => host.endsWith(s))) return "reserved-name";
  return "public";
}

const REASONS: Record<HostClass, string> = {
  loopback: "Loopback host (this machine).",
  "private-network": "Private-network address.",
  "reserved-name": "Reserved or private-use name (e.g. .test, .localhost, .internal); assumed to point at your own environment.",
  "link-local": "Link-local address: this range includes cloud metadata services and cannot be a test target.",
  unspecified: "Unspecified address (0.0.0.0 / ::) cannot be a test target.",
  public: "Public internet host: this build only tests sandboxes on this machine or a private network.",
  invalid: "Not a valid http(s) URL without embedded credentials.",
};

export function assessTargetHost(raw: string | null | undefined): HostAssessment {
  const baseUrl = normalizeTargetUrl(raw);
  if (!baseUrl) return { baseUrl: null, host: null, hostClass: "invalid", registrable: false, reason: REASONS.invalid };
  const url = new URL(baseUrl);
  // Normalization drops query and fragment; refuse them instead of registering a different URL than the one typed.
  const typed = new URL((raw ?? "").trim());
  if (typed.search || typed.hash) {
    return { baseUrl: null, host: url.hostname, hostClass: "invalid", registrable: false, reason: "A target base URL must not contain a query or fragment." };
  }
  const hostClass = classifyHost(url.hostname);
  return { baseUrl, host: url.hostname, hostClass, registrable: REGISTRABLE.has(hostClass), reason: REASONS[hostClass] };
}

/** A sandbox target the user registered. Authorization is the user's statement, not something verified here. */
export interface Target {
  id: string;
  name: string;
  baseUrl: string;
  origin: string;
  /** Path prefix every request must stay under ("" for the origin root). */
  basePath: string;
  environment: "sandbox";
  authorizationStatus: "AUTHORIZED_BY_CONFIGURATION";
  hostClass: HostClass;
  registeredAt: string;
}

export type RegisterResult = { ok: true; target: Target } | { ok: false; reason: string; assessment: HostAssessment };

export function registerTarget(raw: string, opts: { id: string; name?: string; registeredAt: string }): RegisterResult {
  const a = assessTargetHost(raw);
  if (!a.registrable || !a.baseUrl) return { ok: false, reason: a.reason, assessment: a };
  const url = new URL(a.baseUrl);
  return {
    ok: true,
    target: {
      id: opts.id,
      name: opts.name?.trim() || url.host,
      baseUrl: a.baseUrl,
      origin: url.origin,
      basePath: url.pathname === "/" ? "" : url.pathname,
      environment: "sandbox",
      authorizationStatus: "AUTHORIZED_BY_CONFIGURATION",
      hostClass: a.hostClass,
      registeredAt: opts.registeredAt,
    },
  };
}

export function findTarget(targets: readonly Target[], raw: string | null | undefined): Target | null {
  const n = normalizeTargetUrl(raw);
  return (n && targets.find((t) => t.baseUrl === n)) || null;
}

export class TargetScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TargetScopeError";
  }
}

/**
 * The absolute URL for `path` on `target`, guaranteed to stay on the target's origin and under its base path.
 * Joins by string (not URL resolution), so a path like "//other.host/x" cannot switch hosts.
 */
export function resolveRequestUrl(target: Target, path: string): string {
  if (!path.startsWith("/")) throw new TargetScopeError(`Request path must start with "/": ${path}`);
  if (path.includes("\\")) throw new TargetScopeError(`Request path must not contain backslashes: ${path}`);
  let url: URL;
  try {
    url = new URL(target.baseUrl + path);
  } catch {
    throw new TargetScopeError(`Request path does not form a valid URL: ${path}`);
  }
  if (url.origin !== target.origin) throw new TargetScopeError(`Request would leave the registered target (${url.origin} ≠ ${target.origin}).`);
  const underBase = !target.basePath || url.pathname === target.basePath || url.pathname.startsWith(`${target.basePath}/`);
  if (!underBase) throw new TargetScopeError(`Request path escapes the target base path ${target.basePath}: ${url.pathname}`);
  return url.href;
}
