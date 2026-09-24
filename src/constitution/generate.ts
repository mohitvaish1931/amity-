// Security Constitution engine: derives security laws from the typed API model and configuration.
// Pure and deterministic. Every law carries its provenance and an explainable confidence rating.
// Test strategies are specifications only; nothing here performs requests.
import type {
  ApiModel,
  Confidence,
  ConfidenceSignal,
  Endpoint,
  Identity,
  LawCategory,
  LawRule,
  LawScope,
  Provenance,
  Resource,
  Role,
  SecurityConstitution,
  SecurityLaw,
  Sensitivity,
  Severity,
  TestStrategy,
} from "../contracts";
import { resourceName, schemaBaseName, tokenize } from "../model";
import { matchPermissions, permissionRef, type PermissionMatch } from "./permissions";

export interface ConstitutionConfig {
  identities?: readonly Identity[];
  roles?: readonly Role[];
  /** Configured object -> owner map (not typed by resource). */
  ownership?: readonly { objectId: string; ownerId: string }[];
  /** "Resource.fieldPath" -> analyst override. */
  sensitivityOverrides?: Readonly<Record<string, Sensitivity>>;
}

export const CATEGORY_ORDER: readonly LawCategory[] = [
  "OBJECT_AUTHORIZATION",
  "FUNCTION_AUTHORIZATION",
  "DATA_EXPOSURE",
  "AUTHENTICATION",
  "STATE_TRANSITION",
  "SECURITY_CONFIGURATION",
];
const CONFIDENCE_RANK: Record<Confidence, number> = { HIGH: 0, MEDIUM: 1, LOW: 2 };
const SEVERITY_RANK: Record<Severity, number> = { Critical: 0, High: 1, Medium: 2, Low: 3 };
const SENSITIVE: readonly Sensitivity[] = ["PERSONAL", "SENSITIVE"];
const STATE_WORDS = new Set(["status", "state", "stage", "phase", "lifecycle"]);

interface Draft {
  key: string;
  category: LawCategory;
  severity: Severity;
  statement: string;
  rule: LawRule;
  scope: LawScope;
  provenance: Provenance[];
  signals: ConfidenceSignal[];
  /** Explains the thresholds; `level` computes the result from present signal ids. */
  confidenceRule: string;
  level: (present: ReadonlySet<string>) => Confidence;
  testStrategy: TestStrategy;
}

// ---------- small helpers ----------

const label = (e: Endpoint) => `${e.method} ${e.path}`;
const uniq = <T>(xs: readonly T[]) => [...new Set(xs)];
const sorted = (xs: readonly string[]) => uniq(xs).sort((a, b) => a.localeCompare(b));
const list = (xs: readonly string[], max = 4) => (xs.length <= max ? xs.join(", ") : `${xs.slice(0, max).join(", ")} +${xs.length - max} more`);
const andList = (xs: readonly string[]) => (xs.length <= 1 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);
const signal = (id: string, description: string, present: boolean): ConfidenceSignal => ({ id, description, present });
const emptyScope = (): LawScope => ({ endpoints: [], resources: [], fields: [], roles: [], identities: [] });
const isRead = (e: Endpoint) => e.method === "GET" || e.method === "HEAD";

/** Resources addressed by path parameters: "/orders/{id}/invoice" addresses Order through {id}. */
export function addressedResources(e: Endpoint, resources: readonly Resource[]): { param: string; resource: string }[] {
  const segs = e.path.split("/").filter(Boolean);
  const out: { param: string; resource: string }[] = [];
  segs.forEach((seg, i) => {
    const m = /^\{([^{}]+)\}$/.exec(seg);
    const prev = segs[i - 1];
    if (!m || !prev || prev.includes("{")) return;
    const name = resourceName(prev);
    if (resources.some((r) => r.name === name)) out.push({ param: m[1]!, resource: name });
  });
  return out;
}

function schemaOwner(schema: string, resources: readonly Resource[]): string | undefined {
  return (
    resources.find((r) => r.schemaNames.includes(schema))?.name ??
    resources.find((r) => r.name === schema)?.name ??
    resources.find((r) => r.name === schemaBaseName(schema))?.name
  );
}

/** Endpoints whose success response returns a schema that belongs to `resource`. */
function returningEndpoints(resource: string, model: ApiModel): Map<string, string> {
  const out = new Map<string, string>(); // endpoint id -> schema name
  for (const r of model.resources) {
    for (const rel of r.relations) {
      if (rel.kind === "returned-by" && schemaOwner(rel.from, model.resources) === resource) out.set(rel.to, rel.from);
    }
  }
  return out;
}

function mergeRule(a: LawRule, b: LawRule): LawRule {
  const merged: Record<string, unknown> = { ...a };
  for (const [k, v] of Object.entries(b)) {
    const cur = merged[k];
    if (Array.isArray(cur) && Array.isArray(v)) merged[k] = sorted([...cur, ...v] as string[]);
  }
  return merged as LawRule;
}

function mergeScope(a: LawScope, b: LawScope): LawScope {
  return {
    endpoints: sorted([...a.endpoints, ...b.endpoints]),
    resources: sorted([...a.resources, ...b.resources]),
    fields: sorted([...a.fields, ...b.fields]),
    roles: sorted([...a.roles, ...b.roles]),
    identities: sorted([...a.identities, ...b.identities]),
  };
}

function renderInvariant(rule: LawRule): string {
  const eps = (xs: readonly string[]) => `{${xs.join(", ")}}`;
  switch (rule.type) {
    case "requires-authentication":
      return `∀ request r to ${eps(rule.endpoints)}: ¬authenticated(r, ${rule.schemes.join(" | ") || "declared scheme"}) ⇒ DENY(r)`;
    case "owner-only-access":
      return rule.ownershipField
        ? `∀ caller c ∈ roles{${rule.subjectRoles.join(", ")}}, ${rule.resource} o via ${eps(rule.endpoints)}: ALLOW(c, o) ⇒ o.${rule.ownershipField} = c`
        : `∀ caller c, ${rule.resource} o via ${eps(rule.endpoints)}: ALLOW(c, o) ⇒ authorized(c, o)`;
    case "role-restricted":
      return `∀ caller c, request to ${eps(rule.endpoints)}: ALLOW(c) ⇒ role(c) ∈ {${rule.allowedRoles.join(", ")}}` +
        (rule.deniedRoles.length ? `; role(c) ∈ {${rule.deniedRoles.join(", ")}} ⇒ DENY(c)` : "");
    case "no-unauthorized-field-exposure": {
      const parent = rule.inheritedFrom ? rule.inheritedFrom.split(".") : null;
      const condition = rule.ownershipField
        ? `o.${rule.ownershipField} ≠ c`
        : parent
          ? `${parent[0]}(o).${parent.slice(1).join(".")} ≠ c`
          : `¬entitled(c, o)`;
      return `∀ caller c, ${rule.resource} o returned by ${eps(rule.endpoints)}: ${condition} ⇒ fields(response) ∩ {${rule.fields.join(", ")}} = ∅`;
    }
    case "guarded-state-transition":
      return `∀ change of ${rule.resource}.${rule.stateField} via ${eps(rule.endpoints)}: (from, to) ∈ allowedTransitions ∧ authorized(caller)`;
    case "explicit-public-access":
      return `∀ request r to ${eps(rule.endpoints)} (auth ${rule.mode}): fields(response) ∩ sensitive = ∅` +
        (rule.exposesSensitiveFields.length ? ` — currently declares {${rule.exposesSensitiveFields.join(", ")}}` : "");
    case "declared-security-schemes":
      return `∀ scheme s required by ${eps(rule.endpoints)}: s ∈ declaredSchemes — undeclared {${rule.undeclaredSchemes.join(", ")}}`;
    case "permission-matrix":
      return `∀ role r, action a ∈ {${rule.contestedActions.join(", ")}}: ALLOW(r, a) ⟺ permission(r, a) = true`;
  }
}

// ---------- generator ----------

export function generateSecurityConstitution(model: ApiModel, config: ConstitutionConfig = {}): SecurityConstitution {
  const identities = config.identities ?? [];
  const configRoles = config.roles ?? [];
  const roleNames = sorted([...configRoles.map((r) => r.name), ...identities.map((i) => i.role).filter(Boolean)]);
  const roleOf = (name: string): Role => configRoles.find((r) => r.name === name) ?? { name, permissions: {}, privileged: false };
  const privileged = roleNames.filter((r) => roleOf(r).privileged);
  const nonPrivileged = roleNames.filter((r) => !roleOf(r).privileged);
  const identitiesOf = (roles: readonly string[]) => sorted(identities.filter((i) => roles.includes(i.role)).map((i) => i.id));
  const nameOf = (id: string) => identities.find((i) => i.id === id)?.name || id;
  const overrides = config.sensitivityOverrides ?? {};
  const sensitivity = (r: Resource, path: string, base: Sensitivity) => overrides[`${r.name}.${path}`] ?? base;
  const permissions = matchPermissions(configRoles, model.resources);
  const byId = new Map(model.endpoints.map((e) => [e.id, e]));

  const ownershipByOwner = new Map<string, string[]>();
  for (const o of config.ownership ?? []) {
    if (!identities.some((i) => i.id === o.ownerId)) continue;
    ownershipByOwner.set(o.ownerId, [...(ownershipByOwner.get(o.ownerId) ?? []), String(o.objectId)]);
  }
  const ownedResources = model.resources.filter((r) => r.ownershipField);

  const drafts = new Map<string, Draft>();
  const notes: string[] = [];
  const add = (d: Draft) => {
    const cur = drafts.get(d.key);
    if (!cur) {
      drafts.set(d.key, d);
      return;
    }
    // Same key = same law: merge evidence instead of producing a duplicate.
    cur.rule = mergeRule(cur.rule, d.rule);
    cur.scope = mergeScope(cur.scope, d.scope);
    for (const p of d.provenance) if (!cur.provenance.some((x) => x.ref === p.ref)) cur.provenance.push(p);
    for (const s of d.signals) {
      const existing = cur.signals.find((x) => x.id === s.id);
      if (!existing) cur.signals.push(s);
      else existing.present = existing.present || s.present;
    }
  };

  // ---- AUTHENTICATION: one law per distinct security requirement ----
  const requiredGroups = new Map<string, Endpoint[]>();
  for (const e of model.endpoints) {
    if (e.auth.mode !== "required") continue;
    const k = e.auth.alternatives.map((a) => a.schemes.map((s) => s.name).sort().join("+")).sort().join(" | ");
    requiredGroups.set(k, [...(requiredGroups.get(k) ?? []), e]);
  }
  for (const [k, eps] of requiredGroups) {
    const schemes = uniq(eps.flatMap((e) => e.auth.alternatives.flatMap((a) => a.schemes)));
    const schemeNames = sorted(schemes.map((s) => s.name));
    const allDeclared = schemes.every((s) => s.known);
    const typed = schemes.every((s) => s.type !== "unknown");
    const fromRoot = eps.filter((e) => e.auth.source === "root").length;
    add({
      key: `AUTHENTICATION:${k}`,
      category: "AUTHENTICATION",
      severity: "High",
      statement: `Endpoints secured by ${k.replace(/ \| /g, " or ").replace(/\+/g, " + ")} must reject requests without valid credentials.`,
      rule: { type: "requires-authentication", endpoints: eps.map((e) => e.id), schemes: schemeNames },
      scope: { ...emptyScope(), endpoints: eps.map((e) => e.id) },
      provenance: [
        ...uniq(schemes.map((s) => s.name)).map((name) => {
          const s = schemes.find((x) => x.name === name)!;
          return { kind: "security" as const, ref: `security:${name}`, detail: s.known ? `declared scheme (${s.type}${s.scheme ? ` ${s.scheme}` : ""})` : "referenced but not declared in the spec" };
        }),
        ...eps.map((e) => ({ kind: "endpoint" as const, ref: `endpoint:${label(e)}`, detail: e.auth.detail })),
      ],
      signals: [
        signal("explicit", `security requirement declared (${eps.length - fromRoot} at operation level, ${fromRoot} inherited from root)`, true),
        signal("declared-schemes", "every referenced scheme is declared", allDeclared),
        signal("typed-schemes", "every scheme has a known type", typed),
      ],
      confidenceRule: "HIGH: declared requirement with declared, typed schemes. MEDIUM: declared requirement but a scheme is undeclared or untyped.",
      level: (p) => (p.has("declared-schemes") && p.has("typed-schemes") ? "HIGH" : "MEDIUM"),
      testStrategy: {
        kind: "anonymous-access-denied",
        preconditions: [`${eps.length} endpoint(s): ${list(eps.map(label))}`, "Request values built from each operation's parameter and body schemas"],
        steps: [
          "For each endpoint, build a schema-valid request.",
          "Send it without any credentials.",
          `Send it with an invalid or expired credential for ${schemeNames.join(", ") || "the scheme"}.`,
        ],
        expected: "Every request is rejected (401/403) and the response contains no resource data.",
        executable: false,
      },
    });
  }

  // ---- OBJECT_AUTHORIZATION: one law per resource addressed by identifier ----
  for (const r of model.resources) {
    const addressing = model.endpoints
      .map((e) => ({ e, via: addressedResources(e, model.resources).filter((a) => a.resource === r.name) }))
      .filter((x) => x.via.length > 0);
    if (!addressing.length) continue;

    const exempt = sorted(permissions.filter((m) => m.resource === r.name && m.allowed && m.qualifier === "foreign").map((m) => m.role));
    // The configured ownership map is only meaningful for resources that have an ownership field;
    // applying it elsewhere would attach unrelated objects to this law.
    const owners = !r.ownershipField
      ? []
      : [...ownershipByOwner.keys()].filter((id) => {
          const role = identities.find((i) => i.id === id)?.role ?? "";
          return nonPrivileged.includes(role) && !exempt.includes(role);
        });
    const ownerRoles = sorted(owners.map((id) => identities.find((i) => i.id === id)!.role));
    const subjectRoles = ownerRoles.length ? ownerRoles : nonPrivileged.filter((x) => !exempt.includes(x));
    const supporting = permissions.filter(
      (m) => m.resource === r.name && subjectRoles.includes(m.role) && ((m.qualifier === "foreign" && !m.allowed) || (m.qualifier === "own" && m.allowed)),
    );
    const eps = addressing.map((x) => x.e);
    const f = r.ownershipField;
    const provenance: Provenance[] = addressing.map(({ e, via }) => ({
      kind: "path",
      ref: `endpoint:${label(e)}`,
      detail: `path parameter {${via[0]!.param}} identifies a ${r.name}`,
    }));
    if (f) provenance.push({ kind: "schema", ref: `schema:${r.name}.${f}`, detail: "ownership field inferred from the schema" });
    if (owners.length) {
      provenance.push({
        kind: "ownership",
        ref: "ownership:config",
        detail: `configured owners: ${owners.map((id) => `${nameOf(id)} (${(ownershipByOwner.get(id) ?? []).join(", ")})`).join("; ")}`,
      });
    }
    for (const role of subjectRoles) provenance.push({ kind: "role", ref: `role:${role}`, detail: "non-privileged role subject to ownership checks" });
    for (const role of exempt) provenance.push({ kind: "role", ref: `role:${role}`, detail: "exempt: permission allows access to other identities' objects" });
    for (const m of supporting) provenance.push({ kind: "permission", ref: permissionRef(m), detail: `matched to ${r.name} by name (${m.qualifier} ${m.operation})` });

    const preconditions: string[] = [];
    if (!f) {
      preconditions.push(`The model does not describe how a ${r.name} is owned; provide the ownership rule and objects of at least two identities.`);
    } else if (owners.length >= 2) {
      for (const id of owners) preconditions.push(`${nameOf(id)} owns ${(ownershipByOwner.get(id) ?? []).join(", ")}`);
      if (ownedResources.length > 1) preconditions.push(`The ownership map is not typed by resource; confirm these objects are ${r.name}s.`);
    } else {
      preconditions.push("Needs objects owned by at least two identities (ownership map).");
    }

    add({
      key: `OBJECT_AUTHORIZATION:${r.name}`,
      category: "OBJECT_AUTHORIZATION",
      severity: "High",
      statement: f
        ? `${andList(subjectRoles) || "Callers"} may access only ${r.name} objects they own (ownership field ${r.name}.${f}).`
        : `Access to ${r.name} objects by identifier must be authorized per object; the model does not describe who owns a ${r.name}.`,
      rule: { type: "owner-only-access", resource: r.name, ownershipField: f, subjectRoles, endpoints: eps.map((e) => e.id), operations: uniq(eps.map((e) => (isRead(e) ? "read" : "write"))) as ("read" | "write")[] },
      scope: { endpoints: eps.map((e) => e.id), resources: [r.name], fields: f ? [`${r.name}.${f}`] : [], roles: subjectRoles, identities: identitiesOf(subjectRoles).filter((id) => !owners.length || owners.includes(id)) },
      provenance,
      signals: [
        signal("ownership-field", f ? `ownership field ${r.name}.${f}` : "no ownership field in the schema", !!f),
        signal("addressed-by-id", `${eps.length} endpoint(s) address a ${r.name} by identifier`, true),
        signal(
          "foreign-object",
          !f ? "ownership map not applicable: no ownership field" : owners.length >= 2 ? `objects owned by ${owners.length} identities are configured` : "objects of at least two owners are not configured",
          owners.length >= 2,
        ),
        signal("authenticated", "all addressing endpoints require authentication", eps.every((e) => e.auth.mode === "required")),
        signal("permission", supporting.length ? "configured permissions restrict access to own objects" : "no permission mentions own/foreign access", supporting.length > 0),
      ],
      confidenceRule: "HIGH: ownership field + objects of ≥2 owners + authentication required. MEDIUM: ownership field. LOW: otherwise.",
      level: (p) => (p.has("ownership-field") && p.has("foreign-object") && p.has("authenticated") ? "HIGH" : p.has("ownership-field") ? "MEDIUM" : "LOW"),
      testStrategy: {
        kind: "cross-owner-object-access",
        preconditions,
        steps: [
          `Pick identity A (${andList(subjectRoles) || "a non-privileged role"}) and a ${r.name} that A owns.`,
          `Pick a ${r.name} owned by a different identity B.`,
          `For each of ${list(eps.map(label))}: request A's own object as A (positive control).`,
          "Request B's object as A.",
          "Request A's object without credentials.",
        ],
        expected: "Own object allowed; the other identity's object denied (403/404) with no object data; anonymous request denied.",
        executable: false,
      },
    });
  }

  // ---- FUNCTION_AUTHORIZATION (a): administrative endpoints, one law per resource ----
  const adminByResource = new Map<string, Endpoint[]>();
  for (const e of model.endpoints) if (e.action === "AdminAction") adminByResource.set(e.resource, [...(adminByResource.get(e.resource) ?? []), e]);
  for (const [res, eps] of adminByResource) {
    const related = permissions.filter((m) => m.resource === res && (m.operation === "admin" || m.operation === "any"));
    const denies = related.filter((m) => !m.allowed && nonPrivileged.includes(m.role));
    const allows = related.filter((m) => m.allowed && privileged.includes(m.role));
    const allowed = privileged;
    const denied = nonPrivileged;
    add({
      key: `FUNCTION_AUTHORIZATION:admin:${res}`,
      category: "FUNCTION_AUTHORIZATION",
      severity: "High",
      statement: allowed.length
        ? `Only ${andList(allowed)} may invoke ${list(eps.map(label))}; ${andList(denied) || "all other roles"} must be denied.`
        : `Administrative operations ${list(eps.map(label))} must be restricted to a privileged role; none is configured.`,
      rule: { type: "role-restricted", endpoints: eps.map((e) => e.id), allowedRoles: allowed, deniedRoles: denied },
      scope: { endpoints: eps.map((e) => e.id), resources: [res], fields: [], roles: sorted([...allowed, ...denied]), identities: identitiesOf([...allowed, ...denied]) },
      provenance: [
        ...eps.map((e) => ({ kind: "endpoint" as const, ref: `endpoint:${label(e)}`, detail: "path marks an administrative operation" })),
        ...allowed.map((r) => ({ kind: "role" as const, ref: `role:${r}`, detail: `privileged: ${roleOf(r).privilegeEvidence ?? "configured as privileged"}` })),
        ...denied.map((r) => ({ kind: "role" as const, ref: `role:${r}`, detail: "non-privileged role: must be denied" })),
        ...[...denies, ...allows].map((m) => ({ kind: "permission" as const, ref: permissionRef(m), detail: `matched to ${res} by name (${m.operation})` })),
      ],
      signals: [
        signal("privileged-role", allowed.length ? `privileged role(s): ${allowed.join(", ")}` : "no privileged role configured", allowed.length > 0),
        signal("other-roles", denied.length ? `non-privileged role(s): ${denied.join(", ")}` : "no non-privileged roles configured", denied.length > 0),
        signal("explicit-deny", denies.length ? "configured permissions deny a non-privileged role" : "no permission explicitly denies a non-privileged role", denies.length > 0),
        signal("explicit-allow", allows.length ? "configured permissions allow the privileged role" : "no permission explicitly allows the privileged role", allows.length > 0),
        signal("authenticated", "all administrative endpoints require authentication", eps.every((e) => e.auth.mode === "required")),
      ],
      confidenceRule: "HIGH: privileged role + other roles + explicit deny permission. MEDIUM: privileged role + other roles. LOW: otherwise.",
      level: (p) => (p.has("privileged-role") && p.has("other-roles") && p.has("explicit-deny") ? "HIGH" : p.has("privileged-role") && p.has("other-roles") ? "MEDIUM" : "LOW"),
      testStrategy: {
        kind: "role-boundary",
        preconditions: [`Identities for denied roles (${andList(denied) || "none configured"}) and allowed roles (${andList(allowed) || "none configured"})`],
        steps: [
          `As an identity of each denied role, call ${list(eps.map(label))} with a schema-valid request.`,
          "Repeat the same request as an identity of an allowed role (positive control).",
          "Repeat without credentials.",
        ],
        expected: "Denied roles receive 403 and no state changes; allowed roles succeed; anonymous requests are rejected.",
        executable: false,
      },
    });
  }

  // ---- FUNCTION_AUTHORIZATION (b): explicit permission denies on regular endpoints ----
  const opMatches = (m: PermissionMatch, e: Endpoint) =>
    e.action !== "AdminAction" &&
    ((m.operation === "read" && isRead(e)) ||
      (m.operation === "create" && e.action === "Create") ||
      (m.operation === "update" && e.action === "Update") ||
      (m.operation === "delete" && e.action === "Delete"));
  const denyGroups = new Map<string, PermissionMatch[]>();
  for (const m of permissions) {
    if (m.allowed || m.qualifier !== "any" || !nonPrivileged.includes(m.role)) continue;
    const k = `${m.resource}:${m.operation}`;
    denyGroups.set(k, [...(denyGroups.get(k) ?? []), m]);
  }
  for (const [k, denies] of denyGroups) {
    const { resource, operation } = denies[0]!;
    const eps = model.endpoints.filter((e) => e.resource === resource && opMatches(denies[0]!, e));
    if (!eps.length) continue;
    const deniedRoles = sorted(denies.map((m) => m.role));
    const allowedBy = permissions.filter((x) => x.allowed && x.resource === resource && x.operation === operation && x.qualifier === "any" && !deniedRoles.includes(x.role));
    const allowedRoles = sorted(allowedBy.map((x) => x.role));
    add({
      key: `FUNCTION_AUTHORIZATION:${k}`,
      category: "FUNCTION_AUTHORIZATION",
      severity: "High",
      statement: `${andList(deniedRoles)} must not ${operation} ${resource} (${list(eps.map(label))}).`,
      rule: { type: "role-restricted", endpoints: eps.map((e) => e.id), allowedRoles, deniedRoles },
      scope: { endpoints: eps.map((e) => e.id), resources: [resource], fields: [], roles: sorted([...deniedRoles, ...allowedRoles]), identities: identitiesOf([...deniedRoles, ...allowedRoles]) },
      provenance: [
        ...denies.map((m) => ({ kind: "permission" as const, ref: permissionRef(m), detail: `matched to ${resource} ${operation} by name` })),
        ...allowedBy.map((x) => ({ kind: "permission" as const, ref: permissionRef(x), detail: "positive control" })),
        ...eps.map((e) => ({ kind: "endpoint" as const, ref: `endpoint:${label(e)}`, detail: `${e.action} on ${resource}` })),
      ],
      signals: [
        signal("explicit-deny", "configured permission denies the operation", true),
        signal("endpoint-match", "endpoints matched by resource and action (name heuristic)", true),
        signal("positive-control", allowedRoles.length ? `explicitly allowed: ${allowedRoles.join(", ")}` : "no role is explicitly allowed", allowedRoles.length > 0),
      ],
      confidenceRule: "MEDIUM: explicit deny matched to endpoints by name. Never HIGH, because the permission-to-endpoint mapping is a name heuristic.",
      level: () => "MEDIUM",
      testStrategy: {
        kind: "role-boundary",
        preconditions: [`Identities with role ${andList(deniedRoles)}`],
        steps: [`As each denied role, call ${list(eps.map(label))} with a schema-valid request.`, allowedRoles.length ? `Repeat as ${andList(allowedRoles)} (positive control).` : "No allowed role is configured for a positive control."],
        expected: `${andList(deniedRoles)} ${deniedRoles.length > 1 ? "are" : "is"} denied (403) and nothing changes.`,
        executable: false,
      },
    });
  }

  // ---- FUNCTION_AUTHORIZATION (c): contested permissions that map to no endpoint ----
  const contested = new Map<string, Set<boolean>>();
  const unmatched = new Set<string>();
  for (const role of configRoles) {
    for (const [perm, v] of Object.entries(role.permissions ?? {})) {
      if (typeof v !== "boolean") continue;
      contested.set(perm, (contested.get(perm) ?? new Set()).add(v));
      const m = permissions.find((x) => x.role === role.name && x.permission === perm);
      const mapped = m && model.endpoints.some((e) => e.resource === m.resource);
      if (!mapped) unmatched.add(perm);
    }
  }
  const contestedUnmatched = sorted([...contested].filter(([p, vals]) => vals.size === 2 && unmatched.has(p)).map(([p]) => p));
  if (contestedUnmatched.length) {
    const involved = sorted(configRoles.filter((r) => contestedUnmatched.some((p) => p in (r.permissions ?? {}))).map((r) => r.name));
    add({
      key: "FUNCTION_AUTHORIZATION:matrix",
      category: "FUNCTION_AUTHORIZATION",
      severity: "Medium",
      statement: `Role permissions that differ by role (${list(contestedUnmatched)}) must be enforced; the model does not map them to endpoints.`,
      rule: { type: "permission-matrix", roles: involved, contestedActions: contestedUnmatched },
      scope: { ...emptyScope(), roles: involved, identities: identitiesOf(involved) },
      provenance: contestedUnmatched.flatMap((p) =>
        configRoles.filter((r) => typeof (r.permissions ?? {})[p] === "boolean").map((r) => ({ kind: "permission" as const, ref: `permission:${r.name}.${p}=${r.permissions[p]}`, detail: "not matched to any endpoint" })),
      ),
      signals: [signal("contested", "roles have opposite values for the same permission", true), signal("endpoint-match", "permission names match no endpoint", false)],
      confidenceRule: "LOW: configuration only, not bound to any endpoint.",
      level: () => "LOW",
      testStrategy: {
        kind: "manual-mapping",
        preconditions: ["Map each permission to the endpoints that implement it"],
        steps: ["For each mapped endpoint, call it as a role with the permission and as a role without it."],
        expected: "Only roles with the permission succeed.",
        executable: false,
      },
    });
  }

  // ---- DATA_EXPOSURE: one law per resource whose returned schema has sensitive fields ----
  for (const r of model.resources) {
    const returning = returningEndpoints(r.name, model);
    const fields = r.fields
      .map((f) => ({ f, level: sensitivity(r, f.path, f.sensitivity), overridden: overrides[`${r.name}.${f.path}`] !== undefined }))
      .filter((x) => SENSITIVE.includes(x.level));
    if (!fields.length) continue;
    if (!returning.size) {
      notes.push(`${r.name}: sensitive fields exist but no endpoint's success response returns this resource; no data-exposure law.`);
      continue;
    }
    const eps = [...returning.keys()].map((id) => byId.get(id)).filter((e): e is Endpoint => !!e);
    const fieldRefs = fields.map((x) => `${r.name}.${x.f.path}`);
    const secret = fields.some((x) => x.level === "SENSITIVE");
    const f = r.ownershipField;
    // Without its own ownership field, a resource that is only reachable through an owned parent's
    // identifier (e.g. /orders/{id}/invoice) inherits the parent's entitlement rule.
    const parentsPerEndpoint = f
      ? []
      : eps.map((e) =>
          addressedResources(e, model.resources)
            .map((a) => model.resources.find((x) => x.name === a.resource)!)
            .filter((p) => p.name !== r.name && p.ownershipField),
        );
    const parent = !f && parentsPerEndpoint.length && parentsPerEndpoint.every((ps) => ps.length > 0) && uniq(parentsPerEndpoint.flat().map((p) => p.name)).length === 1
      ? parentsPerEndpoint[0]![0]!
      : null;
    const inheritedFrom = parent ? `${parent.name}.${parent.ownershipField}` : null;
    add({
      key: `DATA_EXPOSURE:${r.name}`,
      category: "DATA_EXPOSURE",
      severity: secret ? "High" : "Medium",
      statement: f
        ? `${r.name} responses must not expose ${list(fields.map((x) => x.f.path))} to callers who do not own the ${r.name}.`
        : parent
          ? `${r.name} responses must not expose ${list(fields.map((x) => x.f.path))} to callers who do not own the parent ${parent.name} (ownership field ${inheritedFrom}).`
          : `${r.name} responses may expose ${list(fields.map((x) => x.f.path))} only to callers entitled to that ${r.name}.`,
      rule: { type: "no-unauthorized-field-exposure", resource: r.name, fields: fields.map((x) => x.f.path), endpoints: eps.map((e) => e.id), ownershipField: f, inheritedFrom },
      scope: { endpoints: eps.map((e) => e.id), resources: parent ? [r.name, parent.name] : [r.name], fields: parent ? [...fieldRefs, inheritedFrom!] : fieldRefs, roles: nonPrivileged, identities: [] },
      provenance: [
        ...eps.map((e) => ({ kind: "endpoint" as const, ref: `endpoint:${label(e)}`, detail: `success response returns ${returning.get(e.id)}` })),
        ...fields.map((x) => ({
          kind: "sensitivity" as const,
          ref: `sensitivity:${r.name}.${x.f.path}=${x.level}`,
          detail: x.overridden ? "analyst override" : `name heuristic: ${x.f.sensitivityReason}`,
        })),
        ...(f ? [{ kind: "schema" as const, ref: `schema:${r.name}.${f}`, detail: "ownership field defines who may see the object" }] : []),
        ...(parent
          ? [
              { kind: "relationship" as const, ref: `relationship:${r.name}→${parent.name}`, detail: `only reachable through ${list(eps.map(label))}, which identify a ${parent.name}` },
              { kind: "schema" as const, ref: `schema:${inheritedFrom}`, detail: `ownership field of the parent ${parent.name}` },
            ]
          : []),
      ],
      signals: [
        signal("sensitive-fields", `${fields.length} PERSONAL/SENSITIVE field(s) in the returned schema`, true),
        signal("secret-level", secret ? "includes SENSITIVE (credential/payment/secret) fields" : "only PERSONAL fields", secret),
        signal(
          "ownership-defined",
          f ? `ownership field ${r.name}.${f} defines entitlement` : parent ? `entitlement inherited from parent ${inheritedFrom}` : "no ownership field: entitlement is undefined",
          !!f || !!parent,
        ),
        signal("analyst-confirmed", fields.some((x) => x.overridden) ? "an analyst confirmed at least one classification" : "classification is a name heuristic only", fields.some((x) => x.overridden)),
        signal("authenticated", "all returning endpoints require authentication", eps.every((e) => e.auth.mode === "required")),
      ],
      confidenceRule: "HIGH: analyst-confirmed sensitivity + ownership field. MEDIUM: ownership field or SENSITIVE-level fields. LOW: PERSONAL-only fields without ownership.",
      level: (p) => (p.has("analyst-confirmed") && p.has("ownership-defined") ? "HIGH" : p.has("ownership-defined") || p.has("secret-level") ? "MEDIUM" : "LOW"),
      testStrategy: {
        kind: "response-field-exposure",
        preconditions: [`Endpoints returning ${r.name}: ${list(eps.map(label))}`, f ? `An identity that does not own the ${r.name} (per ${r.name}.${f})` : `An identity not entitled to the ${r.name}`],
        steps: [
          `Request a ${r.name} as a caller who is not entitled to it.`,
          `Check the response for ${list(fields.map((x) => x.f.path), 8)}.`,
          "Compare returned fields with the declared response schema to spot undocumented fields.",
        ],
        expected: "Either the request is denied, or the listed fields are absent or masked.",
        executable: false,
      },
    });
  }

  // ---- STATE_TRANSITION: enum state fields changed by write endpoints ----
  for (const r of model.resources) {
    const stateField = r.fields.find((f) => !f.path.includes(".") && !f.path.includes("[]") && STATE_WORDS.has(tokenize(f.name).at(-1) ?? "") && (f.enum?.length ?? 0) >= 2);
    if (!stateField) continue;
    // A dedicated transition endpoint acts on one object of this resource: /listings/{listingId}/publish.
    // (POST /stores/{storeId}/listings creates a Listing under a Store; it is not a transition.)
    const addressesThis = (e: Endpoint) => addressedResources(e, model.resources).at(-1)?.resource === r.name;
    const verbEndpoint = (e: Endpoint) => !isRead(e) && /\}\/[^{}/]+\/?$/.test(e.path) && addressesThis(e);
    const eps = model.endpoints.filter((e) => e.resource === r.name && ((e.action === "Update" && addressesThis(e)) || verbEndpoint(e)));
    if (!eps.length) continue;
    const states = stateField.enum!.map(String);
    const dedicated = eps.filter(verbEndpoint);
    add({
      key: `STATE_TRANSITION:${r.name}.${stateField.path}`,
      category: "STATE_TRANSITION",
      severity: "Medium",
      statement: `Changes to ${r.name}.${stateField.path} (${states.join(", ")}) must follow permitted transitions and be made only by authorized identities.`,
      rule: { type: "guarded-state-transition", resource: r.name, stateField: stateField.path, states, endpoints: eps.map((e) => e.id) },
      scope: { endpoints: eps.map((e) => e.id), resources: [r.name], fields: [`${r.name}.${stateField.path}`], roles: nonPrivileged, identities: [] },
      provenance: [
        { kind: "schema", ref: `schema:${r.name}.${stateField.path}`, detail: `enum: ${states.join(", ")}` },
        ...eps.map((e) => ({ kind: "endpoint" as const, ref: `endpoint:${label(e)}`, detail: verbEndpoint(e) ? "dedicated transition endpoint" : `${e.action} on ${r.name}` })),
      ],
      signals: [
        signal("enum-states", `${states.length} states declared`, true),
        signal("transition-endpoints", dedicated.length ? `${dedicated.length} dedicated transition endpoint(s)` : "only generic update endpoints", dedicated.length > 0),
        signal("transition-table", "the spec does not describe allowed transitions", false),
      ],
      confidenceRule: "MEDIUM: enum states + dedicated transition endpoints. LOW: generic updates only. Never HIGH: OpenAPI cannot express the transition table.",
      level: (p) => (p.has("transition-endpoints") ? "MEDIUM" : "LOW"),
      testStrategy: {
        kind: "state-transition",
        preconditions: [`Allowed transitions for ${r.name}.${stateField.path} (not in the spec; must be supplied)`, `Objects of ${r.name} in each state`],
        steps: [`For each endpoint in ${list(eps.map(label))}, attempt each transition from each state.`, "Attempt the same as an identity that is not authorized for the object."],
        expected: "Only permitted transitions by authorized identities succeed; others are rejected without changing state.",
        executable: false,
      },
    });
  }

  // ---- SECURITY_CONFIGURATION (a): public / optional-auth endpoints ----
  const openGroups = new Map<string, Endpoint[]>();
  for (const e of model.endpoints) {
    if (e.auth.mode === "required") continue;
    const k = e.auth.mode === "optional" ? "optional" : e.auth.source === "none" ? "undeclared" : "public";
    openGroups.set(k, [...(openGroups.get(k) ?? []), e]);
  }
  for (const [k, eps] of openGroups) {
    const exposed = sorted(
      eps.flatMap((e) =>
        model.resources
          .filter((r) => returningEndpoints(r.name, model).has(e.id))
          .flatMap((r) => r.fields.filter((f) => SENSITIVE.includes(sensitivity(r, f.path, f.sensitivity))).map((f) => `${r.name}.${f.path}`)),
      ),
    );
    const one = eps.length === 1;
    const how =
      k === "optional"
        ? `${one ? "accepts" : "accept"} anonymous requests (security: [{}])`
        : k === "undeclared"
          ? `${one ? "declares" : "declare"} no security requirement (public by specification)`
          : `${one ? "is" : "are"} explicitly public (security: [])`;
    add({
      key: `SECURITY_CONFIGURATION:${k}`,
      category: "SECURITY_CONFIGURATION",
      severity: exposed.length ? "High" : "Medium",
      statement: exposed.length
        ? `${list(eps.map(label))} ${how} but ${one ? "returns" : "return"} sensitive fields (${list(exposed)}); ${one ? "it" : "they"} must require authentication or omit those fields.`
        : `${list(eps.map(label))} ${how}; this must be intentional and ${one ? "it" : "they"} must not return sensitive data.`,
      rule: { type: "explicit-public-access", endpoints: eps.map((e) => e.id), mode: k === "optional" ? "optional" : "public", exposesSensitiveFields: exposed },
      scope: { endpoints: eps.map((e) => e.id), resources: sorted(exposed.map((x) => x.slice(0, x.indexOf(".")))), fields: exposed, roles: [], identities: [] },
      provenance: [
        ...eps.map((e) => ({ kind: "endpoint" as const, ref: `endpoint:${label(e)}`, detail: e.auth.detail })),
        ...exposed.map((x) => ({ kind: "sensitivity" as const, ref: `sensitivity:${x}`, detail: "returned by an endpoint that does not require authentication" })),
      ],
      signals: [
        signal("explicit-declaration", k === "undeclared" ? "no security requirement declared anywhere" : "public/optional access is declared explicitly", k !== "undeclared"),
        signal("no-sensitive-response", exposed.length ? "declared responses include sensitive fields" : "declared responses include no sensitive fields", exposed.length === 0),
      ],
      confidenceRule: "MEDIUM: public access declared explicitly. LOW: no security declared at all (intent unknown).",
      level: (p) => (p.has("explicit-declaration") ? "MEDIUM" : "LOW"),
      testStrategy: {
        kind: "public-surface-review",
        preconditions: [`${eps.length} endpoint(s) reachable without authentication`],
        steps: ["Request each endpoint without credentials.", "Inspect responses for sensitive or undocumented fields.", "Confirm with the API owner that anonymous access is intended."],
        expected: "Responses contain no sensitive data and public access is confirmed as intended.",
        executable: false,
      },
    });
  }

  // ---- SECURITY_CONFIGURATION (b): requirements naming undeclared schemes ----
  const undeclared = model.endpoints.filter((e) => e.auth.alternatives.some((a) => a.schemes.some((s) => !s.known)));
  if (undeclared.length) {
    const names = sorted(undeclared.flatMap((e) => e.auth.alternatives.flatMap((a) => a.schemes.filter((s) => !s.known).map((s) => s.name))));
    add({
      key: "SECURITY_CONFIGURATION:undeclared-schemes",
      category: "SECURITY_CONFIGURATION",
      severity: "Medium",
      statement: `Security requirements reference undeclared scheme(s) ${names.join(", ")}; they must be declared so authentication can be enforced and verified.`,
      rule: { type: "declared-security-schemes", endpoints: undeclared.map((e) => e.id), undeclaredSchemes: names },
      scope: { ...emptyScope(), endpoints: undeclared.map((e) => e.id) },
      provenance: [
        ...names.map((n) => ({ kind: "security" as const, ref: `security:${n}`, detail: "referenced by a requirement, missing from securitySchemes" })),
        ...undeclared.map((e) => ({ kind: "endpoint" as const, ref: `endpoint:${label(e)}`, detail: e.auth.detail })),
      ],
      signals: [signal("spec-fact", "the specification itself references an undeclared scheme", true)],
      confidenceRule: "HIGH: a direct fact of the specification.",
      level: () => "HIGH",
      testStrategy: {
        kind: "spec-review",
        preconditions: ["The API owner's intended authentication scheme"],
        steps: ["Declare the missing scheme(s) in the spec.", "Re-run the constitution to derive authentication laws for these endpoints."],
        expected: "No requirement references an undeclared scheme.",
        executable: false,
      },
    });
  }

  // ---- notes for signals that could not become laws ----
  if (!configRoles.length && !identities.length) notes.push("No identities or roles configured: laws cannot name the affected roles.");
  if (adminByResource.size && !privileged.length) notes.push("Administrative endpoints exist but no privileged role is configured.");

  // ---- finalize: confidence, ordering, ids ----
  const laws: SecurityLaw[] = [...drafts.values()]
    .map((d) => {
      const present = new Set(d.signals.filter((s) => s.present).map((s) => s.id));
      const level = d.level(present);
      const law: Omit<SecurityLaw, "id"> = {
        key: d.key,
        category: d.category,
        severity: d.severity,
        statement: d.statement,
        rule: d.rule,
        invariant: renderInvariant(d.rule),
        appliesTo: mergeScope(emptyScope(), d.scope),
        provenance: [...d.provenance].sort((a, b) => a.kind.localeCompare(b.kind) || a.ref.localeCompare(b.ref)),
        confidence: level,
        confidenceRationale: { level, score: Math.round((present.size / Math.max(1, d.signals.length)) * 100), signals: d.signals, rule: d.confidenceRule },
        testStrategy: d.testStrategy,
      };
      return law;
    })
    .sort(
      (a, b) =>
        CATEGORY_ORDER.indexOf(a.category) - CATEGORY_ORDER.indexOf(b.category) ||
        CONFIDENCE_RANK[a.confidence] - CONFIDENCE_RANK[b.confidence] ||
        SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
        a.key.localeCompare(b.key),
    )
    .map((law, i) => ({ id: `LAW-${String(i + 1).padStart(3, "0")}`, ...law }));

  return { version: "constitution-v1", laws, notes: sorted(notes) };
}
