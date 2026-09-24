// Interprets free-text permission names from the configuration ("View Foreign Order": false)
// against the model's resources. Matching is by whole tokens and is recorded as a heuristic.
import type { Resource, Role } from "../contracts";
import { singularize, tokenize } from "../model";

export type PermissionOperation = "read" | "create" | "update" | "delete" | "admin" | "any";
export type PermissionQualifier = "own" | "foreign" | "any";

export interface PermissionMatch {
  role: string;
  permission: string;
  allowed: boolean;
  resource: string;
  operation: PermissionOperation;
  qualifier: PermissionQualifier;
}

const VERBS: Record<string, PermissionOperation> = {
  view: "read", read: "read", get: "read", list: "read", see: "read", browse: "read", access: "read",
  create: "create", add: "create", new: "create", post: "create", place: "create", submit: "create",
  update: "update", edit: "update", modify: "update", change: "update", patch: "update",
  delete: "delete", remove: "delete", destroy: "delete",
  admin: "admin", administer: "admin", manage: "admin",
};
const OWN = new Set(["own", "mine", "my", "self"]);
const FOREIGN = new Set(["foreign", "other", "others", "another", "any", "all"]);

/** Resources whose (singularized) name tokens all appear in the permission name. Longest name wins. */
function resourceFor(tokens: string[], resources: readonly Resource[]): string | null {
  const singular = tokens.map(singularize);
  const candidates = resources
    .map((r) => ({ name: r.name, parts: tokenize(r.name).map(singularize) }))
    .filter((c) => c.parts.every((p) => singular.includes(p)))
    .sort((a, b) => b.parts.length - a.parts.length || a.name.localeCompare(b.name));
  return candidates[0]?.name ?? null;
}

export function matchPermissions(roles: readonly Role[], resources: readonly Resource[]): PermissionMatch[] {
  const out: PermissionMatch[] = [];
  for (const role of roles) {
    for (const [permission, value] of Object.entries(role.permissions ?? {})) {
      if (typeof value !== "boolean") continue;
      const tokens = tokenize(permission);
      const resource = resourceFor(tokens, resources);
      if (!resource) continue;
      const verb = tokens.map((t) => VERBS[t]).find(Boolean);
      const qualifier: PermissionQualifier = tokens.some((t) => OWN.has(t)) ? "own" : tokens.some((t) => FOREIGN.has(t)) ? "foreign" : "any";
      out.push({ role: role.name, permission, allowed: value, resource, operation: verb ?? "any", qualifier });
    }
  }
  return out;
}

export function permissionRef(m: PermissionMatch): string {
  return `permission:${m.role}.${m.permission}=${m.allowed}`;
}
