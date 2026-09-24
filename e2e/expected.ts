// Expected graph/constitution for a spec + configuration, computed in Node from the model libraries.
// The E2E tests compare what the browser renders against these values, so counts are never hardcoded.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Identity, Role } from "../src/contracts";
import { generateSecurityConstitution } from "../src/constitution";
import { analyzeSpecText } from "../src/model";
import { buildTwinGraph, lawHighlight } from "../src/twin/graph";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const readRepoFile = (rel: string) => readFileSync(path.join(ROOT, rel), "utf8");

export interface StepOneConfig {
  identities: Identity[];
  permissions: Record<string, Record<string, boolean>>;
  ownership: Record<string, string>;
}

export function demoInput(): { spec: string; config: StepOneConfig } {
  return {
    spec: readRepoFile("1-security-twin/samples/sample-swagger.json"),
    config: JSON.parse(readRepoFile("1-security-twin/samples/sample-config.json")) as StepOneConfig,
  };
}

/** Mirrors Step 1's documented inputs: the privileged role is the configured role whose name contains "admin". */
export function expectedFor(spec: string, config: StepOneConfig) {
  const r = analyzeSpecText(spec);
  if (!r.ok) throw new Error(r.errors.join("; "));
  const identityRoles = [...new Set(config.identities.map((i) => i.role).filter(Boolean))];
  const adminRole = identityRoles.find((x) => /admin/i.test(x)) ?? null;
  const roleNames = [...new Set([...identityRoles, ...Object.keys(config.permissions)])];
  const roles: Role[] = roleNames.map((name) => ({ name, permissions: config.permissions[name] ?? {}, privileged: name === adminRole }));
  const ownership = Object.entries(config.ownership).map(([objectId, ownerId]) => ({ objectId, ownerId }));
  const constitution = generateSecurityConstitution(r.model, { identities: config.identities, roles, ownership });
  const privilegedEndpoints = adminRole ? r.view.endpoints.filter((e) => e.action === "AdminAction" || e.resource === "Admin").map((e) => e.id) : [];
  const graph = buildTwinGraph({
    endpoints: r.model.endpoints,
    resources: r.model.resources,
    identities: config.identities,
    roles,
    laws: constitution.laws,
    ownership,
    privilegedEndpoints,
  });
  return { model: r.model, constitution, graph, highlight: (lawId: string) => lawHighlight(graph, lawId) };
}
