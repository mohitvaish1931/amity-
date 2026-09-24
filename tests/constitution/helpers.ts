import type { ApiModel, Role, SecurityConstitution, SecurityLaw } from "../../src/contracts";
import { generateSecurityConstitution, type ConstitutionConfig } from "../../src/constitution";
import { buildApiModel } from "../../src/model";
import { readRepoFile, specOf } from "../helpers";

export const marketplaceModel = (): ApiModel => buildApiModel(specOf(readRepoFile("tests/fixtures/constitution/marketplace.json")));

export const marketplaceRoles: Role[] = [
  { name: "Merchant", permissions: { "Edit own listing": true }, privileged: false },
  { name: "Buyer", permissions: { "Delete Listing": false, "Manage Payouts": false, "View Store": true }, privileged: false },
  { name: "Support", permissions: { "View any Listing": true }, privileged: false },
  { name: "Operator", permissions: { "Manage Payouts": true, "Export reports": true }, privileged: true, privilegeEvidence: "configured as operations staff" },
];
// "Export reports" is contested (Operator true, Merchant false) and matches no resource.
marketplaceRoles[0]!.permissions["Export reports"] = false;

export const marketplaceConfig: ConstitutionConfig = {
  identities: [
    { id: "m1", name: "Merchant One", role: "Merchant" },
    { id: "m2", name: "Merchant Two", role: "Merchant" },
    { id: "b1", name: "Buyer One", role: "Buyer" },
    { id: "sup1", name: "Support One", role: "Support" },
    { id: "ops1", name: "Ops One", role: "Operator" },
  ],
  roles: marketplaceRoles,
  ownership: [
    { objectId: "L-1", ownerId: "m1" },
    { objectId: "L-2", ownerId: "m2" },
    { objectId: "S-1", ownerId: "m1" },
  ],
};

export const marketplace = (config: ConstitutionConfig = marketplaceConfig): SecurityConstitution =>
  generateSecurityConstitution(marketplaceModel(), config);

export function lawByKey(c: SecurityConstitution, key: string): SecurityLaw {
  const law = c.laws.find((l) => l.key === key);
  if (!law) throw new Error(`no law ${key}; have ${c.laws.map((l) => l.key).join(", ")}`);
  return law;
}

export function endpointIds(model: ApiModel, ...labels: string[]): string[] {
  return labels.map((lbl) => {
    const [method, path] = lbl.split(" ");
    const e = model.endpoints.find((x) => x.method === method && x.path === path);
    if (!e) throw new Error(`no endpoint ${lbl}`);
    return e.id;
  });
}
