import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ApiModel, Endpoint } from "../src/contracts";
import { parseApiSpec, type NormalizedSpec, type RawEndpoint } from "../src/openapi";
import { buildApiModel } from "../src/model";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export function readRepoFile(rel: string): string {
  return readFileSync(path.join(ROOT, rel), "utf8");
}

export function fixture(name: string): string {
  return readRepoFile(`tests/fixtures/openapi/${name}`);
}

export function specOf(text: string): NormalizedSpec {
  const r = parseApiSpec(text);
  if (!r.ok) throw new Error(`fixture failed to parse: ${r.errors.join("; ")}`);
  return r.spec;
}

export function specFixture(name: string): NormalizedSpec {
  return specOf(fixture(name));
}

export function modelFixture(name: string): ApiModel {
  return buildApiModel(specFixture(name));
}

export function findEndpoint<T extends RawEndpoint | Endpoint>(eps: readonly T[], method: string, p: string): T {
  const e = eps.find((x) => x.method === method && x.path === p);
  if (!e) throw new Error(`endpoint ${method} ${p} not found`);
  return e;
}
