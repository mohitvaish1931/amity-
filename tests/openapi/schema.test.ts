import { describe, expect, it } from "vitest";
import type { Field } from "../../src/contracts";
import { findEndpoint, specFixture } from "../helpers";

const byPath = (fields: readonly Field[]) => Object.fromEntries(fields.map((f) => [f.path, f]));

describe("nested objects (fixture C)", () => {
  const fields = byPath(specFixture("c-nested.json").schemas.Account!.fields);

  it("flattens nested objects with dotted paths", () => {
    expect(Object.keys(fields)).toEqual([
      "id",
      "plan",
      "holder",
      "holder.email",
      "holder.apiToken",
      "holder.mailing",
      "holder.mailing.street",
      "holder.mailing.city",
      "holder.mailing.country",
    ]);
  });

  it("keeps types, formats, required flags and $ref targets of nested fields", () => {
    expect(fields.holder).toMatchObject({ type: "object", required: false });
    expect(fields["holder.email"]).toMatchObject({ type: "string", format: "email", required: true });
    expect(fields["holder.mailing"]).toMatchObject({ type: "object", ref: "PostalAddress" });
  });

  it("honours OpenAPI 3.0 nullable", () => {
    expect(fields.plan!.nullable).toBe(true);
    expect(fields.id!.nullable).toBe(false);
  });
});

describe("arrays (fixture D)", () => {
  const fields = byPath(specFixture("d-arrays.json").schemas.Project!.fields);

  it("marks arrays of primitives without inventing children", () => {
    expect(fields.labels).toMatchObject({ type: "array" });
    expect(Object.keys(fields).some((p) => p.startsWith("labels."))).toBe(false);
  });

  it("flattens inline array items with [] paths", () => {
    expect(fields["members[].displayName"]).toMatchObject({ type: "string" });
    expect(fields["members[].ssn"]).toMatchObject({ type: "string" });
  });

  it("follows $ref array items and records the item schema name", () => {
    expect(fields.milestones).toMatchObject({ type: "array", ref: "Milestone" });
    expect(fields["milestones[].dueDate"]).toMatchObject({ type: "string", format: "date" });
  });
});

describe("recursive $ref (fixture E, YAML)", () => {
  const spec = specFixture("e-recursive.yaml");

  it("stops at self-references and marks them recursive", () => {
    const f = byPath(spec.schemas.TreeNode!.fields);
    expect(Object.keys(f)).toEqual(["id", "parent", "children"]);
    expect(f.parent).toMatchObject({ recursive: true, ref: "TreeNode" });
    expect(f.children).toMatchObject({ type: "array", recursive: true, ref: "TreeNode" });
  });

  it("stops at mutual recursion (Folder -> File -> Folder)", () => {
    const f = byPath(spec.schemas.Folder!.fields);
    expect(f["files[].name"]).toBeDefined();
    expect(f["files[].folder"]).toMatchObject({ recursive: true, ref: "Folder" });
    expect(Object.keys(f).some((p) => p.startsWith("files[].folder."))).toBe(false);
  });

  it("describes recursive response schemas on endpoints without looping", () => {
    const get = findEndpoint(spec.endpoints, "GET", "/nodes/{nodeId}");
    expect(get.responses[0]!.contents[0]!.schema!.fields.map((x) => x.path)).toEqual(["id", "parent", "children"]);
  });
});

describe("allOf / oneOf / anyOf, nullable and enums (fixture M, OpenAPI 3.1)", () => {
  const spec = specFixture("m-composition-31.json");
  const schema = findEndpoint(spec.endpoints, "GET", "/pets/{petId}").responses[0]!.contents[0]!.schema!;
  const f = byPath(schema.fields);

  it("merges allOf branches, including required", () => {
    expect(schema.type).toBe("object");
    expect(f.id).toMatchObject({ required: true });
    expect(f.kind).toMatchObject({ enum: ["cat", "dog"] });
  });

  it("treats 3.1 type arrays with null as nullable", () => {
    expect(f.nickname).toMatchObject({ type: "string", nullable: true });
  });

  it("includes fields from every oneOf branch, tagging branch-only fields", () => {
    expect(f.indoor).toBeDefined();
    expect(f.indoor!.variant).toBeUndefined(); // present in both Cat and Dog
    expect(f.microchipSecret).toMatchObject({ variant: "oneOf:Cat" });
    expect(f.breed).toMatchObject({ variant: "oneOf:Dog", type: "string", nullable: true });
  });
});
