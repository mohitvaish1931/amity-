import { describe, expect, it } from "vitest";
import {
  InvalidPathParameterError,
  MissingPathParameterError,
  PathParameterError,
  fillPath,
  lastPathParam,
  pathParamNames,
} from "../../src/paths";

function missing(fn: () => unknown): MissingPathParameterError {
  try {
    fn();
  } catch (e) {
    if (e instanceof MissingPathParameterError) return e;
    throw e;
  }
  throw new Error("expected MissingPathParameterError");
}

describe("fillPath", () => {
  it("1. fills one parameter", () => {
    expect(fillPath("/orders/{orderId}", { orderId: "o-1" })).toBe("/orders/o-1");
  });

  it("2. fills two parameters", () => {
    expect(fillPath("/users/{userId}/orders/{orderId}", { userId: "u-2", orderId: "o-9" })).toBe("/users/u-2/orders/o-9");
  });

  it("3. fills three or more parameters", () => {
    expect(fillPath("/orgs/{orgId}/users/{userId}/orders/{orderId}", { orgId: "org-1", userId: "user-2", orderId: "order-99" })).toBe(
      "/orgs/org-1/users/user-2/orders/order-99",
    );
    expect(fillPath("/{a}/{b}/{c}/{d}/{e}", { a: 1, b: 2, c: 3, d: 4, e: 5 })).toBe("/1/2/3/4/5");
  });

  it("4. follows template order regardless of the order of keys in params", () => {
    expect(fillPath("/orgs/{orgId}/users/{userId}", { userId: "u", orgId: "o" })).toBe("/orgs/o/users/u");
  });

  it("5. accepts numeric values (including zero and bigint)", () => {
    expect(fillPath("/items/{id}/rev/{rev}", { id: 42, rev: 0 })).toBe("/items/42/rev/0");
    expect(fillPath("/big/{n}", { n: 9007199254740993n })).toBe("/big/9007199254740993");
  });

  it("6. encodes spaces", () => {
    expect(fillPath("/files/{name}", { name: "annual report 2026" })).toBe("/files/annual%20report%202026");
  });

  it("7. encodes special characters", () => {
    expect(fillPath("/q/{v}", { v: "a?b#c&d=e%f+g" })).toBe("/q/a%3Fb%23c%26d%3De%25f%2Bg");
    expect(fillPath("/q/{v}", { v: "über/€" })).toBe("/q/%C3%BCber%2F%E2%82%AC");
  });

  it("8. encodes slashes so a value stays one path segment", () => {
    expect(fillPath("/docs/{docId}/view", { docId: "a/b/../c" })).toBe("/docs/a%2Fb%2F..%2Fc/view");
  });

  it("9. fails clearly for missing parameters, listing all of them in order", () => {
    const e = missing(() => fillPath("/orgs/{orgId}/users/{userId}/orders/{orderId}", { userId: "u" }));
    expect(e).toBeInstanceOf(PathParameterError);
    expect(e.name).toBe("MissingPathParameterError");
    expect(e.parameters).toEqual(["orgId", "orderId"]);
    expect(e.template).toBe("/orgs/{orgId}/users/{userId}/orders/{orderId}");
    expect(e.message).toBe('Missing values for path parameters "orgId", "orderId" in "/orgs/{orgId}/users/{userId}/orders/{orderId}".');
    expect(missing(() => fillPath("/a/{x}", { x: undefined })).parameters).toEqual(["x"]);
    expect(missing(() => fillPath("/a/{x}", { x: null })).parameters).toEqual(["x"]);
  });

  it("10. returns an empty template unchanged", () => {
    expect(fillPath("", {})).toBe("");
    expect(pathParamNames("")).toEqual([]);
  });

  it("11. returns a template without parameters unchanged, ignoring extra params", () => {
    expect(fillPath("/health", {})).toBe("/health");
    expect(fillPath("/health", { unused: "x" })).toBe("/health");
  });

  it("12. never confuses parameter names that are prefixes of each other", () => {
    expect(fillPath("/users/{id}/posts/{postId}", { id: "7", postId: "99" })).toBe("/users/7/posts/99");
    expect(fillPath("/users/{userId}/{id}", { id: "B", userId: "A" })).toBe("/users/A/B");
    expect(missing(() => fillPath("/users/{id}/posts/{postId}", { postId: "99" })).parameters).toEqual(["id"]);
  });

  it("fills repeated parameters everywhere they appear", () => {
    expect(fillPath("/a/{x}/b/{x}", { x: "1" })).toBe("/a/1/b/1");
  });

  it("does not mutate its inputs", () => {
    const params = Object.freeze({ a: "1", b: 2 });
    const template = "/{a}/{b}";
    expect(fillPath(template, params)).toBe("/1/2");
    expect(params).toEqual({ a: "1", b: 2 });
    expect(template).toBe("/{a}/{b}");
  });

  it("rejects values that cannot be a safe path segment", () => {
    for (const bad of [".", "..", ""]) {
      expect(() => fillPath("/a/{x}", { x: bad })).toThrow(InvalidPathParameterError);
    }
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, { toString: () => "x" }, ["x"], true]) {
      expect(() => fillPath("/a/{x}", { x: bad })).toThrow(InvalidPathParameterError);
    }
  });

  it("only looks at own properties of params", () => {
    const inherited = Object.create({ id: "from-prototype" }) as Record<string, unknown>;
    expect(missing(() => fillPath("/a/{id}", inherited)).parameters).toEqual(["id"]);
  });

  it("can keep unfilled parameters for display only when asked", () => {
    expect(fillPath("/tenants/{tenantId}/projects/{projectId}", { projectId: "p 1" }, { onMissing: "keep" })).toBe(
      "/tenants/{tenantId}/projects/p%201",
    );
  });
});

describe("path template helpers", () => {
  it("lists parameters in template order and finds the last one", () => {
    expect(pathParamNames("/orgs/{orgId}/users/{userId}")).toEqual(["orgId", "userId"]);
    expect(lastPathParam("/orgs/{orgId}/users/{userId}")).toBe("userId");
    expect(lastPathParam("/health")).toBeNull();
  });

  it("ignores empty or unbalanced braces", () => {
    expect(pathParamNames("/a/{}/b/{open")).toEqual([]);
    expect(fillPath("/a/{}/b/{open", {})).toBe("/a/{}/b/{open");
  });
});
