// XSS regression tests: crafted spec/config/model content must render as text, never as markup.
// Payloads only set a marker (window.__xss); they are inert test fixtures.
import { afterEach, describe, expect, it } from "vitest";
import { loadApp, type LoadedApp } from "../../scripts/app-harness.mjs";
import { readRepoFile } from "../helpers";

const ATTR_BREAKOUT = 'x" autofocus onfocus="window.__xss=1" data-y="';
const TAG = '<img src=x onerror="window.__xss=2">';
const SVG = "<svg onload=window.__xss=3></svg>";

let app: LoadedApp | undefined;
afterEach(() => {
  app?.close();
  app = undefined;
});

/** Elements carrying on* handlers. The only legitimate one is the static upload dropzone in Step 1's index.html. */
function handlerElements(doc: Document): string[] {
  return [...doc.querySelectorAll("*")]
    .filter((el) => [...el.attributes].some((a) => a.name.toLowerCase().startsWith("on")))
    .map((el) => `${el.tagName.toLowerCase()}.${el.className}`);
}

/** Elements that only an injection could create. React Flow draws its own <svg> inside .react-flow. */
function injectedElements(doc: Document): string[] {
  return [...doc.querySelectorAll("img, script, iframe, object, embed, svg")]
    .filter((el) => el.tagName.toLowerCase() !== "svg" || !el.closest(".react-flow"))
    .map((el) => el.outerHTML.slice(0, 80));
}

function focusAll(app: LoadedApp, selector: string): void {
  app.document.querySelectorAll<HTMLElement>(selector).forEach((el) => el.focus());
}

describe("Step 1 renders crafted spec and config content as text", () => {
  const craftedSpec = JSON.stringify({
    openapi: "3.0.0",
    info: { title: TAG, version: "1" },
    servers: [{ url: `https://sandbox.test/${TAG}` }],
    security: [{ [`k${TAG}`]: [] }],
    paths: {
      [`/things/{id}/${SVG}`]: {
        get: {
          summary: TAG,
          operationId: `get${SVG}`,
          tags: [TAG],
          parameters: [
            { name: "id", in: "path", required: true, schema: { type: "string" } },
            { name: ATTR_BREAKOUT, in: "query", schema: { type: "string" } },
          ],
          responses: { "200": { description: TAG, content: { "application/json": { schema: { $ref: "#/components/schemas/Thing" } } } } },
        },
      },
    },
    components: {
      schemas: {
        Thing: {
          type: "object",
          properties: {
            [ATTR_BREAKOUT]: { type: "string" },
            [TAG]: { type: "string" },
            ownerId: { type: "string", enum: [SVG] },
          },
        },
      },
    },
  });

  async function buildCrafted(): Promise<LoadedApp> {
    const a = await loadApp("1-security-twin");
    a.setValue("swaggerText", craftedSpec);
    a.setValue("identitiesEditor", JSON.stringify([{ name: TAG, role: ATTR_BREAKOUT, id: "u1" }, { name: "Admin", role: `Admin${SVG}`, id: `a1${TAG}` }]));
    a.setValue("permissionsEditor", JSON.stringify({ [ATTR_BREAKOUT]: { [TAG]: true, other: false } }));
    a.setValue("ownershipEditor", JSON.stringify({ [TAG]: "u1", o2: `a1${TAG}` }));
    a.click("buildBtn");
    return a;
  }

  it("builds without errors and shows the payloads literally", async () => {
    app = await buildCrafted();
    expect(app.alerts).toEqual([]);
    const text = app.document.body.textContent!;
    expect(text).toContain(TAG);
    expect(text).toContain(ATTR_BREAKOUT);
    expect(text).toContain(SVG);
  });

  it("creates no injected elements or event-handler attributes", async () => {
    app = await buildCrafted();
    expect(injectedElements(app.document)).toEqual([]);
    // The page has no inline event-handler attributes at all (the upload zone is a real button).
    expect(handlerElements(app.document)).toEqual([]);
    expect(app.document.querySelectorAll("[autofocus]").length).toBe(0);
  });

  it("keeps attribute values intact (no attribute breakout in data-* or option values)", async () => {
    app = await buildCrafted();
    const select = [...app.document.querySelectorAll<HTMLSelectElement>("#sensTable select")].find((s) => s.dataset.f === ATTR_BREAKOUT);
    expect(select).toBeDefined();
    expect(select!.dataset.f).toBe(ATTR_BREAKOUT);
    expect(select!.getAttributeNames().sort()).toEqual(["aria-label", "data-f", "data-r"]);
    expect(select!.getAttribute("aria-label")).toContain(ATTR_BREAKOUT);
  });

  it("never executes injected handlers, even when elements receive focus", async () => {
    app = await buildCrafted();
    focusAll(app, "select, input, textarea, button");
    expect(app.window.__xss).toBeUndefined();
  });
});

describe("Step 2 renders crafted model content as text", () => {
  function craftedModel(): string {
    const m = JSON.parse(readRepoFile("2-test-lab/samples/sample-testable-model.json"));
    m.laws[0].category = TAG;
    m.laws[0].title = SVG;
    m.laws[1].id = `LAW-X${TAG}`;
    m.laws[1].severity = ATTR_BREAKOUT;
    m.testIdentities[0].name = TAG;
    m.testIdentities[0].role = SVG;
    m.testIdentities[1].id = ATTR_BREAKOUT;
    m.endpoints[1].path = `/orders/{id}${TAG}`;
    m.sandboxBaseUrl = `https://sandbox.test/${ATTR_BREAKOUT}`;
    return JSON.stringify(m);
  }

  async function planCrafted(): Promise<LoadedApp> {
    const a = await loadApp("2-test-lab");
    a.setValue("modelText", craftedModel());
    a.click("planBtn");
    return a;
  }

  it("plans without errors and shows the payloads literally", async () => {
    app = await planCrafted();
    expect(app.alerts).toEqual([]);
    const text = app.document.body.textContent!;
    expect(text).toContain(TAG);
    expect(text).toContain(SVG);
    expect(text).toContain(ATTR_BREAKOUT);
  });

  it("creates no injected elements or event-handler attributes", async () => {
    app = await planCrafted();
    expect(injectedElements(app.document)).toEqual([]);
    expect(handlerElements(app.document)).toEqual([]);
    expect(app.document.querySelectorAll("[autofocus]").length).toBe(0);
    const credInputs = [...app.document.querySelectorAll<HTMLInputElement>("#authBox input[data-cred]")];
    expect(credInputs.map((i) => i.dataset.cred)).toContain(ATTR_BREAKOUT);
    for (const i of credInputs) expect(i.getAttributeNames().sort()).toEqual(["aria-label", "data-cred", "placeholder", "style", "type"]);
  });

  it("never executes injected handlers, even when elements receive focus", async () => {
    app = await planCrafted();
    focusAll(app, "select, input, textarea, button");
    expect(app.window.__xss).toBeUndefined();
  });

  it("keeps credentials out of the markup when re-rendering", async () => {
    app = await planCrafted();
    const secret = "tok-audit-placeholder-123";
    const input = app.document.querySelector<HTMLInputElement>("#authBox input[data-cred]")!;
    input.value = secret;
    input.dispatchEvent(new app.window.Event("change"));
    // Switching scheme re-renders the credential form.
    const scheme = app.$("authScheme") as unknown as HTMLSelectElement;
    scheme.value = "apiKey";
    scheme.dispatchEvent(new app.window.Event("change"));
    const rerendered = app.document.querySelector<HTMLInputElement>("#authBox input[data-cred]")!;
    expect(rerendered.value).toBe(secret);
    expect(app.$("authBox").innerHTML).not.toContain(secret);
  });
});

describe("static guard", () => {
  it.each(["1-security-twin/app.js", "2-test-lab/app.js"])("%s has no raw HTML sinks", (file) => {
    const src = readRepoFile(file);
    expect(src).not.toMatch(/\.innerHTML\s*[+]?=/);
    expect(src).not.toMatch(/\.outerHTML\s*=/);
    expect(src).not.toMatch(/insertAdjacentHTML|document\.write/);
  });
});

describe("Content-Security-Policy", () => {
  for (const page of ["1-security-twin/index.html", "2-test-lab/index.html"]) {
    it(`${page} only runs scripts from its own origin`, () => {
      const html = readRepoFile(page);
      const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)?.[1];
      expect(csp).toBeDefined();
      const directives = Object.fromEntries(csp!.split(";").map((d) => d.trim().split(/\s+/)).map(([k, ...v]) => [k, v]));
      expect(directives["script-src"]).toEqual(["'self'"]);
      expect(directives["object-src"]).toEqual(["'none'"]);
      expect(directives["base-uri"]).toEqual(["'none'"]);
      // No inline scripts or inline event handlers anywhere in the page source.
      expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>/);
      expect(html).not.toMatch(/\son[a-z]+=/i);
    });
  }
});
