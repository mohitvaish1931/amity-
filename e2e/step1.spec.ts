// End-to-end tests for Step 1 (Security Twin + Constitution) on the production build in real browsers.
// Purely local: the page loads its own assets from the local server; the tests assert nothing else is requested.
import { expect, test, type Page } from "@playwright/test";
import { demoInput, expectedFor, readRepoFile, type StepOneConfig } from "./expected";

const APP = "/1-security-twin/";

/** Records console errors, page errors and every request the page makes. */
function watch(page: Page) {
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  const requests: string[] = [];
  page.on("console", (m) => {
    if (m.type() === "error") consoleErrors.push(m.text());
  });
  page.on("pageerror", (e) => pageErrors.push(e.message));
  page.on("request", (r) => requests.push(r.url()));
  return { consoleErrors, pageErrors, requests };
}

/** Only the app's own local assets may be requested. */
function expectOnlyLocalAssets(requests: string[], baseURL: string) {
  const origin = new URL(baseURL).origin;
  const allowed = new Set([
    `${origin}${APP}`,
    `${origin}${APP}styles.css`,
    `${origin}${APP}app.css`,
    `${origin}${APP}app.js`,
    `${origin}${APP}samples/sample-swagger.json`,
    `${origin}${APP}samples/sample-config.json`,
  ]);
  // Code-split chunks of the app itself (the lazily loaded Security Twin graph).
  const isAppChunk = (u: string) => u.startsWith(`${origin}${APP}chunks/`) && u.endsWith(".js");
  const unexpected = requests.filter((u) => !u.startsWith("data:") && !allowed.has(u) && !isAppChunk(u));
  expect(unexpected, "unexpected network requests").toEqual([]);
}

async function fillConfig(page: Page, spec: string, config: StepOneConfig) {
  await page.locator("#swaggerText").fill(spec);
  await page.locator("#identitiesEditor").fill(JSON.stringify(config.identities));
  await page.locator("#permissionsEditor").fill(JSON.stringify(config.permissions));
  await page.locator("#ownershipEditor").fill(JSON.stringify(config.ownership));
}

const nodes = (page: Page) => page.getByTestId("twin-node");
const edges = (page: Page) => page.locator('[data-testid^="rf__edge-"]');
const lawCard = (page: Page, id: string) => page.locator(`[data-testid="law-card"][data-law="${id}"]`);

test.describe("Step 1: demo model", () => {
  test("builds the twin, inspects a node and a law, and highlights the law's scope", async ({ page, baseURL }) => {
    const seen = watch(page);
    const { spec, config } = demoInput();
    const expected = expectedFor(spec, config);

    // 1–3. open, load the bundled demo, build
    await page.goto(APP);
    await page.getByRole("button", { name: "Load Demo Swagger + Config" }).click();
    await expect(page.locator("#swaggerText")).not.toBeEmpty();
    // The graph code (React Flow) is lazy-loaded: nothing of it is downloaded before BUILD.
    const graphChunk = (u: string) => /\/chunks\/mount-[\w-]+\.js$/.test(u);
    expect(seen.requests.filter(graphChunk)).toEqual([]);
    await page.getByRole("button", { name: "[ BUILD SECURITY TWIN ]" }).click();

    // 4–6. graph appears with exactly the model's nodes and edges
    const graph = page.getByTestId("twin-graph");
    await expect(graph).toBeVisible();
    expect(seen.requests.filter(graphChunk)).toHaveLength(1);
    await expect(nodes(page)).toHaveCount(expected.graph.nodes.length);
    // The initial fit works with the lazily mounted graph: every node lies inside the visible canvas.
    await expect
      .poll(async () =>
        page.evaluate(() => {
          const c = document.querySelector(".twin-canvas")!.getBoundingClientRect();
          return [...document.querySelectorAll('[data-testid="twin-node"]')].filter((n) => {
            const r = n.getBoundingClientRect();
            return r.left < c.left - 1 || r.right > c.right + 1 || r.top < c.top - 1 || r.bottom > c.bottom + 1;
          }).length;
        }),
      )
      .toBe(0);
    await expect(edges(page)).toHaveCount(expected.graph.edges.length);
    for (const type of ["identity", "role", "endpoint", "resource", "field", "law"] as const) {
      await expect(page.locator(`[data-testid="twin-node"][data-node-type="${type}"]`)).toHaveCount(expected.graph.nodes.filter((n) => n.type === type).length);
    }

    // 7–9. click a real resource node; the detail panel shows its relationships
    const order = expected.graph.nodes.find((n) => n.type === "resource" && n.meta.ownershipField !== "none")!;
    await page.locator(`[data-node-id="${order.id}"]`).click();
    const panel = page.getByTestId("twin-panel");
    await expect(panel.getByRole("heading", { level: 4 })).toHaveText(order.label);
    await expect(panel).toContainText(`Relationships (${order.degree})`);
    await expect(panel).toContainText("OWNS ←");
    await expect(panel).toContainText("Relevant laws");

    // 10–11. open a law: statement, machine rule, confidence, provenance
    const law = expected.constitution.laws.find((l) => l.appliesTo.resources.includes(order.label) && l.category === "OBJECT_AUTHORIZATION")!;
    const card = lawCard(page, law.id);
    await card.locator("summary").first().click();
    await expect(card).toHaveAttribute("open", "");
    await expect(card).toContainText(law.statement);
    await expect(card).toContainText(law.invariant);
    await expect(card).toContainText(`Confidence: ${law.confidence}`);
    for (const p of law.provenance) await expect(card).toContainText(p.ref);

    // 12–14. highlight the law's scope; unrelated nodes are dimmed
    await expect(page.locator(".twin-node.is-dim")).toHaveCount(0);
    await card.getByTestId("law-focus").click();
    const scope = expected.highlight(law.id);
    await expect(page.locator(".twin-node.is-highlight")).toHaveCount(scope.nodes.size);
    await expect(page.locator(".twin-node.is-dim")).toHaveCount(expected.graph.nodes.length - scope.nodes.size);
    const highlightedIds = await page.locator(".twin-node.is-highlight").evaluateAll((els) => els.map((e) => e.getAttribute("data-node-id")));
    expect(highlightedIds.sort()).toEqual([...scope.nodes].sort());
    const unrelated = expected.graph.nodes.find((n) => !scope.nodes.has(n.id))!;
    await expect(page.locator(`[data-node-id="${unrelated.id}"]`)).toHaveClass(/is-dim/);
    await expect(card).toHaveClass(/is-focused/);
    await expect(page.getByTestId("twin-law-filter")).toHaveValue(law.id);

    // 15–16. clean console, local assets only
    expect(seen.consoleErrors).toEqual([]);
    expect(seen.pageErrors).toEqual([]);
    expectOnlyLocalAssets(seen.requests, baseURL!);
  });
});

test.describe("Step 1: regression states", () => {
  test("empty model: nothing rendered before a build, and a spec without operations yields no endpoints or laws", async ({ page, baseURL }) => {
    const seen = watch(page);
    await page.goto(APP);
    await expect(page.locator("#twinGraph")).toContainText("Click BUILD SECURITY TWIN");
    await expect(nodes(page)).toHaveCount(0);

    const { config } = demoInput();
    const spec = JSON.stringify({ openapi: "3.0.3", info: { title: "empty", version: "1" }, paths: {} });
    const expected = expectedFor(spec, config);
    await fillConfig(page, spec, config);
    await page.getByRole("button", { name: "[ BUILD SECURITY TWIN ]" }).click();
    await expect(page.locator("#invCount")).toHaveText("0 endpoints");
    await expect(nodes(page)).toHaveCount(expected.graph.nodes.length);
    await expect(page.locator('[data-testid="twin-node"][data-node-type="endpoint"]')).toHaveCount(0);
    await expect(page.locator('[data-testid="twin-node"][data-node-type="law"]')).toHaveCount(0);
    await expect(page.getByTestId("law-card")).toHaveCount(0);
    expect(expected.constitution.laws).toHaveLength(0);
    expect(seen.consoleErrors).toEqual([]);
    expectOnlyLocalAssets(seen.requests, baseURL!);
  });

  test("non-demo model: laws and graph come from the supplied spec and configuration", async ({ page, baseURL }) => {
    const seen = watch(page);
    const spec = readRepoFile("tests/fixtures/constitution/marketplace.json");
    const config: StepOneConfig = {
      identities: [
        { id: "m1", name: "Merchant One", role: "Merchant" },
        { id: "m2", name: "Merchant Two", role: "Merchant" },
        { id: "ops1", name: "Ops", role: "Administrator" },
      ],
      permissions: { Merchant: { "Delete Listing": false }, Administrator: { "Manage Payouts": true } },
      ownership: { "L-1": "m1", "L-2": "m2" },
    };
    const expected = expectedFor(spec, config);
    await page.goto(APP);
    await fillConfig(page, spec, config);
    await page.getByRole("button", { name: "[ BUILD SECURITY TWIN ]" }).click();

    await expect(nodes(page)).toHaveCount(expected.graph.nodes.length);
    await expect(edges(page)).toHaveCount(expected.graph.edges.length);
    await expect(page.getByTestId("law-card")).toHaveCount(expected.constitution.laws.length);
    for (const law of expected.constitution.laws) await expect(lawCard(page, law.id)).toContainText(law.statement);
    await expect(page.locator("#laws")).not.toContainText("Order");
    expect(seen.consoleErrors).toEqual([]);
    expectOnlyLocalAssets(seen.requests, baseURL!);
  });

  test("invalid model: a clear error, and no graph is built", async ({ page, baseURL }) => {
    const seen = watch(page);
    const { config } = demoInput();
    await page.goto(APP);
    await fillConfig(page, '{"openapi": "3.0.0", "paths": ', config);
    // The error is shown inline (role="alert"), never as a blocking dialog.
    const dialogs: string[] = [];
    page.on("dialog", async (d) => {
      dialogs.push(d.message());
      await d.dismiss();
    });
    await page.getByRole("button", { name: "[ BUILD SECURITY TWIN ]" }).click();
    const error = page.getByRole("alert").filter({ hasText: "Invalid spec" });
    await expect(error).toContainText("Invalid spec: nothing was built.");
    await expect(error).toContainText("Invalid JSON");
    expect(dialogs).toEqual([]);
    await expect(nodes(page)).toHaveCount(0);
    await expect(page.locator("#twinGraph")).toContainText("Click BUILD SECURITY TWIN");
    await expect(page.getByTestId("law-card")).toHaveCount(0);
    expect(seen.consoleErrors).toEqual([]);
    expectOnlyLocalAssets(seen.requests, baseURL!);
  });
});
