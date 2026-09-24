// Loads a browser app (1-security-twin / 2-test-lab) into jsdom with its real bundled code.
// Used by tests and by scripts/regen-sample.mjs. No network: fetch() only serves the app's own files.
import { build } from "esbuild";
import { JSDOM } from "jsdom";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Bundle <appDir>/app.js (and the src/ modules it imports) into one IIFE string. */
export async function bundleApp(appDir, { minify = false, sourcemap = false } = {}) {
  const result = await build({
    entryPoints: [path.join(ROOT, appDir, "app.js")],
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "es2020",
    write: false,
    minify,
    sourcemap: sourcemap ? "inline" : false,
    logLevel: "silent",
  });
  return result.outputFiles[0].text;
}

export async function loadApp(appDir) {
  const code = await bundleApp(appDir);
  const page = readFileSync(path.join(ROOT, appDir, "index.html"), "utf8").replace(/<script[^>]*src="app\.js"[^>]*><\/script>/, "");
  const dom = new JSDOM(page, { runScripts: "dangerously", url: `http://sentinel.test/${appDir}/`, pretendToBeVisual: true });
  const w = dom.window;
  const alerts = [];
  w.alert = (m) => alerts.push(String(m));
  Object.defineProperty(w.navigator, "clipboard", { value: { writeText: async () => {} }, configurable: true });
  w.fetch = async (url) => {
    const u = new URL(String(url), w.location.href);
    const appRoot = `/${appDir}/`;
    if (u.origin !== "http://sentinel.test" || !u.pathname.startsWith(appRoot)) {
      throw new Error(`harness: network access blocked (${u.href})`);
    }
    const file = path.join(ROOT, appDir, decodeURIComponent(u.pathname.slice(appRoot.length)));
    const text = readFileSync(file, "utf8");
    return { ok: true, status: 200, text: async () => text, json: async () => JSON.parse(text) };
  };
  w.eval(code);
  w.dispatchEvent(new w.Event("DOMContentLoaded"));

  const $ = (id) => w.document.getElementById(id);
  return {
    window: w,
    document: w.document,
    alerts,
    $,
    click: (id) => $(id).click(),
    setValue: (id, value) => {
      $(id).value = value;
    },
    /** Let pending promise callbacks (fetch/FileReader chains) settle. */
    settle: () => new Promise((r) => setTimeout(r, 20)),
    close: () => w.close(),
  };
}
