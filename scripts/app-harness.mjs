// Loads a browser app (1-security-twin / 2-test-lab) into jsdom with its real bundled code.
// Used by tests and by scripts/regen-sample.mjs. No network: fetch() only serves the app's own files.
import { build } from "esbuild";
import { JSDOM } from "jsdom";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Bundle <appDir>/app.js (and the src/ modules it imports). Returns the JS and any bundled CSS. */
export async function bundleApp(appDir, { minify = false, sourcemap = false } = {}) {
  const result = await build({
    entryPoints: [path.join(ROOT, appDir, "app.js")],
    bundle: true,
    format: "iife",
    platform: "browser",
    target: "es2020",
    outdir: path.join(ROOT, "dist", appDir), // naming only; write:false keeps output in memory
    write: false,
    minify,
    sourcemap: sourcemap ? "inline" : false,
    jsx: "automatic",
    define: { "process.env.NODE_ENV": JSON.stringify(minify ? "production" : "development") },
    logLevel: "silent",
  });
  const js = result.outputFiles.find((f) => f.path.endsWith(".js"));
  const css = result.outputFiles.find((f) => f.path.endsWith(".css"));
  return { js: js ? js.text : "", css: css ? css.text : "" };
}

/** Minimal layout APIs React Flow needs in jsdom (it measures nodes and observes resizes). */
function installLayoutStubs(w) {
  w.ResizeObserver = class {
    constructor(cb) {
      this.cb = cb;
    }
    observe(target) {
      const rect = { width: target.offsetWidth, height: target.offsetHeight, top: 0, left: 0, x: 0, y: 0 };
      this.cb([{ target, contentRect: rect, borderBoxSize: [{ inlineSize: rect.width, blockSize: rect.height }] }], this);
    }
    unobserve() {}
    disconnect() {}
  };
  w.DOMMatrixReadOnly = class {
    constructor(transform) {
      const scale = /scale\(([\d.]+)\)/.exec(String(transform || ""));
      this.m22 = scale ? Number(scale[1]) : 1;
    }
  };
  Object.defineProperties(w.HTMLElement.prototype, {
    offsetHeight: { get() { return parseFloat(this.style.height) || 1; }, configurable: true },
    offsetWidth: { get() { return parseFloat(this.style.width) || 1; }, configurable: true },
  });
  w.SVGElement.prototype.getBBox = () => ({ x: 0, y: 0, width: 0, height: 0 });
}

export async function loadApp(appDir) {
  const { js, css } = await bundleApp(appDir);
  const page = readFileSync(path.join(ROOT, appDir, "index.html"), "utf8").replace(/<script[^>]*src="app\.js"[^>]*><\/script>/, "");
  const dom = new JSDOM(page, { runScripts: "dangerously", url: `http://sentinel.test/${appDir}/`, pretendToBeVisual: true });
  const w = dom.window;
  installLayoutStubs(w);
  if (css) {
    const style = w.document.createElement("style");
    style.textContent = css;
    w.document.head.appendChild(style);
  }
  const alerts = [];
  const errors = [];
  w.alert = (m) => alerts.push(String(m));
  w.addEventListener("error", (e) => errors.push(String(e.message || e.error)));
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
  w.eval(js);
  w.dispatchEvent(new w.Event("DOMContentLoaded"));

  const $ = (id) => w.document.getElementById(id);
  return {
    window: w,
    document: w.document,
    alerts,
    errors,
    $,
    click: (id) => $(id).click(),
    setValue: (id, value) => {
      $(id).value = value;
    },
    /** Let pending promise callbacks (fetch/FileReader chains, React effects) settle. */
    settle: () => new Promise((r) => setTimeout(r, 30)),
    /** Poll until `predicate()` is truthy. For state that appears after asynchronous React renders. */
    waitFor: async (predicate, { timeout = 5000, interval = 20 } = {}) => {
      const deadline = Date.now() + timeout;
      for (;;) {
        if (predicate()) return;
        if (Date.now() > deadline) throw new Error(`waitFor: condition not met within ${timeout}ms`);
        await new Promise((r) => setTimeout(r, interval));
      }
    },
    close: () => w.close(),
  };
}
