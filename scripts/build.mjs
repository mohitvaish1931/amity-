// Production build: dist/<app>/ with bundled app.js, index.html, styles.css and samples/.
import { cpSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { ROOT, bundleApp } from "./app-harness.mjs";

const APPS = [
  { dir: "1-security-twin", title: "Step 1 — Security Twin", assets: ["index.html", "styles.css", "samples"] },
  { dir: "2-test-lab", title: "Step 2 — Test Lab", assets: ["index.html", "styles.css", "samples"] },
];
const DIST = path.join(ROOT, "dist");

rmSync(DIST, { recursive: true, force: true });
for (const app of APPS) {
  const out = path.join(DIST, app.dir);
  mkdirSync(out, { recursive: true });
  for (const asset of app.assets) cpSync(path.join(ROOT, app.dir, asset), path.join(out, asset), { recursive: true });
  const { js, css } = await bundleApp(app.dir, { minify: true });
  writeFileSync(path.join(out, "app.js"), js);
  console.log(`built dist/${app.dir}/app.js (${(js.length / 1024).toFixed(1)} KiB)`);
  if (css) {
    writeFileSync(path.join(out, "app.css"), css);
    console.log(`built dist/${app.dir}/app.css (${(css.length / 1024).toFixed(1)} KiB)`);
  }
}

const links = APPS.map((a) => `<li><a href="${a.dir}/">${a.title}</a></li>`).join("");
writeFileSync(
  path.join(DIST, "index.html"),
  `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Sentinel X</title></head>` +
    `<body style="font-family:system-ui;background:#070b16;color:#e2e8f0;padding:24px">` +
    `<h1>Sentinel X</h1><ul>${links}</ul></body></html>`,
);
console.log("build complete: dist/");
