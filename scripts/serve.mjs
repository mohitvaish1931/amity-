// Minimal static file server for dist/ (local development only; binds to 127.0.0.1).
import { createServer } from "node:http";
import { existsSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { ROOT } from "./app-harness.mjs";
import { resolveStaticPath } from "./static-path.mjs";

const DIST = path.join(ROOT, "dist");
const PORT = Number(process.env.PORT || 8000);
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8", ".yaml": "text/yaml; charset=utf-8", ".yml": "text/yaml; charset=utf-8" };

if (!existsSync(DIST)) {
  console.error("dist/ not found. Run `npm run build` first.");
  process.exit(1);
}

createServer((req, res) => {
  const resolved = resolveStaticPath(DIST, req.url);
  if (!resolved.ok) {
    res.writeHead(resolved.status).end(resolved.status === 400 ? "bad request" : "forbidden");
    return;
  }
  let file = resolved.file;
  if (existsSync(file) && statSync(file).isDirectory()) file = path.join(file, "index.html");
  if (!existsSync(file)) {
    res.writeHead(404).end("not found");
    return;
  }
  res.writeHead(200, { "Content-Type": TYPES[path.extname(file)] || "application/octet-stream", "X-Content-Type-Options": "nosniff" });
  res.end(readFileSync(file));
}).listen(PORT, "127.0.0.1", () => {
  console.log(`Sentinel X: http://127.0.0.1:${PORT}/  (Step 1: /1-security-twin/, Step 2: /2-test-lab/)`);
});
