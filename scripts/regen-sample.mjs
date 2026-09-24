// Regenerates 2-test-lab/samples/sample-testable-model.json by running Step 1 on its demo input.
// tests/apps/sample-model.test.ts fails if the committed sample drifts from this output.
import { writeFileSync } from "node:fs";
import path from "node:path";
import { ROOT, loadApp } from "./app-harness.mjs";

export async function generateSampleModel() {
  const app = await loadApp("1-security-twin");
  try {
    app.click("demoBtn");
    await app.settle();
    app.click("buildBtn");
    if (app.alerts.length) throw new Error(`Step 1 reported: ${app.alerts.join(" | ")}`);
    return app.$("out4").textContent + "\n";
  } finally {
    app.close();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.join(ROOT, "scripts", "regen-sample.mjs")) {
  const text = await generateSampleModel();
  const out = path.join(ROOT, "2-test-lab", "samples", "sample-testable-model.json");
  writeFileSync(out, text);
  console.log(`wrote ${path.relative(ROOT, out)}`);
}
