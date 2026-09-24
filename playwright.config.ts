import { defineConfig, devices } from "@playwright/test";

const PORT = Number(process.env.E2E_PORT ?? 4178);

// Browsers: installed Chrome and Edge on Windows (no Playwright browser download needed);
// elsewhere Playwright's bundled Chromium (`npx playwright install chromium`).
// Override with e.g. PW_CHANNELS=chromium or PW_CHANNELS=chrome.
const channels = process.env.PW_CHANNELS
  ? process.env.PW_CHANNELS.split(",").map((c) => c.trim()).filter(Boolean)
  : process.platform === "win32"
    ? ["chrome", "msedge"]
    : ["chromium"];

export default defineConfig({
  testDir: "e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [["list"]],
  timeout: 60_000,
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: "retain-on-failure",
  },
  projects: channels.map((channel) => ({
    name: channel,
    use: channel === "chromium" ? { ...devices["Desktop Chrome"] } : { ...devices["Desktop Chrome"], channel },
  })),
  webServer: {
    // Builds dist/ and serves it; never reuses a server that happens to be running.
    command: "node scripts/e2e-server.mjs",
    url: `http://127.0.0.1:${PORT}/1-security-twin/`,
    reuseExistingServer: false,
    timeout: 180_000,
    env: { PORT: String(PORT) },
    stdout: "ignore",
    stderr: "pipe",
  },
});
