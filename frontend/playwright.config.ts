import { defineConfig, devices } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e",
  timeout: 45_000,
  workers: 1,
  use: { baseURL: "http://127.0.0.1:3000", trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      command: "uv run python scripts/e2e_server.py",
      cwd: "..",
      url: "http://127.0.0.1:8000/health/live",
      timeout: 60_000,
      reuseExistingServer: false,
    },
    {
      command: "npm run dev -- --port 3000",
      url: "http://127.0.0.1:3000",
      timeout: 60_000,
      reuseExistingServer: false,
      env: { NEXT_TELEMETRY_DISABLED: "1" },
    },
  ],
});
