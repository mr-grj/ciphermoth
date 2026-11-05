import { defineConfig } from "@playwright/test";

// Extension tests drive Playwright's own Chromium with the test build loaded
// (branded Chrome no longer accepts --load-extension). Each test file starts a
// live backend and an HTTPS fixture server; see tests/e2e/harness.ts.
export default defineConfig({
  testDir: "tests/e2e",
  timeout: 90_000,
  expect: { timeout: 10_000 },
  workers: 1,
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  globalSetup: "./tests/e2e/global-setup.ts",
  use: { trace: "retain-on-failure" },
});
