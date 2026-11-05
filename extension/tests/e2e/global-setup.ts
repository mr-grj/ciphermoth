import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

import { E2E_DIR, EXTENSION_ROOT, FRONTEND_DIST } from "./paths";

// The web app is served by the fixture server for the handoff tests, built
// once with a relative API URL (the fixture server proxies /api).
export default function globalSetup(): void {
  if (!existsSync(join(EXTENSION_ROOT, "dist-test/chromium/manifest.json"))) {
    execFileSync("node", ["scripts/build.mjs", "--test"], {
      cwd: EXTENSION_ROOT,
      stdio: "inherit",
    });
  }
  if (process.env.E2E_REBUILD_FRONTEND || !existsSync(join(FRONTEND_DIST, "index.html"))) {
    execFileSync(
      "npx",
      ["vite", "build", "--outDir", FRONTEND_DIST, "--emptyOutDir", "--logLevel", "warn"],
      {
        cwd: join(EXTENSION_ROOT, "../frontend"),
        stdio: "inherit",
        env: { ...process.env, VITE_API_URL: "/api" },
      }
    );
  }
  void E2E_DIR;
}
