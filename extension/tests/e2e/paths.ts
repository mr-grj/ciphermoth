import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const EXTENSION_ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");
export const E2E_DIR = join(EXTENSION_ROOT, ".e2e");
export const FRONTEND_DIST = join(E2E_DIR, "frontend");
export const BACKEND_DIR = join(EXTENSION_ROOT, "../backend");
export const TEST_BUILD = join(EXTENSION_ROOT, "dist-test/chromium");
export const SITES_DIR = join(EXTENSION_ROOT, "tests/fixtures/sites");
export const LAB_DIR = join(EXTENSION_ROOT, "tests/attack-lab");
export const OTHER_EXTENSION = join(EXTENSION_ROOT, "tests/fixtures/other-extension");
