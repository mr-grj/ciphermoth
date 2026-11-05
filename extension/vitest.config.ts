import { defineConfig } from "vitest/config";

export default defineConfig({
  define: {
    __E2E__: "false",
    __TARGET__: JSON.stringify("chromium"),
    __VERSION__: JSON.stringify("0.0.0-test"),
  },
  esbuild: { jsx: "automatic", jsxImportSource: "preact" },
  test: { environment: "node", include: ["tests/unit/**/*.test.ts"] },
});
