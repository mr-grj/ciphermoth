import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

// The extension renders only through Preact and never builds HTML or code from
// strings: these sinks are errors everywhere, tests included.
const SINKS = {
  "no-eval": "error",
  "no-implied-eval": "error",
  "no-new-func": "error",
  "no-script-url": "error",
  "no-restricted-properties": [
    "error",
    ...["innerHTML", "outerHTML", "insertAdjacentHTML", "srcdoc"].map((property) => ({
      property,
      message: "Build DOM with Preact or createElement, never from HTML strings.",
    })),
    { object: "document", property: "write", message: "No document.write." },
    { object: "document", property: "writeln", message: "No document.writeln." },
  ],
  "no-restricted-syntax": [
    "error",
    {
      selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
      message: "No raw HTML in the extension's pages.",
    },
    {
      selector: "CallExpression[callee.name=/^set(Timeout|Interval)$/][arguments.0.type='Literal']",
      message: "No string timers.",
    },
    {
      selector: "Identifier[name='onMessageExternal']",
      message: "The extension accepts no messages from outside itself.",
    },
  ],
};

export default tseslint.config(
  {
    ignores: [
      ".e2e/**",
      "dist/**",
      "dist-test/**",
      "dist-dev/**",
      "node_modules/**",
      "test-results/**",
      "playwright-report/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx,js,mjs}"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: { ...globals.browser, ...globals.webextensions, ...globals.node },
    },
    rules: {
      ...SINKS,
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
    },
  },
  {
    // Attack-lab pages are hostile on purpose; only the sink bans are relaxed
    // where a page needs them to attack.
    files: ["tests/attack-lab/**"],
    rules: { "no-restricted-properties": "off" },
  },
  {
    // Tests name hostile URLs (javascript:, data:) as data, never navigate the
    // extension to them.
    files: ["tests/**"],
    rules: { "no-script-url": "off" },
  }
);
