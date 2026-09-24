import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**", "coverage/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.ts", "**/*.tsx"],
    rules: {
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/no-unused-vars": ["error", { ignoreRestSiblings: true, argsIgnorePattern: "^_" }],
    },
  },
  {
    // Browser apps: plain JS bundled by esbuild (see scripts/build.mjs).
    files: ["1-security-twin/**/*.js", "2-test-lab/**/*.js"],
    languageOptions: { globals: globals.browser, sourceType: "module" },
    rules: {
      // Legacy prototype code: keep signal on real problems, not style.
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": ["error", { args: "none", caughtErrors: "none" }],
      "no-empty": ["error", { allowEmptyCatch: true }],
      "@typescript-eslint/no-unused-expressions": "off",
      // Rendering must go through setHtml()/html`` from src/ui/safe-html.ts.
      "no-restricted-properties": ["error",
        { property: "innerHTML", message: "Use setHtml(el, html`...`) from src/ui/safe-html.ts." },
        { property: "outerHTML", message: "Use setHtml(el, html`...`) from src/ui/safe-html.ts." }],
      "no-restricted-syntax": ["error",
        { selector: "CallExpression[callee.property.name='insertAdjacentHTML']", message: "Use setHtml() with html``." }],
    },
  },
  {
    files: ["scripts/**/*.mjs"],
    languageOptions: { globals: globals.node },
  },
);
