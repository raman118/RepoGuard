import { defineConfig, globalIgnores } from "eslint/config";
import js from "@eslint/js";
import ts from "typescript-eslint";
import hooks from "eslint-plugin-react-hooks";
import a11y from "eslint-plugin-jsx-a11y";

export default defineConfig([
  globalIgnores([
    ".next/**",
    "next-env.d.ts",
    "playwright-report/**",
    "test-results/**",
  ]),
  js.configs.recommended,
  ...ts.configs.recommended,
  { ...hooks.configs.flat.recommended, files: ["**/*.{ts,tsx}"] },
  { ...a11y.flatConfigs.recommended, files: ["**/*.tsx"] },
  {
    files: ["**/*.{ts,tsx,mjs}"],
    languageOptions: {
      globals: {
        process: "readonly",
        Buffer: "readonly",
        fetch: "readonly",
        AbortSignal: "readonly",
        AbortController: "readonly",
        console: "readonly",
        crypto: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
      },
    },
  },
]);
