import type { DOMWindow } from "jsdom";

export const ROOT: string;

export function bundleApp(appDir: string, opts?: { minify?: boolean; sourcemap?: boolean }): Promise<{ js: string; css: string }>;

export interface LoadedApp {
  window: DOMWindow & { __xss?: unknown };
  document: Document;
  alerts: string[];
  /** Uncaught errors raised inside the page. */
  errors: string[];
  $: (id: string) => HTMLElement & { value: string };
  click: (id: string) => void;
  setValue: (id: string, value: string) => void;
  settle: () => Promise<void>;
  waitFor: (predicate: () => unknown, opts?: { timeout?: number; interval?: number }) => Promise<void>;
  close: () => void;
}

export function loadApp(appDir: "1-security-twin" | "2-test-lab"): Promise<LoadedApp>;
