import type { DOMWindow } from "jsdom";

export const ROOT: string;

export function bundleApp(
  appDir: string,
  opts?: { minify?: boolean; sourcemap?: boolean; split?: boolean },
): Promise<{ js: string; css: string; chunks: Record<string, string> }>;

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

/** `beforeRun(window)` runs before the app script, e.g. to pre-fill localStorage as a previous visit would have. */
export function loadApp(appDir: "1-security-twin" | "2-test-lab", opts?: { beforeRun?: (window: LoadedApp["window"]) => void }): Promise<LoadedApp>;
