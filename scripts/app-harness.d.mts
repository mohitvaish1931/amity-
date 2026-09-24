import type { DOMWindow } from "jsdom";

export const ROOT: string;

export function bundleApp(appDir: string, opts?: { minify?: boolean; sourcemap?: boolean }): Promise<string>;

export interface LoadedApp {
  window: DOMWindow & { __xss?: unknown };
  document: Document;
  alerts: string[];
  $: (id: string) => HTMLElement & { value: string };
  click: (id: string) => void;
  setValue: (id: string, value: string) => void;
  settle: () => Promise<void>;
  close: () => void;
}

export function loadApp(appDir: "1-security-twin" | "2-test-lab"): Promise<LoadedApp>;
