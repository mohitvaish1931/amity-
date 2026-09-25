// Inline operation status (loading / success / empty / error / info), announced to assistive technology.
// Errors use role="alert" and can offer a Retry button; nothing fails silently.
import { html, joinHtml, setHtml } from "./safe-html";

export type StatusKind = "loading" | "success" | "empty" | "error" | "info";

export interface StatusOptions {
  /** Extra lines, e.g. individual validation errors. */
  details?: readonly string[];
  /** Shows a Retry button that calls this. */
  retry?: () => void;
}

const ICON: Record<StatusKind, string> = { loading: "…", success: "✓", empty: "○", error: "✕", info: "ℹ" };

export function showStatus(el: HTMLElement, kind: StatusKind, message: string, opts: StatusOptions = {}): void {
  el.dataset.status = kind;
  el.setAttribute("role", kind === "error" ? "alert" : "status");
  el.setAttribute("aria-live", kind === "error" ? "assertive" : "polite");
  el.setAttribute("aria-busy", kind === "loading" ? "true" : "false");
  const details = opts.details?.length ? html`<ul class="status-details">${opts.details.map((d) => html`<li>${d}</li>`)}</ul>` : "";
  const retry = opts.retry ? html` <button class="ghost status-retry" type="button">Retry</button>` : "";
  setHtml(el, html`<span class="status-${kind}"><span aria-hidden="true">${ICON[kind]}</span> ${message}</span>${retry}${details}`);
  if (opts.retry) {
    const run = opts.retry;
    el.querySelector<HTMLButtonElement>(".status-retry")!.addEventListener("click", () => run());
  }
}

export function clearStatus(el: HTMLElement): void {
  delete el.dataset.status;
  el.setAttribute("aria-busy", "false");
  setHtml(el, joinHtml([]));
}

/** Fetches a text resource of the app itself; rejects with a readable message on HTTP errors. */
export async function fetchText(url: string, fetchImpl: typeof fetch = fetch): Promise<string> {
  let r: Response;
  try {
    r = await fetchImpl(url);
  } catch (e) {
    throw new Error(`could not reach ${url} (${e instanceof Error ? e.message : String(e)})`);
  }
  if (!r.ok) throw new Error(`${url} returned HTTP ${r.status}`);
  return r.text();
}

/** Copies text and reports the real outcome (clipboard access can be denied). */
export async function copyText(text: string, clipboard: Pick<Clipboard, "writeText"> | undefined = globalThis.navigator?.clipboard): Promise<void> {
  if (!clipboard) throw new Error("clipboard is not available in this context");
  await clipboard.writeText(text);
}
