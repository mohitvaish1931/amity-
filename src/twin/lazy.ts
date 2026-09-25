// Loads the Security Twin graph (React + React Flow) only when it is first needed, so the Step 1 page does not
// download the graph code up front. Calls made before the code arrives are replayed in order once it loads.
import type { TwinGraphInput } from "./graph";
import type { mountSecurityTwinGraph } from "./mount";

type TwinView = ReturnType<typeof mountSecurityTwinGraph>;
type Loader = () => Promise<{ mountSecurityTwinGraph: typeof mountSecurityTwinGraph }>;

export type LazyTwinState = "idle" | "loading" | "ready" | "error";

export interface LazyTwinView {
  render(input: TwinGraphInput | null): void;
  focusLaw(lawId: string): void;
  readonly state: LazyTwinState;
  /** Resolves when the graph has loaded and every queued call has been applied (rejects on load failure). */
  whenReady(): Promise<void>;
}

const defaultLoader: Loader = () => import("./mount");

export function createLazyTwinView(el: HTMLElement, load: Loader = defaultLoader): LazyTwinView {
  let state: LazyTwinState = "idle";
  let view: TwinView | null = null;
  let pending: Promise<void> | null = null;
  // Only the latest input matters; a law focus applies to whatever input is current.
  let lastInput: TwinGraphInput | null | undefined;
  let lastFocus: string | null = null;

  const showStatus = (text: string, retry: boolean) => {
    el.replaceChildren();
    const p = el.ownerDocument.createElement("p");
    p.className = retry ? "sub twin-load-error" : "sub twin-loading";
    p.setAttribute("role", retry ? "alert" : "status");
    p.textContent = text;
    el.appendChild(p);
    if (retry) {
      const b = el.ownerDocument.createElement("button");
      b.type = "button";
      b.className = "ghost";
      b.textContent = "Retry loading graph";
      b.addEventListener("click", () => void ensure().catch(() => {}));
      el.appendChild(b);
    }
  };

  const apply = () => {
    if (!view) return;
    if (lastInput !== undefined) view.render(lastInput);
    if (lastFocus) view.focusLaw(lastFocus);
  };

  const ensure = (): Promise<void> => {
    if (view) return Promise.resolve();
    if (pending) return pending;
    state = "loading";
    showStatus("Loading Security Twin graph…", false);
    pending = load().then(
      (mod) => {
        el.replaceChildren();
        view = mod.mountSecurityTwinGraph(el);
        state = "ready";
        pending = null;
        apply();
      },
      (err: unknown) => {
        state = "error";
        pending = null;
        showStatus(`Could not load the Security Twin graph (${err instanceof Error ? err.message : String(err)}).`, true);
        throw err;
      },
    );
    return pending;
  };

  return {
    render(input) {
      lastInput = input;
      lastFocus = null;
      if (view) view.render(input);
      else void ensure().catch(() => {});
    },
    focusLaw(lawId) {
      lastFocus = lawId;
      if (view) view.focusLaw(lawId);
      else void ensure().catch(() => {});
    },
    get state() {
      return state;
    },
    whenReady: () => ensure(),
  };
}
