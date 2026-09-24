import { createRoot } from "react-dom/client";
import { flushSync } from "react-dom";
import { SecurityTwinGraph, type LawFocus } from "./SecurityTwinGraph";
import type { TwinGraphInput } from "./graph";

/** Mounts the Security Twin graph into a plain DOM element (used by the vanilla Step 1 app). */
export function mountSecurityTwinGraph(el: HTMLElement) {
  const root = createRoot(el);
  let input: TwinGraphInput | null = null;
  let focus: LawFocus = null;
  let seq = 0;
  // Synchronous so the DOM reflects the model as soon as the caller returns.
  const draw = () => flushSync(() => root.render(<SecurityTwinGraph input={input} focus={focus} />));
  return {
    render(next: TwinGraphInput | null): void {
      input = next;
      focus = null;
      draw();
    },
    /** Highlight one law's scope in the graph and zoom to it. */
    focusLaw(lawId: string): void {
      focus = { lawId, seq: ++seq };
      draw();
    },
    unmount(): void {
      root.unmount();
    },
  };
}
