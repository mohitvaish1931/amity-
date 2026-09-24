import { createRoot } from "react-dom/client";
import { flushSync } from "react-dom";
import { SecurityTwinGraph } from "./SecurityTwinGraph";
import type { TwinGraphInput } from "./graph";

/** Mounts the Security Twin graph into a plain DOM element (used by the vanilla Step 1 app). */
export function mountSecurityTwinGraph(el: HTMLElement) {
  const root = createRoot(el);
  return {
    render(input: TwinGraphInput | null): void {
      // Synchronous so the DOM reflects the model as soon as the caller returns.
      flushSync(() => root.render(<SecurityTwinGraph input={input} />));
    },
    unmount(): void {
      root.unmount();
    },
  };
}
