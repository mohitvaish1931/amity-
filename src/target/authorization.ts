// What the application actually knows about a sandbox target's authorization.
// Configuring a URL is not proof of authorization; only a matching confirmation record is.

export type TargetAuthorizationState = "UNKNOWN" | "CONFIGURED" | "CONFIRMED";

/** A recorded authorization for one target. Nothing in the current apps produces this yet. */
export interface TargetAuthorizationRecord {
  targetUrl: string;
  confirmedBy: string;
  confirmedAt: string;
  scope: string;
}

export interface TargetAuthorization {
  state: TargetAuthorizationState;
  /** Normalized target (origin + path, no trailing slash), or null when absent/invalid. */
  target: string | null;
  label: string;
  detail: string;
}

export function normalizeTargetUrl(raw: string | null | undefined): string | null {
  const text = (raw ?? "").trim();
  if (!text) return null;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (url.username || url.password) return null; // credentials never belong in a target URL
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

export function deriveTargetAuthorization(
  baseUrl: string | null | undefined,
  record?: TargetAuthorizationRecord | null,
): TargetAuthorization {
  const trimmed = (baseUrl ?? "").trim();
  const target = normalizeTargetUrl(trimmed);
  if (!trimmed) {
    return { state: "UNKNOWN", target: null, label: "No sandbox target configured", detail: "Authorization status unknown." };
  }
  if (!target) {
    return {
      state: "UNKNOWN",
      target: null,
      label: "Target URL is not valid",
      detail: "Authorization status unknown. Use an http(s) URL without embedded credentials.",
    };
  }
  if (record && normalizeTargetUrl(record.targetUrl) === target && record.confirmedBy && record.confirmedAt) {
    return {
      state: "CONFIRMED",
      target,
      label: "Authorization confirmed",
      detail: `Confirmed by ${record.confirmedBy} at ${record.confirmedAt} (scope: ${record.scope || "unspecified"}).`,
    };
  }
  return {
    state: "CONFIGURED",
    target,
    label: "Sandbox target configured",
    detail: "Authorization status unknown: configuring a URL does not show that you are authorized to test it.",
  };
}
