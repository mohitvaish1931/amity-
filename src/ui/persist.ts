// Opt-in, per-browser save/restore of Step 1 inputs (spec, configuration, sandbox URL, sensitivity overrides).
// Never stores credentials. Storage can be missing, full or blocked; every call returns a result instead of throwing.

export const SENSITIVITY_LEVELS = ["PUBLIC", "INTERNAL", "PERSONAL", "SENSITIVE"] as const;
type Level = (typeof SENSITIVITY_LEVELS)[number];

export interface Workspace {
  specText: string;
  identities: string;
  permissions: string;
  ownership: string;
  baseUrl: string;
  overrides: Record<string, Level>;
}

export interface SavedWorkspace extends Workspace {
  version: 1;
  savedAt: string;
}

/** Upper bound for one saved workspace (characters); browsers allow roughly 5 MB per origin. */
export const MAX_WORKSPACE_CHARS = 2_000_000;

export type LoadResult = { ok: true; data: SavedWorkspace } | { ok: false; reason: "empty" | "unavailable" | "corrupt" };
export type SaveResult = { ok: true; savedAt: string } | { ok: false; reason: "unavailable" | "too-large" | "quota"; message: string };

type StorageLike = Pick<Storage, "getItem" | "setItem" | "removeItem">;

function isWorkspace(v: unknown): v is SavedWorkspace {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  const strings = ["specText", "identities", "permissions", "ownership", "baseUrl", "savedAt"];
  if (o.version !== 1 || !strings.every((k) => typeof o[k] === "string")) return false;
  if (!o.overrides || typeof o.overrides !== "object" || Array.isArray(o.overrides)) return false;
  return Object.values(o.overrides as Record<string, unknown>).every((l) => (SENSITIVITY_LEVELS as readonly unknown[]).includes(l));
}

export function createWorkspaceStore(getStorage: () => StorageLike | null | undefined, key = "sentinel-x:step1:workspace:v1") {
  const rememberKey = `${key}:remember`;
  const storage = (): StorageLike | null => {
    try {
      return getStorage() ?? null;
    } catch {
      return null; // e.g. SecurityError when site data is blocked
    }
  };
  return {
    /** Whether the user opted in to remembering their inputs in this browser. */
    remembered(): boolean {
      try {
        return storage()?.getItem(rememberKey) === "1";
      } catch {
        return false;
      }
    },
    load(): LoadResult {
      const s = storage();
      if (!s) return { ok: false, reason: "unavailable" };
      let raw: string | null;
      try {
        raw = s.getItem(key);
      } catch {
        return { ok: false, reason: "unavailable" };
      }
      if (raw === null) return { ok: false, reason: "empty" };
      try {
        const data: unknown = JSON.parse(raw);
        return isWorkspace(data) ? { ok: true, data } : { ok: false, reason: "corrupt" };
      } catch {
        return { ok: false, reason: "corrupt" };
      }
    },
    save(ws: Workspace, now: string): SaveResult {
      const s = storage();
      if (!s) return { ok: false, reason: "unavailable", message: "browser storage is not available here" };
      // Copy only the declared fields, so nothing else a caller holds (e.g. a credential) can end up in storage.
      const data: SavedWorkspace = {
        version: 1,
        savedAt: now,
        specText: ws.specText,
        identities: ws.identities,
        permissions: ws.permissions,
        ownership: ws.ownership,
        baseUrl: ws.baseUrl,
        overrides: { ...ws.overrides },
      };
      const raw = JSON.stringify(data);
      if (raw.length > MAX_WORKSPACE_CHARS) {
        return { ok: false, reason: "too-large", message: `the spec and configuration are too large to remember (${Math.round(raw.length / 1024)} KiB)` };
      }
      try {
        s.setItem(key, raw);
        s.setItem(rememberKey, "1");
        return { ok: true, savedAt: now };
      } catch (e) {
        return { ok: false, reason: "quota", message: `browser storage refused the data (${e instanceof Error ? e.name : String(e)})` };
      }
    },
    /** Forgets the saved inputs and the opt-in. */
    clear(): void {
      const s = storage();
      try {
        s?.removeItem(key);
        s?.removeItem(rememberKey);
      } catch {
        /* nothing stored, or storage blocked: nothing to clear */
      }
    },
  };
}
