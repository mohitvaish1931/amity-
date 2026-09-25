// Maps a request URL to a file inside a root folder, or explains why not. Pure, so the static servers can share it.
import path from "node:path";

/**
 * @returns {{ ok: true, file: string } | { ok: false, status: 400 | 403 }}
 * 400: undecodable path (e.g. a malformed %-escape). 403: the path resolves outside `root` (including sibling folders
 * that merely share its name as a prefix, like root "dist" vs "dist-old").
 */
export function resolveStaticPath(root, requestUrl) {
  let urlPath;
  try {
    urlPath = decodeURIComponent(new URL(requestUrl || "/", "http://localhost").pathname);
  } catch {
    return { ok: false, status: 400 };
  }
  if (urlPath.includes("\0")) return { ok: false, status: 400 };
  const base = path.resolve(root);
  const file = path.resolve(base, `.${path.sep}${urlPath}`);
  if (file !== base && !file.startsWith(base + path.sep)) return { ok: false, status: 403 };
  return { ok: true, file };
}
