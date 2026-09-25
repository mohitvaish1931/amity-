export function resolveStaticPath(root: string, requestUrl: string | undefined): { ok: true; file: string } | { ok: false; status: 400 | 403 };
