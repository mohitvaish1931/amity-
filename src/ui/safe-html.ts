// Escape-by-default HTML templating for the browser apps.
//
//   setHtml(el, html`<b>${userText}</b>`)
//
// Every interpolated value is escaped unless it is itself an html`` fragment (SafeHtml).
// Arrays of fragments are concatenated. setHtml() refuses plain strings, so raw markup
// can only reach the DOM through a template literal written in source code.

const brand = Symbol("SafeHtml");

export class SafeHtml {
  readonly [brand] = true;
  constructor(readonly value: string) {}

  /** Implicit string conversion (e.g. Array#join) would silently re-escape or leak markup. */
  toString(): string {
    throw new TypeError("SafeHtml cannot be converted to a string implicitly; interpolate it in html`` or use joinHtml().");
  }
}

export type HtmlValue = SafeHtml | string | number | boolean | null | undefined | readonly HtmlValue[];

const ESCAPES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
  "`": "&#96;",
};

/** Escape text for use in element content or in a quoted attribute value. */
export function escapeHtml(value: unknown): string {
  return String(value ?? "").replace(/[&<>"'`]/g, (c) => ESCAPES[c]!);
}

function render(value: HtmlValue): string {
  if (value === null || value === undefined || value === false) return "";
  if (value instanceof SafeHtml) return value.value;
  if (Array.isArray(value)) return value.map(render).join("");
  return escapeHtml(value);
}

export function html(strings: TemplateStringsArray, ...values: HtmlValue[]): SafeHtml {
  let out = strings[0] ?? "";
  for (let i = 0; i < values.length; i++) out += render(values[i]!) + (strings[i + 1] ?? "");
  return new SafeHtml(out);
}

export function joinHtml(items: readonly HtmlValue[], separator: HtmlValue = ""): SafeHtml {
  const sep = render(separator);
  return new SafeHtml(items.map(render).join(sep));
}

export function setHtml(el: Element | null, content: SafeHtml): void {
  if (!el) return;
  if (!(content instanceof SafeHtml)) throw new TypeError("setHtml() only accepts html`` fragments.");
  el.innerHTML = content.value;
}
