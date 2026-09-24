// Generic naming helpers. No domain words live here.

/** "customerId" / "customer_id" / "Customer-ID" / "APIKey2" -> ["customer","id"] etc. */
export function tokenize(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((t) => t.toLowerCase());
}

const IRREGULAR: Record<string, string> = {
  people: "person",
  children: "child",
  men: "man",
  women: "woman",
  data: "data",
  media: "media",
  criteria: "criterion",
};
const NO_STRIP = /(ss|us|is|ics)$/;

export function singularize(word: string): string {
  const w = word.toLowerCase();
  if (IRREGULAR[w]) return IRREGULAR[w]!;
  if (w.length > 3 && w.endsWith("ies")) return w.slice(0, -3) + "y";
  if (w.endsWith("sses")) return w.slice(0, -2);
  if (/(xes|ches|shes|zzes)$/.test(w)) return w.slice(0, -2);
  if (NO_STRIP.test(w)) return w;
  if (w.length > 3 && w.endsWith("s")) return w.slice(0, -1);
  return w;
}

export function pascal(tokens: readonly string[]): string {
  return tokens.map((t) => t.charAt(0).toUpperCase() + t.slice(1)).join("");
}

/** Singular PascalCase resource name from a raw word or identifier. */
export function resourceName(raw: string): string {
  const tokens = tokenize(raw);
  if (!tokens.length) return "";
  tokens[tokens.length - 1] = singularize(tokens[tokens.length - 1]!);
  return pascal(tokens);
}
