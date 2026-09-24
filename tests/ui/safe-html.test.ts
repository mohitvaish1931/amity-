import { describe, expect, it } from "vitest";
import { JSDOM } from "jsdom";
import { escapeHtml, html, joinHtml, setHtml, type SafeHtml } from "../../src/ui/safe-html";

describe("escapeHtml", () => {
  it("escapes every character that can break out of text or a quoted attribute", () => {
    expect(escapeHtml(`<a href="x" onclick='y'>&\`</a>`)).toBe("&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&#96;&lt;/a&gt;");
    expect(escapeHtml(null)).toBe("");
    expect(escapeHtml(42)).toBe("42");
  });
});

describe("html`` templates", () => {
  it("escapes interpolated strings by default", () => {
    const label = '"><img src=x onerror="alert(1)">';
    expect(html`<b title="${label}">${label}</b>`.value).toBe(
      '<b title="&quot;&gt;&lt;img src=x onerror=&quot;alert(1)&quot;&gt;">&quot;&gt;&lt;img src=x onerror=&quot;alert(1)&quot;&gt;</b>',
    );
  });

  it("nests fragments and arrays of fragments without double escaping", () => {
    const rows = ["a<b", "c"].map((x) => html`<li>${x}</li>`);
    expect(html`<ul>${rows}</ul>`.value).toBe("<ul><li>a&lt;b</li><li>c</li></ul>");
    expect(joinHtml(rows, html`<br>`).value).toBe("<li>a&lt;b</li><br><li>c</li>");
  });

  it("renders null, undefined and false as nothing so conditionals are easy", () => {
    const flag = false as boolean;
    expect(html`${null}${undefined}${flag && html`<i>x</i>`}${0}`.value).toBe("0");
  });

  it("refuses implicit string conversion of fragments", () => {
    const frag = html`<i>x</i>`;
    expect(() => [frag, frag].join("")).toThrow(/cannot be converted/);
    expect(() => `${frag}`).toThrow(/cannot be converted/);
  });
});

describe("setHtml", () => {
  it("writes fragments and rejects plain strings", () => {
    const { document } = new JSDOM("<div id=t></div>").window;
    const el = document.getElementById("t")!;
    setHtml(el, html`<span>${"<script>x</script>"}</span>`);
    expect(el.querySelector("script")).toBeNull();
    expect(el.textContent).toBe("<script>x</script>");
    expect(() => setHtml(el, "<b>raw</b>" as unknown as SafeHtml)).toThrow(/only accepts/);
  });
});
