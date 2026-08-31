// Copyright 2026 Imran Hafeez (RZA)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Repository markdown reaches the browser with the Replicant origin and the
// ambient session cookie, so raw HTML in it must never become markup.
//
// The defect these guard, from the 2026-08 review: the Docs tab passed
// `marked.parse` output straight to `dangerouslySetInnerHTML`, and marked
// preserved `<img src=x onerror=...>` unchanged. The comment in the source
// argued repository files are trusted because anyone who can edit docs can edit
// the app. Documentation is reviewed under a different bar than executable code,
// which is exactly why that reasoning fails.

import { describe, expect, it } from "vitest";
import { renderMarkdown } from "./DocsView";

describe("renderMarkdown", () => {
  it("does not emit an inline event handler", () => {
    const html = renderMarkdown('<img src=x onerror="globalThis.pwned=1">');

    // The escaped output still CONTAINS the characters "onerror=" as visible
    // text, which is the point: it is text, not an attribute. What must not
    // survive is the element it would have hung off.
    expect(html).not.toMatch(/<img/i);
    expect(html).toContain("&lt;img");
  });

  it("does not emit a script element", () => {
    const html = renderMarkdown("<script>globalThis.pwned=1</script>");

    expect(html).not.toMatch(/<script/i);
  });

  it("does not emit an svg payload", () => {
    const html = renderMarkdown('<svg><animate onbegin="globalThis.pwned=1" /></svg>');

    expect(html).not.toMatch(/<svg/i);
    expect(html).not.toMatch(/<animate/i);
    expect(html).toContain("&lt;svg");
  });

  it("shows the raw tag as text instead of silently dropping it", () => {
    // Dropping it would hide from a reader that the source contains markup.
    const html = renderMarkdown("<b>bold</b>");

    expect(html).toContain("&lt;b&gt;");
  });

  it("still renders the markdown the CEF references are made of", () => {
    // The five served documents are headings, tables and fenced code. If the fix
    // broke those it would have traded one defect for a worse one.
    const html = renderMarkdown("# Title\n\n| a | b |\n| - | - |\n| 1 | 2 |\n\n```\nCEF:0|x|y\n```\n");

    expect(html).toMatch(/<h1/);
    expect(html).toMatch(/<table/);
    expect(html).toMatch(/<code/);
    expect(html).toContain("CEF:0");
  });

  it("leaves a javascript: link unusable", () => {
    const html = renderMarkdown("[click](javascript:globalThis.pwned=1)");

    expect(html).not.toMatch(/href="javascript:/i);
  });

  it("rejects a protocol-relative link that would navigate off-site", () => {
    const html = renderMarkdown("[x](//evil.example/path)");

    // The href must not survive at all: // and /\ are off-origin, unlike a
    // single-slash in-repo path.
    expect(html).not.toMatch(/href="\/\//);
    expect(html).not.toMatch(/href="\/\\/);
  });

  it("still allows a single-slash in-repo relative path", () => {
    const html = renderMarkdown("[x](/blueprint.md)");

    expect(html).toMatch(/href="\/blueprint\.md"/);
  });
});
