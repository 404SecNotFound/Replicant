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

import { useEffect, useMemo, useState } from "react";
import { Marked } from "marked";
import { cn } from "@/lib/utils";
import { getDoc, getDocs, type DocsIndex } from "@/lib/api";

// Raw HTML in the source is rendered as visible text, never as markup.
//
// The previous reasoning here was that repository files are trusted because
// anyone who can change docs/*.md can change the application anyway. A 2026-08
// review disagreed and was right: documentation is reviewed under a different
// bar than executable code, and this pipeline gave it the Replicant origin and
// the ambient session cookie. `<img src=x onerror=...>` survived `marked.parse`
// unchanged and would have run.
//
// Escaping the whole source instead would break the code fences the CEF
// references are made of. Overriding the `html` token is narrower: markdown
// constructs render normally, and only raw HTML degrades to text. None of the
// five served documents contains a raw tag, so nothing renders differently.
//
// This is defence in depth alongside the Content-Security-Policy the server
// sends; neither is relied on alone.
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// A dedicated instance, not `marked.use(...)`: the global would apply this
// override to any other caller in the bundle, and a partial `renderer` passed as
// a parse option replaces the whole renderer rather than merging with it, which
// leaves `paragraph` undefined.
const docsMarked = new Marked({
  renderer: {
    // marked passes a token; older shapes pass the raw string.
    html(token: unknown) {
      return escapeHtml(
        typeof token === "string" ? token : String((token as { raw: string }).raw),
      );
    },
    // marked does not filter link protocols, so `[click](javascript:...)` became
    // a working `href`. Neutralising raw HTML alone would have left that open.
    link(token: { href?: string; title?: string | null; text?: string }) {
      const href = String(token.href ?? "");
      // A single leading slash is an in-repo relative path and is allowed; a
      // double one (`//host`, or `/\host`) is a protocol-relative URL that
      // navigates off-site, so the `\/` alternative must not match it. Without
      // the negative lookahead, `[x](//evil.example)` rendered a working
      // off-origin link from the Replicant page.
      const safe = /^(https?:|mailto:|#|\/(?![/\\])|\.)/i.test(href.trim());
      const text = escapeHtml(String(token.text ?? ""));
      if (!safe) return text;
      const title = token.title ? ` title="${escapeHtml(token.title)}"` : "";
      return `<a href="${escapeHtml(href)}"${title}>${text}</a>`;
    },
  },
});

export function renderMarkdown(markdown: string): string {
  return docsMarked.parse(markdown, { async: false }) as string;
}

export function DocsView() {
  const [index, setIndex] = useState<DocsIndex | null>(null);
  const [current, setCurrent] = useState<string | null>(null);
  const [markdown, setMarkdown] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getDocs()
      .then((data) => {
        setIndex(data);
        const first = data.pages.find((page) => page.available);
        if (first) setCurrent(first.id);
      })
      .catch((err) => setError((err as Error).message));
  }, []);

  useEffect(() => {
    if (!current) return;
    let cancelled = false;
    setError(null);
    getDoc(current)
      .then((doc) => {
        if (!cancelled) setMarkdown(doc.markdown);
      })
      .catch((err) => {
        if (!cancelled) {
          setMarkdown("");
          setError((err as Error).message);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [current]);

  const html = useMemo(() => (markdown ? renderMarkdown(markdown) : ""), [markdown]);

  if (index && !index.available) {
    return (
      <div className="grid h-full place-items-center p-8 text-center">
        <p className="max-w-md text-sm text-muted-foreground">
          The reference documents are not present in this install. They ship with the repository
          rather than the package, so they are available from a git checkout or an editable
          install (<code className="font-mono">pip install -e</code>).
        </p>
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 w-full flex-col lg:grid lg:grid-cols-[248px_minmax(0,1fr)]">
      {/* The document picker is a sidebar at lg and a horizontal strip below it.
          Four entries scroll sideways in less space than they stack vertically,
          and stacking would push the document itself off the first screen. */}
      <nav
        aria-label="Reference documents"
        className="flex flex-none gap-px overflow-x-auto scroll-thin border-b p-3 lg:flex-col lg:overflow-x-visible lg:overflow-y-auto lg:border-b-0 lg:border-r"
      >
        <span className="u-label mb-2 hidden px-2 lg:block">Reference</span>
        {(index?.pages ?? []).map((page) => (
          <button
            key={page.id}
            onClick={() => setCurrent(page.id)}
            disabled={!page.available}
            aria-current={page.id === current ? "true" : undefined}
            className={cn(
              "whitespace-nowrap rounded-md px-2.5 py-2 text-left text-body transition-colors hover:bg-secondary disabled:opacity-40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              page.id === current && "bg-secondary",
            )}
          >
            {page.title}
          </button>
        ))}
      </nav>

      <article className="min-h-0 flex-1 overflow-y-auto scroll-thin px-4 py-5 sm:px-8 sm:py-6">
        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 p-2.5 text-body text-destructive">
            {error}
          </div>
        )}
        {!error && !html && <p className="text-sm text-muted-foreground">Loading…</p>}
        {html && (
          <div className="doc-prose max-w-[880px]" dangerouslySetInnerHTML={{ __html: html }} />
        )}
      </article>
    </div>
  );
}
