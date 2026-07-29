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
import { marked } from "marked";
import { cn } from "@/lib/utils";
import { getDoc, getDocs, type DocsIndex } from "@/lib/api";

// The markdown is server-side content from a fixed allowlist of files inside this
// repository. Nothing an operator types reaches it, so it is rendered directly
// rather than routed through a sanitizer: anyone who can change docs/*.md can
// already change the application itself.
function renderMarkdown(markdown: string): string {
  return marked.parse(markdown, { async: false }) as string;
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
    <div className="grid h-full min-h-0 grid-cols-[248px_minmax(0,1fr)]">
      <nav aria-label="Reference documents" className="flex flex-col gap-px overflow-y-auto scroll-thin border-r p-3">
        <span className="u-label mb-2 px-2">Reference</span>
        {(index?.pages ?? []).map((page) => (
          <button
            key={page.id}
            onClick={() => setCurrent(page.id)}
            disabled={!page.available}
            aria-current={page.id === current ? "true" : undefined}
            className={cn(
              "rounded-md px-2.5 py-2 text-left text-[12.5px] transition-colors hover:bg-secondary disabled:opacity-40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              page.id === current && "bg-secondary font-medium",
            )}
          >
            {page.title}
          </button>
        ))}
      </nav>

      <article className="min-h-0 overflow-y-auto scroll-thin px-8 py-6">
        {error && (
          <div className="rounded-md border border-destructive/40 bg-destructive/10 p-2.5 text-[12px] text-destructive">
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
