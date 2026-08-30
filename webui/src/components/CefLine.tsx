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

// One log line with the emphasis the design system allows: brightness only,
// weight 400, no color. Any syslog prefix reads muted, the CEF header (the
// first seven pipe-delimited fields) reads in the text color, and the
// extension settles into the tertiary gray.

export function CefLine({ line, className }: { line: string; className?: string }) {
  const at = line.indexOf("CEF:");
  if (at === -1) return <div className={className}>{line}</div>;

  // The 7th unescaped pipe closes the header; escaped pipes (\|) stay inside.
  let end = -1;
  for (let i = at, seen = 0; i < line.length; i++) {
    if (line[i] === "|" && line[i - 1] !== "\\" && ++seen === 7) {
      end = i + 1;
      break;
    }
  }
  if (end === -1) end = line.length;

  return (
    <div className={className}>
      {at > 0 && <span className="text-text-4">{line.slice(0, at)}</span>}
      <span className="text-foreground">{line.slice(at, end)}</span>
      {line.slice(end)}
    </div>
  );
}
