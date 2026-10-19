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

// Dissects one emitted line into the parts the wire view shows: an optional
// syslog prefix, the seven CEF header fields, and the extension key=value pairs.
// Every part carries its character span in the original line, so the view can
// light the matching bytes in the hex dump. Values are shown as emitted, escapes
// included: the point is to see exactly what went on the wire.

export interface Span {
  start: number;
  end: number;
}

export interface CefPart extends Span {
  key: string;
  value: string;
}

export interface CefDissection {
  /** Syslog header text before `CEF:`, if the line carries one. */
  prefix: (Span & { text: string; pri: number | null }) | null;
  header: CefPart[];
  extension: CefPart[];
}

export const HEADER_FIELDS = [
  "Version",
  "Device Vendor",
  "Device Product",
  "Device Version",
  "Signature ID",
  "Name",
  "Severity",
] as const;

const SEVERITY_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];
const FACILITY_NAMES = [
  "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
  "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
  "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
];

/** `<134>` as `local0.info`, or null when the number is outside the syslog range. */
export function describePri(pri: number): string | null {
  if (!Number.isInteger(pri) || pri < 0 || pri > 191) return null;
  return `${FACILITY_NAMES[pri >> 3]}.${SEVERITY_NAMES[pri & 7]}`;
}

function isKeyChar(ch: string): boolean {
  return /[A-Za-z0-9_.[\]]/.test(ch);
}

/** A delimiter counts only when the backslashes before it are even in number. */
function isEscaped(line: string, index: number): boolean {
  let slashes = 0;
  for (let i = index - 1; i >= 0 && line[i] === "\\"; i--) slashes++;
  return slashes % 2 === 1;
}

export function dissectCef(line: string): CefDissection | null {
  const at = line.indexOf("CEF:");
  if (at === -1) return null;

  let prefix: CefDissection["prefix"] = null;
  if (at > 0) {
    const text = line.slice(0, at);
    const priMatch = text.match(/^<(\d{1,3})>/);
    prefix = { start: 0, end: at, text, pri: priMatch ? Number(priMatch[1]) : null };
  }

  const header: CefPart[] = [];
  let cursor = at;
  for (let field = 0; field < HEADER_FIELDS.length; field++) {
    let end = cursor;
    while (end < line.length && !(line[end] === "|" && !isEscaped(line, end))) end++;
    // The version field starts after "CEF:"; every other field starts at the cursor.
    const valueStart = field === 0 ? cursor + 4 : cursor;
    header.push({ key: HEADER_FIELDS[field], value: line.slice(valueStart, end), start: valueStart, end });
    if (end >= line.length) return { prefix, header, extension: [] };
    cursor = end + 1;
  }

  // Extension: each unescaped "=" preceded by a key run that starts the line or
  // follows a space opens a pair; the value runs to the space before the next key.
  const opens: { key: string; keyStart: number; valueStart: number }[] = [];
  for (let i = cursor; i < line.length; i++) {
    if (line[i] !== "=" || isEscaped(line, i)) continue;
    let k = i;
    while (k > cursor && isKeyChar(line[k - 1])) k--;
    if (k === i) continue;
    if (k !== cursor && line[k - 1] !== " ") continue;
    opens.push({ key: line.slice(k, i), keyStart: k, valueStart: i + 1 });
  }
  const extension = opens.map((open, index) => {
    const next = opens[index + 1];
    const valueEnd = next ? next.keyStart - 1 : line.length;
    return {
      key: open.key,
      value: line.slice(open.valueStart, Math.max(open.valueStart, valueEnd)),
      start: open.keyStart,
      end: Math.max(open.valueStart, valueEnd),
    };
  });
  return { prefix, header, extension };
}

/** Convert a character span to the UTF-8 byte span the hex dump draws. */
export function byteSpan(line: string, span: Span): Span {
  const encoder = new TextEncoder();
  const start = encoder.encode(line.slice(0, span.start)).length;
  return { start, end: start + encoder.encode(line.slice(span.start, span.end)).length };
}

export interface HexRow {
  offset: number;
  bytes: number[];
}

export function hexRows(line: string, width = 16): HexRow[] {
  const bytes = new TextEncoder().encode(line);
  const rows: HexRow[] = [];
  for (let offset = 0; offset < bytes.length; offset += width) {
    rows.push({ offset, bytes: Array.from(bytes.slice(offset, offset + width)) });
  }
  return rows;
}

export function extensionValue(dissection: CefDissection | null, key: string): string | null {
  return dissection?.extension.find((part) => part.key === key)?.value ?? null;
}

/**
 * The event's own time as a UTC clock. PAN-OS writes `rt` in epoch seconds, Check
 * Point in milliseconds, and FortiGate carries `FTNTFGTeventtime` instead. Null
 * when none is present or the value is not a plain epoch number.
 */
export function eventClock(dissection: CefDissection | null): string | null {
  const raw = extensionValue(dissection, "rt") ?? extensionValue(dissection, "FTNTFGTeventtime");
  if (!raw || !/^\d{10}(\d{3})?$/.test(raw)) return null;
  const ms = raw.length === 13 ? Number(raw) : Number(raw) * 1000;
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? null : date.toISOString().slice(11, 19);
}
