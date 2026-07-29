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

import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { terminalWsUrl } from "@/lib/api";
import { readThemeColor, type Theme } from "@/lib/theme";

// The 16 ANSI slots the Rich menu actually paints with.
//
// xterm's defaults are tuned for a generic dark terminal and measured badly in
// both of ours: 11 of 16 fell below 4.5:1 on the light card, and 6 of 16 on the
// dark one, so the embedded menu was partly illegible even before light mode
// existed. These two sets are measured against the card each renders on.
//
// `black` is the one deliberate exception in the dark set (1.59:1). ANSI black is
// the background-adjacent slot by definition, used for fills and shadow rather
// than for text; forcing it to 4.5:1 would defeat what programs use it for.
const ANSI_LIGHT = {
  black: "#24211e",
  red: "#b8281e",
  green: "#2f6f1a",
  yellow: "#6f4802",
  blue: "#1d4ed8",
  magenta: "#86198f",
  cyan: "#0e6b78",
  white: "#4a443d",
  brightBlack: "#68615a",
  brightRed: "#c62f22",
  brightGreen: "#3a7f20",
  brightYellow: "#a04c03",
  brightBlue: "#2563c4",
  brightMagenta: "#9d28a8",
  brightCyan: "#12798a",
  brightWhite: "#24211e",
} as const;

const ANSI_DARK = {
  black: "#3b3a36",
  red: "#f0685e",
  green: "#93d066",
  yellow: "#f4b23e",
  blue: "#7aa7e9",
  magenta: "#c58ad0",
  cyan: "#5fc9d6",
  white: "#c9c6bd",
  brightBlack: "#8a847a",
  brightRed: "#ff8478",
  brightGreen: "#a8e07e",
  brightYellow: "#ffc65c",
  brightBlue: "#9cc0f5",
  brightMagenta: "#dba6e4",
  brightCyan: "#7fdfe9",
  brightWhite: "#f2f1ed",
} as const;

// xterm.js takes concrete colours, not CSS variables, so the palette has to be
// resolved at call time. The surface colours are read out of the stylesheet
// rather than restated here: the previous values were a hardcoded blue-slate
// (#0b1120) that matched neither theme, and in light mode would have been a
// black box on paper.
//
// `--card` rather than `--background`, because the terminal sits inside a card.
// The cursor stays on `--foreground`: amber is reserved for live emission signal
// and a text cursor is not that.
function terminalTheme(theme: Theme) {
  const dark = theme === "dark";
  return {
    background: readThemeColor("--card") ?? (dark ? "#161618" : "#fcfcfa"),
    foreground: readThemeColor("--foreground") ?? (dark ? "#f2f1ed" : "#24211e"),
    cursor: readThemeColor("--foreground") ?? (dark ? "#f2f1ed" : "#24211e"),
    cursorAccent: readThemeColor("--card") ?? (dark ? "#161618" : "#fcfcfa"),
    selectionBackground: readThemeColor("--elev") ?? (dark ? "#24242b" : "#e7e2d9"),
    selectionForeground: readThemeColor("--foreground") ?? (dark ? "#f2f1ed" : "#24211e"),
    ...(dark ? ANSI_DARK : ANSI_LIGHT),
  };
}

// Mounts an xterm.js terminal wired to the server PTY bridge, which runs the real
// `replicant menu`. Radix unmounts inactive tab content, so leaving the Terminal
// tab closes the socket and ends the menu process; returning starts a fresh one.
export function TerminalView({ theme }: { theme: Theme }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);

  // Recolour in place. Deliberately not a dependency of the mount effect below:
  // rebuilding the Terminal would tear down the websocket and kill the operator's
  // running menu process, so toggling the theme mid-session would lose their work.
  useEffect(() => {
    if (termRef.current) termRef.current.options.theme = terminalTheme(theme);
  }, [theme]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
      fontSize: 13,
      theme: terminalTheme(theme),
    });
    termRef.current = term;
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(container);
    fit.fit();

    const ws = new WebSocket(terminalWsUrl());

    const sendResize = () => {
      try {
        fit.fit();
      } catch {
        return;
      }
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ t: "r", cols: term.cols, rows: term.rows }));
      }
    };

    ws.onopen = () => sendResize();
    ws.onmessage = (event) => {
      if (typeof event.data === "string") term.write(event.data);
    };
    ws.onclose = () => term.write("\r\n\x1b[2m[terminal session closed]\x1b[0m\r\n");

    const dataSub = term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: "i", d: data }));
    });

    const observer = new ResizeObserver(() => sendResize());
    observer.observe(container);

    return () => {
      observer.disconnect();
      dataSub.dispose();
      ws.close();
      term.dispose();
      termRef.current = null;
    };
    // `theme` is read for the initial palette but deliberately not a dependency:
    // re-running this would tear down the websocket and kill the operator's menu
    // process. The effect above recolours the live terminal instead.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return <div ref={containerRef} className="h-full w-full" />;
}
