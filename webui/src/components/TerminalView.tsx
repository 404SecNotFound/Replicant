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
import { readThemeColor } from "@/lib/theme";

// The 16 ANSI slots the Rich menu actually paints with.
//
// xterm's defaults are tuned for a generic dark terminal and measured badly
// here: 6 of 16 fell below 4.5:1 on the card, so the embedded menu was partly
// illegible. This set is measured against the card it renders on.
//
// `black` is the one deliberate exception (1.59:1). ANSI black is the
// background-adjacent slot by definition, used for fills and shadow rather
// than for text; forcing it to 4.5:1 would defeat what programs use it for.
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
// rather than restated here, so a token move cannot leave the terminal behind.
//
// `--card` rather than `--background`, because the terminal sits inside a card.
// The cursor stays on `--foreground`: signal orange is reserved for live
// emission and a text cursor is not that. The fallbacks are the same Factory
// hexes the tokens encode, for the one case where the stylesheet is unreadable.
function terminalTheme() {
  return {
    background: readThemeColor("--card") ?? "#1d1a18",
    foreground: readThemeColor("--foreground") ?? "#eeeeee",
    cursor: readThemeColor("--foreground") ?? "#eeeeee",
    cursorAccent: readThemeColor("--card") ?? "#1d1a18",
    selectionBackground: readThemeColor("--accent") ?? "#4d4947",
    selectionForeground: readThemeColor("--foreground") ?? "#eeeeee",
    ...ANSI_DARK,
  };
}

// Mounts an xterm.js terminal wired to the server PTY bridge, which runs the real
// `replicant menu`. Radix unmounts inactive tab content, so leaving the Terminal
// tab closes the socket and ends the menu process; returning starts a fresh one.
export function TerminalView() {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
      fontSize: 13,
      theme: terminalTheme(),
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
  }, []);

  return <div ref={containerRef} className="h-full w-full" />;
}
