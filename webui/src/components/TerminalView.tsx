import { useEffect, useRef } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { terminalWsUrl } from "@/lib/api";

// Mounts an xterm.js terminal wired to the server PTY bridge, which runs the real
// `replicant menu`. Radix unmounts inactive tab content, so leaving the Terminal
// tab closes the socket and ends the menu process; returning starts a fresh one.
export function TerminalView() {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
      fontSize: 13,
      theme: { background: "#0b1120", foreground: "#e2e8f0", cursor: "#34d399" },
    });
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
    };
  }, []);

  return <div ref={containerRef} className="h-full w-full" />;
}
