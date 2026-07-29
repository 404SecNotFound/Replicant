#!/usr/bin/env python3
# Copyright 2026 Imran Hafeez (RZA)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Regenerate the web UI screenshots in docs/images/ at the size the README uses.

The README's screenshots go stale every time the UI changes, and the previous
regeneration was done ad hoc and not kept, so it had to be reinvented. This is
that method, written down.

Drives headless Chrome over the DevTools Protocol rather than a screenshot tool,
because two of the three shots need interaction: one needs the Docs tab open, one
needs a run actually emitting. Captures at 1440x900 at scale 1, matching the
images already committed.

Usage:

    replicant web --no-browser                       # in another shell
    python scripts/capture-webui-screenshots.py "http://127.0.0.1:9787/?token=..."

The run shot starts a real run with no collector and no output file, so it emits
to the browser stream and writes nothing anywhere.

Requires Google Chrome and the ``websockets`` package (already a transitive
dependency of ``uvicorn[standard]``, so a ``.[web]`` install has it).
"""

from __future__ import annotations

import asyncio
import base64
import json
import subprocess
import sys
import urllib.request
from pathlib import Path

import websockets

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
DEBUG_PORT = 9222
WIDTH, HEIGHT = 1440, 900
OUT_DIR = Path(__file__).resolve().parents[1] / "docs" / "images"


class Chrome:
    """A very small CDP client: enough to navigate, poke the page, and capture."""

    def __init__(self, socket: websockets.ClientConnection) -> None:
        self.socket = socket
        self.next_id = 0

    async def send(self, method: str, **params: object) -> dict:
        self.next_id += 1
        message_id = self.next_id
        await self.socket.send(json.dumps({"id": message_id, "method": method, "params": params}))
        while True:
            payload = json.loads(await self.socket.recv())
            if payload.get("id") == message_id:
                if "error" in payload:
                    raise RuntimeError(f"{method}: {payload['error']}")
                return payload.get("result", {})

    async def evaluate(self, expression: str) -> object:
        result = await self.send(
            "Runtime.evaluate", expression=expression, returnByValue=True, awaitPromise=True
        )
        # A JS exception is reported here, not as a protocol error. Without this
        # check a broken script returns undefined, which reads downstream as "the
        # element was not there" and sends you looking at the page instead of at
        # the script.
        if "exceptionDetails" in result:
            detail = result["exceptionDetails"]
            text = detail.get("exception", {}).get("description") or detail.get("text")
            raise RuntimeError(f"JS failed: {text}\n  expression: {expression}")
        return result.get("result", {}).get("value")

    async def wait_for(self, expression: str, *, what: str, timeout: float = 20.0) -> None:
        """Poll a JS predicate. Fails loudly rather than capturing a half-rendered page."""
        for _ in range(int(timeout * 10)):
            if await self.evaluate(expression):
                return
            await asyncio.sleep(0.1)
        raise TimeoutError(f"timed out waiting for {what}")

    async def click(self, selector_js: str) -> None:
        # Built with a single f-string. Splitting it across an f-string and a plain
        # adjacent literal silently leaves the plain half's `}}` unescaped, which
        # produces a syntax error rather than the intended arrow function.
        clicked = await self.evaluate(
            f"(() => {{ const el = {selector_js}; if (!el) return false;"
            f" el.click(); return true; }})()"
        )
        if not clicked:
            raise RuntimeError(f"nothing to click for {selector_js}")

    async def type_line(self, text: str) -> None:
        """Type into the focused element and press Enter.

        The terminal tab is a real PTY, so it only advances if something actually
        answers its prompts. Without this the capture is the first question and an
        otherwise empty screen.
        """
        await self.send("Input.insertText", text=text)
        for event_type in ("keyDown", "keyUp"):
            await self.send(
                "Input.dispatchKeyEvent",
                type=event_type,
                key="Enter",
                code="Enter",
                windowsVirtualKeyCode=13,
                nativeVirtualKeyCode=13,
                text="\r",
            )

    async def capture(self, name: str) -> None:
        result = await self.send("Page.captureScreenshot", format="png")
        path = OUT_DIR / name
        path.write_bytes(base64.b64decode(result["data"]))
        print(f"  wrote {path.relative_to(OUT_DIR.parents[1])}")


def button_by_text(text: str) -> str:
    return (
        "[...document.querySelectorAll('button')]"
        f".find(b => b.textContent.trim() === {json.dumps(text)})"
    )


async def capture_all(url: str) -> None:
    chrome = subprocess.Popen(  # noqa: S603 - fixed path, no shell
        [
            CHROME,
            "--headless=new",
            f"--remote-debugging-port={DEBUG_PORT}",
            f"--window-size={WIDTH},{HEIGHT}",
            "--force-device-scale-factor=1",
            "--hide-scrollbars",
            "--disable-gpu",
            "--no-first-run",
            "--user-data-dir=/tmp/replicant-shots",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        endpoint = ""
        for _ in range(100):
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{DEBUG_PORT}/json") as response:
                    targets = json.load(response)
                page = next((t for t in targets if t["type"] == "page"), None)
                if page:
                    endpoint = page["webSocketDebuggerUrl"]
                    break
            except OSError:
                pass
            await asyncio.sleep(0.1)
        if not endpoint:
            raise RuntimeError("Chrome did not expose a debugging endpoint")

        async with websockets.connect(endpoint, max_size=64 * 1024 * 1024) as socket:
            page = Chrome(socket)
            await page.send("Page.enable")
            await page.send(
                "Emulation.setDeviceMetricsOverride",
                width=WIDTH,
                height=HEIGHT,
                deviceScaleFactor=1,
                mobile=False,
            )
            await page.send("Page.navigate", url=url)
            await page.wait_for(
                "!!document.querySelector('input[aria-label=\"Filter techniques\"]')",
                what="the catalog rail",
            )
            # The signal diagram animates in; let it settle before capturing.
            await asyncio.sleep(1.5)
            print("emitter view")
            await page.capture("webui-emitter.png")

            print("docs tab")
            await page.click(button_by_text("Docs"))
            await page.wait_for("!!document.querySelector('.doc-prose h1')", what="a rendered doc")
            await asyncio.sleep(0.5)
            await page.capture("webui-docs.png")

            print("live run")
            await page.click(button_by_text("Emitter"))
            await page.wait_for(
                "!!document.querySelector('main')", what="the emitter view to come back"
            )
            # The shot needs a plan big enough to fill the waveform and the progress
            # bar. REP-001's default is 243 events and is over in well under a
            # second; REP-004's is 108000. Filtering to it also puts the rail in a
            # more useful state for the shot, since REP-004 is mapped to two tactics
            # and so appears under both.
            #
            # React tracks the input's value on the DOM node, so assigning .value
            # directly is silently reverted on the next render. Going through the
            # prototype setter and then dispatching `input` is what makes React see
            # the change.
            await page.evaluate(
                "(() => { const box ="
                " document.querySelector('input[aria-label=\"Filter techniques\"]');"
                " const setter = Object.getOwnPropertyDescriptor("
                "   window.HTMLInputElement.prototype, 'value').set;"
                " setter.call(box, 'REP-004');"
                " box.dispatchEvent(new Event('input', { bubbles: true })); })()"
            )
            await page.wait_for(
                "[...document.querySelectorAll('button')]"
                ".some(b => b.textContent.includes('DNS tunneling'))",
                what="REP-004 in the filtered rail",
            )
            await page.click(
                "[...document.querySelectorAll('button')]"
                ".find(b => b.textContent.includes('DNS tunneling'))"
            )
            await asyncio.sleep(0.8)
            # No collector and no output file: the run emits to the browser stream
            # and writes nothing to disk.
            await page.click(button_by_text("Start run"))
            # Capture just after the plan drains. REP-004's default is 108000 events
            # and the useful window is narrow: at 2.2s the readout still showed
            # single digits, and a looser "wait until the rate is high" predicate
            # matched the intensity-preset numbers elsewhere on the page and fired
            # before the run even started. The settled frame carries more anyway --
            # the full waveform, the delivered rate against the cap, and the
            # manifest panel -- so it is the one the README uses.
            await asyncio.sleep(4.0)
            await page.evaluate(
                "document.querySelector('main').scrollTop = "
                "document.querySelector('main').scrollHeight * 0.55"
            )
            await asyncio.sleep(0.4)
            await page.capture("webui-run.png")
            await page.click(button_by_text("Stop"))

            print("terminal tab")
            await page.click(button_by_text("Terminal"))
            await page.wait_for(
                "!!document.querySelector('.xterm-screen')", what="the terminal to attach"
            )
            await asyncio.sleep(2.5)
            # Focus xterm's hidden textarea, then decline the collector prompt so the
            # shot shows the main menu and the technique table rather than the first
            # question on an empty screen.
            await page.evaluate("document.querySelector('.xterm-helper-textarea').focus()")
            await page.type_line("n")
            await asyncio.sleep(2.5)
            await page.capture("webui-terminal.png")
    finally:
        chrome.terminate()
        chrome.wait(timeout=10)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    if not Path(CHROME).exists():
        print(f"Google Chrome not found at {CHROME}", file=sys.stderr)
        return 1
    asyncio.run(capture_all(sys.argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
