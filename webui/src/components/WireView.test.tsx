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

import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { WireView } from "./WireView";

const line = (n: number, dst = "203.0.113.47") =>
  `CEF:0|Fortinet|Fortigate|v7.4.3|00013|traffic:forward accept|3|FTNTFGTeventtime=${1752586800 + n} src=10.20.30.139 dst=${dst} dpt=443 act=accept`;

function renderWire(lines: string[], heldFields = ["src", "dst", "dpt"]) {
  return render(<WireView lines={lines} running={false} revision={lines.length}
    heldFields={heldFields} bufferLimit={800} profile="fortigate" />);
}

/** The hex cells currently lit, read back as text. */
function litBytes(): string {
  const bytes = screen.getByRole("group", { name: "Bytes" });
  return Array.from(bytes.querySelectorAll(".text-signal"))
    .filter((el) => el.textContent?.length === 1)
    .map((el) => el.textContent)
    .join("");
}

describe("WireView", () => {
  it("lists every buffered event with its parsed time, endpoints and summary", () => {
    renderWire([line(0), line(60, "198.51.100.12")]);
    const stream = screen.getByLabelText("Event stream");
    expect(within(stream).getByText("203.0.113.47:443")).toBeInTheDocument();
    expect(within(stream).getByText("198.51.100.12:443")).toBeInTheDocument();
    expect(within(stream).getByText("13:41:00")).toBeInTheDocument();
    // The action is already in the CEF name, so it is not printed twice.
    expect(within(stream).getAllByText("traffic:forward accept")).toHaveLength(2);
  });

  it("lights the bytes of the first held field by default and of any field clicked", () => {
    renderWire([line(0)]);
    expect(litBytes()).toBe("src=10.20.30.139");
    fireEvent.click(screen.getByRole("button", { name: /^dpt\s*443/ }));
    expect(litBytes()).toBe("dpt=443");
    fireEvent.click(screen.getByRole("button", { name: /^Device Vendor\s*Fortinet/ }));
    expect(litBytes()).toBe("Fortinet");
  });

  it("marks held fields in the dissection", () => {
    renderWire([line(0)], ["dpt"]);
    expect(screen.getByRole("button", { name: /^dpt\s*443\s*held/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^src\s*10\.20\.30\.139$/ })).toBeInTheDocument();
  });

  it("follows the live end until a row is pinned, and keeps the pinned event as the buffer moves", () => {
    const first = [line(0), line(60, "198.51.100.12")];
    const { rerender } = renderWire(first);
    expect(screen.getByText(/#2 ·/)).toBeInTheDocument();
    fireEvent.click(screen.getByText("203.0.113.47:443"));
    expect(screen.getByText(/#1 ·/)).toBeInTheDocument();

    // The oldest line falls out of a bounded buffer: the pin follows the event, not the index.
    const moved = [line(60, "198.51.100.12"), line(120, "192.0.2.77"), line(0)];
    rerender(<WireView lines={moved} running revision={3} heldFields={[]} bufferLimit={800} profile="fortigate" />);
    expect(screen.getByText(/#3 ·/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Follow live" }));
    expect(screen.getByText(/#3 ·/)).toBeInTheDocument();
  });

  it("names the stream's own profile and says when nothing has arrived", () => {
    renderWire([line(0)]);
    expect(screen.getByText("Wire · fortigate")).toBeInTheDocument();
    render(<WireView lines={[]} running revision={0} heldFields={[]} bufferLimit={800} profile="fortigate" />);
    expect(screen.getByText("Waiting for the first event…")).toBeInTheDocument();
  });
});
