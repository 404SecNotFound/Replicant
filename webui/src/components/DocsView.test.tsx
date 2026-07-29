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

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DocsView } from "./DocsView";
import * as api from "@/lib/api";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, getDocs: vi.fn(), getDoc: vi.fn() };
});

const INDEX: api.DocsIndex = {
  available: true,
  pages: [
    { id: "fortigate-cef", title: "FortiGate CEF reference", available: true },
    { id: "paloalto-cef", title: "Palo Alto PAN-OS CEF reference", available: true },
  ],
};

beforeEach(() => {
  vi.mocked(api.getDocs).mockResolvedValue(INDEX);
  vi.mocked(api.getDoc).mockResolvedValue({
    id: "fortigate-cef",
    title: "FortiGate CEF reference",
    markdown: "# Golden lines\n\n| field | value |\n| --- | --- |\n| vendor | Fortinet |\n",
  });
});

describe("DocsView", () => {
  it("lists the reference pages", async () => {
    render(<DocsView />);

    expect(await screen.findByRole("button", { name: /FortiGate CEF reference/ })).toBeVisible();
    expect(screen.getByRole("button", { name: /Palo Alto/ })).toBeVisible();
  });

  it("renders markdown as real markup, not as source text", async () => {
    // The CEF reference tables are the reason this tab exists; showing raw pipe
    // characters would make the pages unreadable.
    render(<DocsView />);

    expect(await screen.findByRole("heading", { name: "Golden lines" })).toBeInTheDocument();
    expect(screen.getByRole("table")).toBeInTheDocument();
  });

  it("loads the page the operator clicks", async () => {
    render(<DocsView />);
    await screen.findByRole("button", { name: /Palo Alto/ });

    fireEvent.click(screen.getByRole("button", { name: /Palo Alto/ }));

    await waitFor(() => expect(api.getDoc).toHaveBeenCalledWith("paloalto-cef"));
  });

  it("explains itself when the docs are not in this install", async () => {
    // docs/ ships with the repository, not the wheel, so a non-editable install
    // has none. That is a fact to state, not a spinner to leave running.
    vi.mocked(api.getDocs).mockResolvedValue({ available: false, pages: [] });

    render(<DocsView />);

    expect(await screen.findByText(/editable install|git checkout/i)).toBeInTheDocument();
  });

  it("surfaces a load failure instead of showing a blank pane", async () => {
    vi.mocked(api.getDoc).mockRejectedValue(new Error("unknown document"));

    render(<DocsView />);

    expect(await screen.findByText(/unknown document/)).toBeInTheDocument();
  });
});
