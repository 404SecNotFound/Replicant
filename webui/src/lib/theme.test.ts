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

// `?raw` gives the literal bytes of the shipped file, transformed by nothing. It
// avoids pulling @types/node in just so a test can call readFileSync.
import indexHtml from "../../index.html?raw";
import { describe, expect, it } from "vitest";
import {
  THEME_STORAGE_KEY,
  applyTheme,
  hslTripletToHex,
  readStoredTheme,
  resolveTheme,
  storeTheme,
} from "./theme";

describe("resolveTheme", () => {
  it("uses an explicit stored choice over the operating system", () => {
    expect(resolveTheme("light", true)).toBe("light");
    expect(resolveTheme("dark", false)).toBe("dark");
  });

  it("follows the operating system when nothing is stored", () => {
    expect(resolveTheme(null, true)).toBe("dark");
    expect(resolveTheme(null, false)).toBe("light");
  });

  it("treats an unrecognised stored value as absent", () => {
    // Whatever wrote "purple" was not this app. Falling through to the OS beats
    // painting an undefined theme.
    expect(resolveTheme("purple", true)).toBe("dark");
    expect(resolveTheme("", false)).toBe("light");
  });
});

describe("storage", () => {
  it("round-trips a choice", () => {
    storeTheme("light");
    expect(readStoredTheme()).toBe("light");
    storeTheme("dark");
    expect(readStoredTheme()).toBe("dark");
  });

  it("survives storage being unavailable", () => {
    // Safari private browsing and a hardened browser profile both throw on
    // access rather than returning null. A theme preference is not worth
    // taking the whole UI down for.
    const original = Object.getOwnPropertyDescriptor(window, "localStorage");
    Object.defineProperty(window, "localStorage", {
      configurable: true,
      get() {
        throw new DOMException("denied");
      },
    });

    expect(() => readStoredTheme()).not.toThrow();
    expect(readStoredTheme()).toBeNull();
    expect(() => storeTheme("dark")).not.toThrow();

    if (original) Object.defineProperty(window, "localStorage", original);
  });
});

describe("applyTheme", () => {
  it("sets the class the CSS keys off and the colour-scheme native controls key off", () => {
    const root = document.createElement("html");

    applyTheme("dark", root);
    expect(root.classList.contains("dark")).toBe(true);
    expect(root.style.colorScheme).toBe("dark");

    applyTheme("light", root);
    expect(root.classList.contains("dark")).toBe(false);
    expect(root.style.colorScheme).toBe("light");
  });
});

describe("hslTripletToHex", () => {
  it("converts the palette tokens xterm cannot read as CSS variables", () => {
    // Values taken from index.css. The dark card is what the terminal pane sits
    // on, and the light signal is the darkened amber that holds AA on paper.
    expect(hslTripletToHex("240 6% 9%")).toBe("#161618");
    expect(hslTripletToHex("28 96% 32%")).toBe("#a04c03");
    expect(hslTripletToHex("48 15% 94%")).toBe("#f2f1ed");
  });

  it("handles the achromatic and boundary cases", () => {
    expect(hslTripletToHex("0 0% 0%")).toBe("#000000");
    expect(hslTripletToHex("0 0% 100%")).toBe("#ffffff");
    expect(hslTripletToHex("360 100% 50%")).toBe("#ff0000");
    // A fractional lightness is used by --card in the light theme.
    expect(hslTripletToHex("40 33% 98.5%")).toBe("#fcfcfa");
  });

  it("returns null rather than a wrong colour when the value is not a triplet", () => {
    // A caller that gets null can fall back; one that gets "#000000" cannot tell
    // the difference between black and a missing variable.
    expect(hslTripletToHex("")).toBeNull();
    expect(hslTripletToHex("rebeccapurple")).toBeNull();
    expect(hslTripletToHex("#f4b23e")).toBeNull();
  });
});

// The pre-paint script in index.html cannot import this module: it has to run
// before the bundle loads, or the page paints dark and then flips. So the rule
// exists twice. This is the guard that they agree, because nothing else would
// notice them drifting apart.
describe("the pre-paint script in index.html", () => {
  const source = indexHtml.match(/<script>([\s\S]*?)<\/script>/)?.[1];

  function runPrePaint(stored: string | null, prefersDark: boolean): string {
    if (!source) throw new Error("no inline script found in index.html");
    const root = document.createElement("html");
    const fakeStorage = {
      getItem: () => {
        if (stored === undefined) throw new DOMException("denied");
        return stored;
      },
    };
    const runner = new Function("localStorage", "matchMedia", "document", source);
    runner(
      fakeStorage,
      (query: string) => ({ matches: query.includes("dark") && prefersDark }),
      { documentElement: root },
    );
    return root.classList.contains("dark") ? "dark" : "light";
  }

  it("exists, because without it the page flashes the wrong theme", () => {
    expect(source).toBeTruthy();
  });

  it("reads the same storage key the app writes", () => {
    expect(source).toContain(THEME_STORAGE_KEY);
  });

  it.each([
    ["light", true],
    ["dark", false],
    [null, true],
    [null, false],
    ["purple", true],
    ["purple", false],
  ] as const)("agrees with resolveTheme for stored=%s prefersDark=%s", (stored, prefersDark) => {
    expect(runPrePaint(stored, prefersDark)).toBe(resolveTheme(stored, prefersDark));
  });

  it("also sets colour-scheme, so native scrollbars match from the first paint", () => {
    expect(source).toContain("colorScheme");
  });
});
