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

// Theme resolution, kept out of App.tsx so the rule is unit-testable on its own.
//
// The same rule is written a second time as an inline script in index.html,
// because it has to run before the bundle loads or the page paints dark and then
// flips to light in front of the operator. `theme.test.ts` extracts that script
// and asserts it agrees with `resolveTheme` for every input, so the duplication
// cannot drift silently.

export type Theme = "light" | "dark";

export const THEME_STORAGE_KEY = "replicant.theme";

const DARK_QUERY = "(prefers-color-scheme: dark)";

function isTheme(value: unknown): value is Theme {
  return value === "light" || value === "dark";
}

/**
 * Decide which theme to paint. An explicit stored choice wins; with nothing
 * stored, follow the operating system. Anything unrecognised in storage is
 * treated as absent rather than trusted.
 */
export function resolveTheme(stored: string | null, prefersDark: boolean): Theme {
  if (isTheme(stored)) return stored;
  return prefersDark ? "dark" : "light";
}

/**
 * The operator's stored choice, or null.
 *
 * Storage access throws rather than returning null in Safari private browsing
 * and in hardened browser profiles. A theme preference is not worth failing the
 * whole UI over, so the failure degrades to "no preference".
 */
export function readStoredTheme(): string | null {
  try {
    return window.localStorage.getItem(THEME_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function storeTheme(theme: Theme): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Same reasoning as readStoredTheme: the choice just does not persist.
  }
}

/**
 * Whether the operator has made an explicit choice.
 *
 * This is what separates "following the OS" from "frozen at whatever the OS said
 * the first time". Only a deliberate toggle is stored, so until one happens the
 * app keeps tracking the system setting.
 */
export function hasStoredTheme(): boolean {
  return isTheme(readStoredTheme());
}

/** The dark-mode media query, or null where matchMedia is unavailable. */
export function darkModeMedia(): MediaQueryList | null {
  return typeof window.matchMedia === "function" ? window.matchMedia(DARK_QUERY) : null;
}

export function systemPrefersDark(): boolean {
  return darkModeMedia()?.matches ?? false;
}

/** The theme to paint on this load. */
export function initialTheme(): Theme {
  return resolveTheme(readStoredTheme(), systemPrefersDark());
}

/**
 * Put the theme on the document.
 *
 * Two separate things: the `dark` class is what the Tailwind/CSS variables key
 * off, and `color-scheme` is what the browser keys off for native scrollbars,
 * form controls and the canvas behind the page. Setting only the class leaves
 * scrollbars in the previous theme.
 */
export function applyTheme(theme: Theme, root: HTMLElement = document.documentElement): void {
  root.classList.toggle("dark", theme === "dark");
  root.style.colorScheme = theme;
}

/**
 * Convert an `H S% L%` custom-property value to `#rrggbb`.
 *
 * The palette is stored as bare HSL triplets so Tailwind can compose them with
 * an alpha (`hsl(var(--signal) / 0.3)`). Anything that cannot take a CSS
 * variable, xterm.js being the one case here, needs a concrete colour instead.
 * Reading it back out of the stylesheet keeps the palette single-sourced rather
 * than restated in TypeScript, where it would drift the first time a token moved.
 */
export function hslTripletToHex(triplet: string): string | null {
  const match = triplet.trim().match(/^([\d.]+)\s+([\d.]+)%\s+([\d.]+)%$/);
  if (!match) return null;

  const hue = Number(match[1]);
  const saturation = Number(match[2]) / 100;
  const lightness = Number(match[3]) / 100;

  const chroma = (1 - Math.abs(2 * lightness - 1)) * saturation;
  const sector = (((hue % 360) + 360) % 360) / 60;
  const second = chroma * (1 - Math.abs((sector % 2) - 1));
  const [r, g, b] = (
    [
      [chroma, second, 0],
      [second, chroma, 0],
      [0, chroma, second],
      [0, second, chroma],
      [second, 0, chroma],
      [chroma, 0, second],
    ] as const
  )[Math.floor(sector) % 6];

  const offset = lightness - chroma / 2;
  const channel = (value: number) =>
    Math.round(Math.min(1, Math.max(0, value + offset)) * 255)
      .toString(16)
      .padStart(2, "0");

  return `#${channel(r)}${channel(g)}${channel(b)}`;
}

/** A palette token resolved to a concrete colour for the current theme. */
export function readThemeColor(
  name: string,
  root: HTMLElement = document.documentElement,
): string | null {
  const raw = getComputedStyle(root).getPropertyValue(name);
  return raw ? hslTripletToHex(raw) : null;
}
