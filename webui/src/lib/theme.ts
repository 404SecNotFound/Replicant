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

// Palette resolution for the one consumer that cannot read CSS variables:
// xterm.js in TerminalView.
//
// The UI is dark-only by design (the Factory system has no light variant), so
// the theme toggle, the stored preference, and the pre-paint script that this
// module used to carry are gone. What remains is reading a token off the
// stylesheet and converting it to a concrete color.

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

/** A palette token resolved to a concrete colour. */
export function readThemeColor(
  name: string,
  root: HTMLElement = document.documentElement,
): string | null {
  const raw = getComputedStyle(root).getPropertyValue(name);
  return raw ? hslTripletToHex(raw) : null;
}
