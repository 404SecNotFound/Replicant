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

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      // The type scale.
      //
      // Before this there were ELEVEN hardcoded sizes across 84 call sites
      // (9, 9.5, 10.5, 11, 11.5, 12, 12.5, 13, 14, 23, 25) and no scale in the
      // design doc at all. That is not a scale, it is eleven separate decisions
      // made one component at a time, each locally reasonable and never compared.
      // Measured on the rendered page: 58 of 104 text elements sat below 12px and
      // only 3 reached the 16px browser default.
      //
      // The distinction that matters is READ versus SCAN. Prose is read in
      // sentences and needs size; tabular and monospace data is scanned, and
      // density genuinely helps there. So `data` and `mono` stay tight while
      // `body` and `lede` grow, and nothing is below 11px any more.
      fontSize: {
        micro: ["11px", { lineHeight: "1.45" }],   // was 9 / 9.5, diagram captions
        label: ["12px", { lineHeight: "1.5" }],    // was 10 / 10.5, section + nav labels
        data: ["12.5px", { lineHeight: "1.55" }],  // scanned values, tags, chips
        body: ["14px", { lineHeight: "1.6" }],     // was 13, prose you actually read
        lede: ["15px", { lineHeight: "1.6" }],     // the technique objective
        title: ["24px", { lineHeight: "1.25" }],
      },
      colors: {
        border: "hsl(var(--border))",
        input: "hsl(var(--input))",
        ring: "hsl(var(--ring))",
        background: "hsl(var(--background))",
        foreground: "hsl(var(--foreground))",
        primary: {
          DEFAULT: "hsl(var(--primary))",
          foreground: "hsl(var(--primary-foreground))",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary))",
          foreground: "hsl(var(--secondary-foreground))",
        },
        muted: {
          DEFAULT: "hsl(var(--muted))",
          foreground: "hsl(var(--muted-foreground))",
        },
        accent: {
          DEFAULT: "hsl(var(--accent))",
          foreground: "hsl(var(--accent-foreground))",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive))",
          foreground: "hsl(var(--destructive-foreground))",
        },
        card: {
          DEFAULT: "hsl(var(--card))",
          foreground: "hsl(var(--card-foreground))",
        },
        signal: {
          DEFAULT: "hsl(var(--signal))",
          foreground: "hsl(var(--signal-foreground))",
        },
        // Positive live data (the a0ca92 green). Same rule as signal: never on
        // buttons, navigation, or headings.
        metric: "hsl(var(--metric))",
        elev: "hsl(var(--elev))",
        // The war-room dashboard frame on the run panel, darker than the canvas.
        frame: "hsl(var(--frame))",
        // The recessed telemetry surface (CEF tail, sample line, progress track).
        // Previously `bg-black`, which only reads correctly in one theme.
        well: "hsl(var(--well))",
        "text-3": "hsl(var(--text-3))",
        "text-4": "hsl(var(--text-4))",
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
        // Buttons and nav in the Factory system are 3px against 10px cards.
        btn: "3px",
      },
      fontFamily: {
        sans: ["Geist", "system-ui", "-apple-system", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "Menlo", "monospace"],
      },
      keyframes: {
        rise: {
          from: { opacity: "0", transform: "translateY(7px)" },
          to: { opacity: "1", transform: "none" },
        },
      },
      animation: {
        rise: "rise 0.34s cubic-bezier(0.2, 0.7, 0.3, 1) both",
      },
    },
  },
  plugins: [],
};
