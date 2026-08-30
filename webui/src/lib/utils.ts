// Adapted from shadcn/ui (https://ui.shadcn.com), Copyright (c) 2023 shadcn,
// MIT License. Modifications Copyright 2026 Imran Hafeez (RZA).
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

import { clsx, type ClassValue } from "clsx";
import { extendTailwindMerge } from "tailwind-merge";

// tailwind-merge only knows the stock font sizes, so without this it classifies
// the project's type-scale rungs (text-label, text-body, ...) as text COLOR
// classes and silently deletes them whenever a real color follows in the same
// cn() call: cn("text-label", "text-signal") returned just "text-signal", and
// the element quietly inherited its parent's size. Measured live on the vendor
// segmented control, which rendered 16px while its class list said 12px.
// The rung names here must match the fontSize keys in tailwind.config.js.
const twMerge = extendTailwindMerge({
  extend: {
    classGroups: {
      "font-size": [{ text: ["micro", "label", "data", "body", "lede", "title"] }],
    },
  },
});

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
