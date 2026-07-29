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

import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Unmount between tests. Without this, queries like getByText match nodes left
// behind by an earlier test and a broken component can still look correct.
afterEach(() => {
  cleanup();
});

// Node 25 ships an experimental built-in `localStorage`. Without a valid
// `--localstorage-file` it is a methodless object, and it shadows the working
// Storage jsdom would otherwise provide, so `getItem` is not a function. Verified
// with a bare `node -e`, no jsdom involved:
//
//   node v25.6.1  ->  typeof localStorage "object", getItem is fn: false
//   Warning: `--localstorage-file` was provided without a valid path
//
// CI runs Node 18 and 20, which have no built-in localStorage, so jsdom's real
// Storage is used there and the branch below never fires. This only bites local
// development on a newer Node. The guard keys off a working `getItem` rather than
// a version check so it follows the actual capability. Tests that need storage to
// *fail* still override this with their own throwing getter.
if (typeof window.localStorage?.getItem !== "function") {
  const entries = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    writable: true,
    value: {
      getItem: (key: string) => entries.get(key) ?? null,
      setItem: (key: string, value: string) => void entries.set(key, String(value)),
      removeItem: (key: string) => void entries.delete(key),
      clear: () => entries.clear(),
      key: (index: number) => [...entries.keys()][index] ?? null,
      get length() {
        return entries.size;
      },
    },
  });
}
