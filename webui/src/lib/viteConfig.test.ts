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

import { describe, expect, it } from "vitest";
import configSource from "../../vite.config.ts?raw";
import { tokenBootstrapProxy } from "./bootstrapProxy";

describe("Vite token bootstrap proxy", () => {
  it("sends only tokenized root navigations through the backend exchange", () => {
    const matcher = new RegExp(tokenBootstrapProxy);

    expect(matcher.test("/?token=launch-token")).toBe(true);
    expect(matcher.test("/?view=catalog&token=launch-token")).toBe(true);
    expect(matcher.test("/")).toBe(false);
    expect(matcher.test("/src/main.tsx?token=launch-token")).toBe(false);
    expect(configSource).toContain("[tokenBootstrapProxy]");
    expect(configSource.match(/changeOrigin: false/g)).toHaveLength(3);
  });
});
