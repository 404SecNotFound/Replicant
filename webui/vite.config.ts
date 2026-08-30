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

/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Dev proxy target: run the backend and point VITE_PROXY at its printed URL.
const proxyTarget = process.env.VITE_PROXY || "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
  build: {
    // Build INTO the Python package, not beside it. Anything outside
    // replicant/ is absent from a wheel, so a `pip install` used to produce a
    // web UI that could never be served. setuptools picks this up via
    // package-data in pyproject.toml.
    outDir: "../replicant/webui_dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": { target: proxyTarget, changeOrigin: true },
      "/ws": { target: proxyTarget, ws: true, changeOrigin: true },
    },
  },
  test: {
    // jsdom, not happy-dom: src/lib/api.ts reads window.location.search at module
    // load time to pick up the session token, so the environment has to provide a
    // real Location before the import runs.
    environment: "jsdom",
    // Without this, vitest stubs every CSS import to an empty module, INCLUDING
    // `index.css?raw`, and theme.test.ts would assert against "" and pass on
    // nothing. Measured before adding: the raw import had length 0.
    css: true,
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
