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

import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { urlWithoutToken } from "@/lib/api";
import "./index.css";

// Defense in depth for a directly served/static build. The normal backend path
// exchanges the bootstrap token and redirects here without it before serving any
// JavaScript; no frontend module extracts, retains, or replays the credential.
const cleaned = urlWithoutToken(window.location.href);
if (cleaned) window.history.replaceState(null, "", cleaned);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
