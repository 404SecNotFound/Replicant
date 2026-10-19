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
import { byteSpan, describePri, dissectCef, eventClock, extensionValue, hexRows } from "./cef";

// One REP-001 line per profile, as `replicant run REP-001 --seed 1337 --no-send`
// rendered them (trimmed to the fields these tests read). Each vendor stresses a
// different part of the parser: FortiGate's eventtime, PAN-OS's epoch-second rt,
// Check Point's spaced header product and spaced extension values.
const FORTIGATE =
  "CEF:0|Fortinet|Fortigate|v7.4.3|00013|traffic:forward accept|3|deviceExternalId=FGVMSYNTH0000001 FTNTFGTeventtime=1752586800 src=10.20.30.139 spt=19700 dst=203.0.113.224 dpt=8080 proto=6 act=accept out=832 in=832";
const PANOS =
  "CEF:0|Palo Alto Networks|PAN-OS|11.1.2|end|TRAFFIC|3|rt=1752586800 src=10.20.30.139 dst=203.0.113.224 dpt=8080 proto=tcp act=allow cs4Label=Source Zone cs4=trust";
const CHECKPOINT =
  "CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|Log|http|Unknown|act=Accept rt=1752586800000 src=10.20.30.139 dst=203.0.113.224 dpt=8080 cs2Label=Rule Name cs2=policy-7 product=VPN-1 & FireWall-1 origin=192.0.2.1";

describe("dissectCef", () => {
  it("splits the seven header fields with spans that index the original line", () => {
    const d = dissectCef(CHECKPOINT)!;
    expect(d.header.map((h) => h.value)).toEqual([
      "0", "Check Point", "VPN-1 & FireWall-1", "Check Point", "Log", "http", "Unknown",
    ]);
    for (const part of d.header) expect(CHECKPOINT.slice(part.start, part.end)).toBe(part.value);
  });

  it("keeps spaced extension values whole and stops at the next key", () => {
    const d = dissectCef(CHECKPOINT)!;
    expect(extensionValue(d, "cs2Label")).toBe("Rule Name");
    expect(extensionValue(d, "product")).toBe("VPN-1 & FireWall-1");
    expect(extensionValue(d, "origin")).toBe("192.0.2.1");
    for (const part of d.extension) {
      expect(CHECKPOINT.slice(part.start, part.end)).toBe(`${part.key}=${part.value}`);
    }
  });

  it("treats an escaped pipe or equals sign as part of the value", () => {
    const d = dissectCef("CEF:0|V|P|1|42|a\\|b|5|msg=x\\=y dst=192.0.2.9")!;
    expect(d.header[5].value).toBe("a\\|b");
    expect(d.header[6].value).toBe("5");
    expect(extensionValue(d, "msg")).toBe("x\\=y");
    expect(extensionValue(d, "dst")).toBe("192.0.2.9");
  });

  it("reports a syslog prefix and its priority", () => {
    const d = dissectCef(`<134>1 2026-10-19T14:02:31.000Z fw-lab-01 - - - - ${FORTIGATE}`)!;
    expect(d.prefix?.pri).toBe(134);
    expect(d.prefix?.text).toBe("<134>1 2026-10-19T14:02:31.000Z fw-lab-01 - - - - ");
    expect(describePri(134)).toBe("local0.info");
    expect(describePri(192)).toBeNull();
  });

  it("returns null for a line that is not CEF and survives a truncated header", () => {
    expect(dissectCef("hello")).toBeNull();
    const d = dissectCef("CEF:0|Fortinet|Fortigate")!;
    expect(d.header).toHaveLength(3);
    expect(d.extension).toEqual([]);
  });
});

describe("eventClock", () => {
  it("reads each profile's own time field", () => {
    expect(eventClock(dissectCef(FORTIGATE))).toBe("13:40:00");
    expect(eventClock(dissectCef(PANOS))).toBe("13:40:00");
    expect(eventClock(dissectCef(CHECKPOINT))).toBe("13:40:00");
    expect(eventClock(dissectCef("CEF:0|V|P|1|42|n|5|rt=Oct 19 2026 14:02:31"))).toBeNull();
  });
});

describe("byte spans and the hex dump", () => {
  it("maps a character span to UTF-8 bytes, past multi-byte characters", () => {
    const line = "CEF:0|V|P|1|42|é|5|dpt=443";
    const d = dissectCef(line)!;
    const dpt = d.extension.find((p) => p.key === "dpt")!;
    const bytes = new TextEncoder().encode(line);
    const span = byteSpan(line, dpt);
    expect(span.start).toBe(dpt.start + 1);
    expect(new TextDecoder().decode(bytes.slice(span.start, span.end))).toBe("dpt=443");
  });

  it("chunks the encoded line into 16-byte rows with offsets", () => {
    const rows = hexRows(PANOS);
    expect(rows[0].offset).toBe(0);
    expect(rows[1].offset).toBe(16);
    expect(rows.flatMap((r) => r.bytes)).toHaveLength(new TextEncoder().encode(PANOS).length);
  });
});
