# Copyright 2026 Imran Hafeez (RZA)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Palo Alto Networks (PAN-OS) vendor profile.

Source of truth for field names, ordering, and severity mapping is
docs/paloalto-cef-reference.md; the seven constructed golden lines there are the
oracle (the golden test reproduces them byte for byte). The profile consumes the
same vendor-neutral EventRecord the FortiGate profile does: techniques emit neutral
``(log_type, subtype)`` categories and this profile maps each to the PAN-OS layout.

All mappings are ``[Unverified]`` against a live PAN-OS build (reference header note).
"""

from __future__ import annotations

from dataclasses import dataclass

from replicant.core.models import CefHeader, EventRecord
from replicant.profiles.base import VendorProfile, require

# PAN-OS log level -> CEF severity. Unlike FortiOS this is not reversed; severity
# rises with seriousness (reference s2.3).
_LEVEL_TO_SEVERITY: dict[str, int] = {
    "emergency": 10,
    "critical": 9,
    "alert": 8,
    "error": 6,
    "warning": 5,
    "notice": 3,
    "notification": 3,
    "information": 2,
    "debug": 1,
}

_PROTO: dict[int, str] = {6: "tcp", 17: "udp", 1: "icmp"}


def _proto(proto: int | None) -> str:
    return _PROTO.get(proto, str(proto)) if proto is not None else ""


@dataclass(frozen=True)
class PanOSDevice:
    """Per-device identity constants. Defaults match the reference golden lines."""

    vendor: str = "Palo Alto Networks"
    product: str = "PAN-OS"
    version: str = "11.1.2"
    hostname: str = "PA-LAB-01"
    serial: str = "007051000054321"
    vsys: str = "vsys1"
    src_zone: str = "trust"
    dst_zone: str = "untrust"
    inbound_intf: str = "ethernet1/2"
    outbound_intf: str = "ethernet1/1"
    nat_ip: str = "198.51.100.10"


class PaloAltoProfile(VendorProfile):
    def __init__(self, device: PanOSDevice | None = None) -> None:
        self.device = device or PanOSDevice()

    @property
    def name(self) -> str:
        return "paloalto"

    def severity(self, level: str) -> int:
        try:
            return _LEVEL_TO_SEVERITY[level.lower()]
        except KeyError as exc:
            raise ValueError(f"unknown PAN-OS level: {level!r}") from exc

    def render(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        key = (event.log_type, event.subtype)
        if key == ("traffic", "forward"):
            return self._traffic_forward(event)
        if key == ("dns", "dns-query"):
            return self._dns_query(event)
        if key == ("utm", "ips"):
            return self._threat_ips(event)
        if key == ("event", "vpn"):
            return self._globalprotect(event)
        if key == ("event", "system"):
            return self._system(event)
        raise ValueError(f"unsupported PAN-OS log type '{event.log_type}:{event.subtype}'")

    # -- helpers ---------------------------------------------------------------

    def _header(self, sigid: str, name: str, level: str) -> CefHeader:
        return CefHeader(
            version=0,
            device_vendor=self.device.vendor,
            device_product=self.device.product,
            device_version=self.device.version,
            signature_id=sigid,
            name=name,
            severity=self.severity(level),
        )

    # -- templates -------------------------------------------------------------

    def _traffic_forward(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        accept = event.action == "accept"
        sigid = "end" if accept else "deny"
        act = "allow" if accept else "deny"
        app = e.get("app") or e.get("service", "")
        ext: dict[str, str] = {}
        ext["rt"] = str(event.eventtime)
        ext["deviceExternalId"] = self.device.serial
        ext["src"] = require(event.src, "src")
        ext["dst"] = require(event.dst, "dst")
        ext["spt"] = require(event.spt, "spt")
        ext["dpt"] = require(event.dpt, "dpt")
        ext["proto"] = _proto(event.proto)
        ext["act"] = act
        ext["app"] = app
        ext["cs1Label"] = "Rule"
        ext["cs1"] = f"policy-{e['policyid']}"
        ext["cs3Label"] = "Virtual System"
        ext["cs3"] = self.device.vsys
        ext["cs4Label"] = "Source Zone"
        ext["cs4"] = self.device.src_zone
        ext["cs5Label"] = "Destination Zone"
        ext["cs5"] = self.device.dst_zone
        ext["deviceInboundInterface"] = self.device.inbound_intf
        ext["deviceOutboundInterface"] = self.device.outbound_intf
        if accept:
            ext["sourceTranslatedAddress"] = self.device.nat_ip
            ext["sourceTranslatedPort"] = require(event.spt, "spt")
        ext["cn1Label"] = "SessionID"
        ext["cn1"] = require(event.session_id, "session_id")
        ext["cnt"] = "1"
        ext["in"] = require(event.in_bytes, "in_bytes")
        ext["out"] = require(event.out_bytes, "out_bytes")
        ext["PanOSPacketsReceived"] = e["rcvdpkt"]
        ext["PanOSPacketsSent"] = e["sentpkt"]
        ext["cs6Label"] = "LogProfile"
        ext["cs6"] = "default"
        return self._header(sigid, "TRAFFIC", event.level), ext

    def _dns_query(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        ext: dict[str, str] = {}
        ext["rt"] = str(event.eventtime)
        ext["deviceExternalId"] = self.device.serial
        ext["src"] = require(event.src, "src")
        ext["dst"] = require(event.dst, "dst")
        ext["spt"] = require(event.spt, "spt")
        ext["dpt"] = require(event.dpt, "dpt")
        ext["proto"] = _proto(event.proto)
        ext["act"] = "allow"
        ext["app"] = "dns"
        ext["cs1Label"] = "Rule"
        ext["cs1"] = f"policy-{e['policyid']}"
        ext["cs3Label"] = "Virtual System"
        ext["cs3"] = self.device.vsys
        ext["cs4Label"] = "Source Zone"
        ext["cs4"] = self.device.src_zone
        ext["cs5Label"] = "Destination Zone"
        ext["cs5"] = self.device.dst_zone
        ext["deviceInboundInterface"] = self.device.inbound_intf
        ext["deviceOutboundInterface"] = self.device.outbound_intf
        ext["cn1Label"] = "SessionID"
        ext["cn1"] = require(event.session_id, "session_id")
        ext["PanOSDNSQuery"] = e["qname"]
        ext["PanOSDNSType"] = e["qtype"]
        ext["cnt"] = "1"
        ext["cs6Label"] = "LogProfile"
        ext["cs6"] = "default"
        return self._header("end", "TRAFFIC", event.level), ext

    def _threat_ips(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        ext: dict[str, str] = {}
        ext["rt"] = str(event.eventtime)
        ext["deviceExternalId"] = self.device.serial
        ext["src"] = require(event.src, "src")
        ext["dst"] = require(event.dst, "dst")
        ext["spt"] = require(event.spt, "spt")
        ext["dpt"] = require(event.dpt, "dpt")
        ext["proto"] = _proto(event.proto)
        ext["act"] = "reset-both"
        ext["app"] = e["service"]
        ext["cs1Label"] = "Rule"
        ext["cs1"] = f"policy-{e['policyid']}"
        ext["cs3Label"] = "Virtual System"
        ext["cs3"] = self.device.vsys
        # An incoming attack: the source is the untrusted zone, the victim the trust zone.
        ext["cs4Label"] = "Source Zone"
        ext["cs4"] = self.device.dst_zone
        ext["cs5Label"] = "Destination Zone"
        ext["cs5"] = self.device.src_zone
        ext["cn1Label"] = "SessionID"
        ext["cn1"] = require(event.session_id, "session_id")
        ext["request"] = e["request"]
        ext["PanOSThreatID"] = e["attackid"]
        ext["PanOSThreatName"] = e["attack"]
        ext["cs2Label"] = "Severity"
        ext["cs2"] = e["ips_severity"]
        ext["cn2Label"] = "Direction"
        ext["cn2"] = "0" if e.get("direction", "incoming") == "incoming" else "1"
        ext["cnt"] = e.get("cnt", "1")
        ext["cs6Label"] = "Profile"
        ext["cs6"] = e.get("profile", "default")
        return self._header("vulnerability", "THREAT", event.level), ext

    def _globalprotect(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        is_fail = event.action == "ssl-login-fail"
        ext: dict[str, str] = {}
        ext["rt"] = str(event.eventtime)
        ext["deviceExternalId"] = self.device.serial
        ext["duser"] = require(event.duser, "duser")
        ext["suser"] = require(event.duser, "duser")
        ext["src"] = require(event.src, "src")
        ext["act"] = "deny" if is_fail else "allow"
        ext["PanOSEventID"] = "gateway-auth-fail" if is_fail else "gateway-auth-succ"
        ext["PanOSStage"] = "login"
        ext["PanOSAuthMethod"] = e["tunneltype"]
        # Synthetic GeoIP tag, present only for geovelocity scenarios (REP-011).
        if "srccountry" in e:
            ext["cs4Label"] = "Source Region"
            ext["cs4"] = e["srccountry"]
        ext["cs3Label"] = "Virtual System"
        ext["cs3"] = self.device.vsys
        if not is_fail:
            ext["cn1Label"] = "TunnelID"
            ext["cn1"] = e["tunnelid"]
            ext["cs2Label"] = "Group"
            ext["cs2"] = e["group"]
        ext["reason"] = e["reason"]
        ext["msg"] = e["msg"]
        return self._header("globalprotect", "GLOBALPROTECT", event.level), ext

    def _system(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        ext: dict[str, str] = {}
        ext["rt"] = str(event.eventtime)
        ext["deviceExternalId"] = self.device.serial
        ext["duser"] = require(event.duser, "duser")
        ext["suser"] = require(event.duser, "duser")
        ext["src"] = require(event.src, "src")
        ext["act"] = e.get("fgt_action", event.action)
        ext["PanOSEventID"] = "auth-fail"
        ext["PanOSModule"] = "general"
        ext["PanOSStatus"] = e["status"]
        ext["cs1Label"] = "Client"
        ext["cs1"] = e["method"]
        ext["cs3Label"] = "Virtual System"
        ext["cs3"] = self.device.vsys
        ext["reason"] = e["reason"]
        ext["msg"] = e["msg"]
        return self._header("general", "SYSTEM", event.level), ext
