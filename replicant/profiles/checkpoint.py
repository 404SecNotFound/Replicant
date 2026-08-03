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
"""Check Point (Log Exporter) vendor profile.

Source of truth for field names, ordering, and severity strings is
docs/checkpoint-cef-reference.md; the seven constructed golden lines there are the
oracle (the golden test reproduces them byte for byte). The profile consumes the same
vendor-neutral EventRecord the FortiGate and Palo Alto profiles do: techniques emit
neutral ``(log_type, subtype)`` categories and this profile maps each to the Check Point
Log Exporter CEF layout.

Check Point differs from FortiGate/PAN-OS in three ways that matter here (reference s1, s2):
``rt`` is epoch milliseconds; ``proto`` is the numeric IANA protocol; and the CEF Severity
is a text string (``Unknown``/``Low``/``Medium``/``High``/``Very-High``), not a 0-10 integer.

All mappings are ``[Unverified]`` against a live Log Exporter build (reference header note).
"""

from __future__ import annotations

from dataclasses import dataclass

from replicant.core.models import CefHeader, EventRecord
from replicant.profiles.base import VendorProfile, require

# Neutral log level -> Check Point CEF severity string. Not reversed; rises with
# seriousness (reference s2.3). Used for event failures; plain connection logs and
# successful auth emit ``Unknown`` directly, and Threat Prevention uses _IPS_SEVERITY.
_LEVEL_TO_SEVERITY: dict[str, str] = {
    "emergency": "Very-High",
    "critical": "Very-High",
    "alert": "High",
    "error": "High",
    "warning": "Medium",
    "notice": "Low",
    "notification": "Low",
    "information": "Low",
    "debug": "Low",
}

# IPS/Threat Prevention severity -> CEF severity string (reference s2.3).
_IPS_SEVERITY: dict[str, str] = {
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Very-High",
}

_SEV_UNKNOWN = "Unknown"


def _is_internal(ip: str) -> bool:
    """True for RFC1918 space (10/8, 172.16/12, 192.168/16)."""

    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) > 1 and parts[1].isdigit():
            return 16 <= int(parts[1]) <= 31
    return False


@dataclass(frozen=True)
class CheckPointDevice:
    """Per-device identity constants. Defaults match the reference golden lines."""

    vendor: str = "Check Point"
    version: str = "Check Point"  # Log Exporter puts the literal words here, not a version
    hostname: str = "CP-LAB-GW-01"  # syslog frame host, per the reference doc
    product_fw: str = "VPN-1 & FireWall-1"
    product_ips: str = "SmartDefense"
    product_vpn: str = "Mobile Access"
    product_sys: str = "Check Point"
    origin: str = "192.0.2.1"
    inzone: str = "Internal"
    outzone: str = "External"
    layer_name: str = "Network"
    nat_ip: str = "198.51.100.10"


class CheckPointProfile(VendorProfile):
    def __init__(self, device: CheckPointDevice | None = None) -> None:
        self.device = device or CheckPointDevice()

    @property
    def name(self) -> str:
        return "checkpoint"

    @property
    def hostname(self) -> str:
        return self.device.hostname

    @property
    def accepted_as(self) -> str:
        # [Unverified] the exact LogRhythm log-source type name for Check Point
        # Log Exporter CEF; named honestly for Check Point, not FortiGate.
        return "Syslog - Check Point Log Exporter CEF"

    def severity(self, level: str) -> int | str:
        try:
            return _LEVEL_TO_SEVERITY[level.lower()]
        except KeyError as exc:
            raise ValueError(f"unknown Check Point level: {level!r}") from exc

    def render(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        key = (event.log_type, event.subtype)
        if key == ("traffic", "forward"):
            return self._traffic_forward(event)
        if key == ("dns", "dns-query"):
            return self._dns_query(event)
        if key == ("dns", "dns-response"):
            return self._dns_response(event)
        if key == ("utm", "ips"):
            return self._threat_ips(event)
        if key == ("event", "vpn"):
            return self._mobile_access(event)
        if key == ("event", "system"):
            return self._system(event)
        raise ValueError(f"unsupported Check Point log type '{event.log_type}:{event.subtype}'")

    # -- helpers ---------------------------------------------------------------

    def _header(self, product: str, sigid: str, name: str, severity: int | str) -> CefHeader:
        return CefHeader(
            version=0,
            device_vendor=self.device.vendor,
            device_product=product,
            device_version=self.device.version,
            signature_id=sigid,
            name=name,
            severity=severity,
        )

    @staticmethod
    def _rt(eventtime: int) -> str:
        """Check Point emits receipt time as epoch milliseconds (reference s1)."""

        return str(eventtime * 1000)

    @staticmethod
    def _direction(dst: str | None) -> str:
        """deviceDirection: 0 when the destination is internal, else 1 (reference s2.2)."""

        return "0" if dst is not None and _is_internal(dst) else "1"

    def _ips_severity(self, level: str) -> str:
        return _IPS_SEVERITY.get(level.lower(), "Medium")

    # -- templates -------------------------------------------------------------

    def _traffic_forward(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        accept = event.action == "accept"
        service = e.get("service", "")
        service_id = service.lower()
        app = e.get("app") or service
        dst = require(event.dst, "dst")
        ext: dict[str, str] = {}
        ext["act"] = "Accept" if accept else "Drop"
        ext["deviceDirection"] = self._direction(event.dst)
        ext["rt"] = self._rt(event.eventtime)
        ext["src"] = require(event.src, "src")
        ext["dst"] = dst
        ext["spt"] = require(event.spt, "spt")
        ext["dpt"] = require(event.dpt, "dpt")
        ext["proto"] = require(event.proto, "proto")
        ext["app"] = app
        ext["service_id"] = service_id
        if accept and e.get("trandisp") == "snat":
            ext["sourceTranslatedAddress"] = self.device.nat_ip
            ext["sourceTranslatedPort"] = require(event.spt, "spt")
        ext["cs2Label"] = "Rule Name"
        ext["cs2"] = f"policy-{e['policyid']}"
        if accept and "duration" in e:
            ext["cn1Label"] = "Elapsed"
            ext["cn1"] = e["duration"]
        ext["in"] = require(event.in_bytes, "in_bytes")
        ext["out"] = require(event.out_bytes, "out_bytes")
        ext["inzone"] = self.device.inzone
        ext["outzone"] = self.device.inzone if _is_internal(dst) else self.device.outzone
        ext["layer_name"] = self.device.layer_name
        ext["product"] = self.device.product_fw
        ext["origin"] = self.device.origin
        return self._header(self.device.product_fw, "Log", service_id, _SEV_UNKNOWN), ext

    def _dns_query(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        dst = require(event.dst, "dst")
        ext: dict[str, str] = {}
        ext["act"] = "Accept"
        ext["deviceDirection"] = self._direction(event.dst)
        ext["rt"] = self._rt(event.eventtime)
        ext["src"] = require(event.src, "src")
        ext["dst"] = dst
        ext["spt"] = require(event.spt, "spt")
        ext["dpt"] = require(event.dpt, "dpt")
        ext["proto"] = require(event.proto, "proto")
        ext["app"] = "dns"
        ext["service_id"] = "domain-udp"
        ext["destinationDnsDomain"] = e["qname"]
        ext["cs2Label"] = "Rule Name"
        ext["cs2"] = f"policy-{e['policyid']}"
        ext["inzone"] = self.device.inzone
        ext["outzone"] = self.device.inzone if _is_internal(dst) else self.device.outzone
        ext["layer_name"] = self.device.layer_name
        ext["product"] = self.device.product_fw
        ext["origin"] = self.device.origin
        return self._header(self.device.product_fw, "Log", "domain-udp", _SEV_UNKNOWN), ext

    def _dns_response(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        """DNS resolution outcome. [Unverified] dns_rcode field name."""

        e = event.extra
        dst = require(event.dst, "dst")
        ext: dict[str, str] = {}
        ext["act"] = "Accept"
        ext["deviceDirection"] = self._direction(event.dst)
        ext["rt"] = self._rt(event.eventtime)
        ext["src"] = require(event.src, "src")
        ext["dst"] = dst
        ext["spt"] = require(event.spt, "spt")
        ext["dpt"] = require(event.dpt, "dpt")
        ext["proto"] = require(event.proto, "proto")
        ext["app"] = "dns"
        ext["service_id"] = "domain-udp"
        ext["destinationDnsDomain"] = e["qname"]
        ext["dns_rcode"] = e["rcode"]
        if e.get("ipaddr"):
            ext["dns_resolved_addr"] = e["ipaddr"]
        ext["cs2Label"] = "Rule Name"
        ext["cs2"] = f"policy-{e['policyid']}"
        ext["inzone"] = self.device.inzone
        ext["outzone"] = self.device.inzone if _is_internal(dst) else self.device.outzone
        ext["layer_name"] = self.device.layer_name
        ext["product"] = self.device.product_fw
        ext["origin"] = self.device.origin
        return self._header(self.device.product_fw, "Log", "domain-udp", _SEV_UNKNOWN), ext

    def _threat_ips(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        service = e.get("service", "")
        sev = self._ips_severity(e["ips_severity"])
        ext: dict[str, str] = {}
        ext["act"] = "Prevent"
        ext["deviceDirection"] = self._direction(event.dst)
        ext["rt"] = self._rt(event.eventtime)
        ext["src"] = require(event.src, "src")
        ext["dst"] = require(event.dst, "dst")
        ext["spt"] = require(event.spt, "spt")
        ext["dpt"] = require(event.dpt, "dpt")
        ext["proto"] = require(event.proto, "proto")
        ext["app"] = service
        ext["service_id"] = service.lower()
        ext["cp_severity"] = sev
        ext["cs1Label"] = "Threat Prevention Rule Name"
        ext["cs1"] = f"policy-{e['policyid']}"
        ext["cs2Label"] = "Protection ID"
        ext["cs2"] = e["attackid"]
        ext["cs3Label"] = "Protection Type"
        ext["cs3"] = "IPS"
        ext["cs4Label"] = "Protection Name"
        ext["cs4"] = e["attack"]
        ext["request"] = e["request"]
        ext["msg"] = e["msg"]
        ext["product"] = self.device.product_ips
        ext["origin"] = self.device.origin
        return self._header(self.device.product_ips, "IPS", e["attack"], sev), ext

    def _mobile_access(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        is_fail = event.action == "ssl-login-fail"
        sev: int | str = self.severity(event.level) if is_fail else _SEV_UNKNOWN
        ext: dict[str, str] = {}
        ext["act"] = "Reject" if is_fail else "Accept"
        ext["rt"] = self._rt(event.eventtime)
        ext["src"] = require(event.src, "src")
        ext["duser"] = require(event.duser, "duser")
        ext["suser"] = require(event.duser, "duser")
        ext["auth_status"] = "Failed Login" if is_fail else "Successful Login"
        if is_fail:
            ext["cp_severity"] = str(sev)
        if not is_fail:
            ext["cs3Label"] = "User Group"
            ext["cs3"] = e["group"]
        ext["cs5Label"] = "Auth Method"
        ext["cs5"] = e["tunneltype"]
        if not is_fail:
            ext["cn1Label"] = "Tunnel ID"
            ext["cn1"] = e["tunnelid"]
        ext["reason"] = e["reason"]
        ext["msg"] = e["msg"]
        ext["product"] = self.device.product_vpn
        ext["origin"] = self.device.origin
        return self._header(self.device.product_vpn, "Log", "Log", sev), ext

    def _system(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        sev = self.severity(event.level)
        # The login verdict follows the event, as it already does in _vpn above.
        # These two were hardcoded to failure while the engine only ever sends
        # status="success" down this path (REP-018's lateral movement chain), so
        # every admin login rendered as a Reject whose own msg said "Admin login
        # successful". REP-018's detection use case keys on successful logins, so
        # the contradiction landed in exactly the field a rule reads.
        is_fail = e.get("status") != "success"
        ext: dict[str, str] = {}
        ext["act"] = "Reject" if is_fail else "Accept"
        ext["rt"] = self._rt(event.eventtime)
        ext["src"] = require(event.src, "src")
        ext["duser"] = require(event.duser, "duser")
        ext["suser"] = require(event.duser, "duser")
        ext["auth_status"] = "Failed Login" if is_fail else "Successful Login"
        ext["cp_severity"] = str(sev)
        ext["administrator"] = require(event.duser, "duser")
        ext["operation"] = "Log In"
        ext["cs1Label"] = "Client"
        ext["cs1"] = e["method"]
        ext["reason"] = e["reason"]
        ext["msg"] = e["msg"]
        ext["product"] = self.device.product_sys
        ext["origin"] = self.device.origin
        return self._header(self.device.product_sys, "Log", "Log", sev), ext
