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
"""FortiGate (FortiOS) vendor profile.

Source of truth for field names, ordering, signature IDs, and severity mapping is
docs/fortigate-cef-reference.md. The five record templates below reproduce the
seven constructed golden lines in that file byte for byte (the golden test is the
oracle). Field order inside each template is exact and intentional: real FortiOS
CEF is order-sensitive for downstream parsers.

Native FortiOS fields that have no standard CEF key are emitted with an
``FTNTFGT`` prefix; standard keys (src, dst, spt, dpt, proto, act, app, duser,
out, in, deviceExternalId, externalId, request, cnt, cat) are used where they
exist (reference s2.2, blueprint s9).
"""

from __future__ import annotations

from dataclasses import dataclass

from replicant.core.models import CefHeader, EventRecord
from replicant.profiles.base import VendorProfile, require

# Reversed FortiOS priority level -> CEF severity (reference s2.4).
# CEF severity = 8 - FortiOS numeric priority.
_LEVEL_TO_SEVERITY: dict[str, int] = {
    "emergency": 8,
    "alert": 7,
    "critical": 6,
    "error": 5,
    "warning": 4,
    "notice": 3,
    "notification": 3,
    "information": 2,
    "debug": 1,
}

# Full FortiOS logid per record family. Signature ID (CEF field 5) is the last
# five characters; the full logid is retained as FTNTFGTlogid (reference s2.3).
LOGID_TRAFFIC_FORWARD = "0000000013"
LOGID_UTM_IPS = "0419016384"
LOGID_DNS_QUERY = "1501054803"  # [Unverified] dns-query last-5; dns-response 54802 is confirmed
LOGID_DNS_RESPONSE = "1501054802"  # confirmed (reference s2.4)
LOGID_VPN_SUCCESS = "0101039947"  # [Unverified] tunnel-up last-5; login-fail 39426 is confirmed
LOGID_VPN_FAIL = "0101039426"
LOGID_EVENT_SYSTEM = "0100032002"


@dataclass(frozen=True)
class FortiGateDevice:
    """Per-device identity constants. Defaults match the reference golden lines."""

    vendor: str = "Fortinet"
    product: str = "Fortigate"  # lower-case g, matches real FortiOS output
    version: str = "v7.4.3"
    hostname: str = "FGT-LAB-01"
    serial: str = "FGVMSYNTH0000001"
    vd: str = "root"
    inbound_intf: str = "port2"
    outbound_intf: str = "port1"
    byte_key_out: str = "out"  # switchable to FTNTFGTsentbyte on some builds (reference s2.2)
    byte_key_in: str = "in"


class FortiGateProfile(VendorProfile):
    def __init__(self, device: FortiGateDevice | None = None) -> None:
        self.device = device or FortiGateDevice()

    @property
    def name(self) -> str:
        return "fortigate"

    @property
    def hostname(self) -> str:
        return self.device.hostname

    @property
    def accepted_as(self) -> str:
        # The LogRhythm log-source type these FortiOS CEF records map to.
        return "Syslog - Fortinet FortiGate v5.6 CEF"

    def severity(self, level: str) -> int:
        try:
            return _LEVEL_TO_SEVERITY[level.lower()]
        except KeyError as exc:
            raise ValueError(f"unknown FortiOS level: {level!r}") from exc

    def render(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        key = (event.log_type, event.subtype)
        if key == ("traffic", "forward"):
            return self._traffic_forward(event)
        if key == ("dns", "dns-query"):
            return self._dns_query(event)
        if key == ("dns", "dns-response"):
            return self._dns_response(event)
        if key == ("utm", "ips"):
            return self._utm_ips(event)
        if key == ("event", "vpn"):
            return self._event_vpn(event)
        if key == ("event", "system"):
            return self._event_system(event)
        raise ValueError(f"unsupported FortiGate log type '{event.log_type}:{event.subtype}'")

    # -- helpers ---------------------------------------------------------------

    def _header(self, logid: str, name: str, level: str) -> CefHeader:
        return CefHeader(
            version=0,
            device_vendor=self.device.vendor,
            device_product=self.device.product,
            device_version=self.device.version,
            signature_id=logid[-5:],
            name=name,
            severity=self.severity(level),
        )

    def _common_prefix(
        self,
        ext: dict[str, str],
        *,
        logid: str,
        cat: str,
        subtype: str,
        level: str,
        eventtime: int,
        eventtype: str | None = None,
        ips_severity: str | None = None,
    ) -> None:
        ext["deviceExternalId"] = self.device.serial
        ext["FTNTFGTlogid"] = logid
        ext["cat"] = cat
        ext["FTNTFGTsubtype"] = subtype
        if eventtype is not None:
            ext["FTNTFGTeventtype"] = eventtype
        ext["FTNTFGTlevel"] = level
        ext["FTNTFGTvd"] = self.device.vd
        ext["FTNTFGTeventtime"] = str(eventtime)
        if ips_severity is not None:
            ext["FTNTFGTseverity"] = ips_severity

    # -- templates -------------------------------------------------------------

    def _traffic_forward(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        ext: dict[str, str] = {}
        self._common_prefix(
            ext,
            logid=LOGID_TRAFFIC_FORWARD,
            cat="traffic:forward",
            subtype="forward",
            level=event.level,
            eventtime=event.eventtime,
        )
        ext["src"] = require(event.src, "src")
        ext["spt"] = require(event.spt, "spt")
        ext["deviceInboundInterface"] = e.get("src_intf", self.device.inbound_intf)
        ext["dst"] = require(event.dst, "dst")
        ext["dpt"] = require(event.dpt, "dpt")
        ext["deviceOutboundInterface"] = e.get("dst_intf", self.device.outbound_intf)
        ext["proto"] = require(event.proto, "proto")
        ext["act"] = event.action
        ext["FTNTFGTpolicyid"] = e["policyid"]
        ext["FTNTFGTservice"] = e["service"]
        if event.action == "accept":
            ext["app"] = e["app"]
            ext["FTNTFGTtrandisp"] = e["trandisp"]
        else:
            ext["FTNTFGTpolicytype"] = e.get("policytype", "policy")
        ext["externalId"] = require(event.session_id, "session_id")
        if event.action == "accept":
            ext["FTNTFGTduration"] = e["duration"]
        ext[self.device.byte_key_out] = require(event.out_bytes, "out_bytes")
        ext[self.device.byte_key_in] = require(event.in_bytes, "in_bytes")
        ext["FTNTFGTsentpkt"] = e["sentpkt"]
        ext["FTNTFGTrcvdpkt"] = e["rcvdpkt"]
        return (
            self._header(LOGID_TRAFFIC_FORWARD, f"traffic:forward {event.action}", event.level),
            ext,
        )

    def _dns_query(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        ext: dict[str, str] = {}
        self._common_prefix(
            ext,
            logid=LOGID_DNS_QUERY,
            cat="dns:dns-query",
            subtype="dns-query",
            level=event.level,
            eventtime=event.eventtime,
        )
        ext["FTNTFGTpolicyid"] = e["policyid"]
        ext["externalId"] = require(event.session_id, "session_id")
        ext["src"] = require(event.src, "src")
        ext["spt"] = require(event.spt, "spt")
        ext["deviceInboundInterface"] = e.get("src_intf", self.device.inbound_intf)
        ext["dst"] = require(event.dst, "dst")
        ext["dpt"] = require(event.dpt, "dpt")
        ext["proto"] = require(event.proto, "proto")
        ext["FTNTFGTprofile"] = e.get("profile", "default")
        ext["FTNTFGTxid"] = e["xid"]
        ext["FTNTFGTqname"] = e["qname"]
        ext["FTNTFGTqtype"] = e["qtype"]
        ext["FTNTFGTqtypeval"] = e["qtypeval"]
        ext["FTNTFGTqclass"] = e.get("qclass", "IN")
        ext["act"] = event.action
        return self._header(LOGID_DNS_QUERY, f"dns:dns-query {event.action}", event.level), ext

    def _dns_response(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        """dns:dns-response. Carries the resolution outcome, which dns-query cannot.

        This path exists because a DGA's signal is *failed* resolution: a cluster
        of NXDOMAIN answers with similar syntactic features. dns-query has no
        response code, so REP-016 is not expressible without it.

        Field naming: FortiOS non-standard fields take the FTNTFGT prefix
        (reference s1.3). ``FTNTFGTrcode`` and ``FTNTFGTipaddr`` are
        [Unverified] against a live build; signature id 54802 is confirmed.
        """

        e = event.extra
        ext: dict[str, str] = {}
        self._common_prefix(
            ext,
            logid=LOGID_DNS_RESPONSE,
            cat="dns:dns-response",
            subtype="dns-response",
            level=event.level,
            eventtime=event.eventtime,
        )
        ext["FTNTFGTpolicyid"] = e["policyid"]
        ext["externalId"] = require(event.session_id, "session_id")
        ext["src"] = require(event.src, "src")
        ext["spt"] = require(event.spt, "spt")
        ext["deviceInboundInterface"] = e.get("src_intf", self.device.inbound_intf)
        ext["dst"] = require(event.dst, "dst")
        ext["dpt"] = require(event.dpt, "dpt")
        ext["proto"] = require(event.proto, "proto")
        ext["FTNTFGTprofile"] = e.get("profile", "default")
        ext["FTNTFGTxid"] = e["xid"]
        ext["FTNTFGTqname"] = e["qname"]
        ext["FTNTFGTqtype"] = e["qtype"]
        ext["FTNTFGTqtypeval"] = e["qtypeval"]
        ext["FTNTFGTqclass"] = e.get("qclass", "IN")
        ext["FTNTFGTrcode"] = e["rcode"]
        # A resolved answer only exists when the name resolved. Omitting it on
        # NXDOMAIN is the point: that absence is what a DGA cluster looks like.
        if e.get("ipaddr"):
            ext["FTNTFGTipaddr"] = e["ipaddr"]
        ext["act"] = event.action
        name = f"dns:dns-response {event.action}"
        return self._header(LOGID_DNS_RESPONSE, name, event.level), ext

    def _utm_ips(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        eventtype = e.get("eventtype", "signature")
        ext: dict[str, str] = {}
        self._common_prefix(
            ext,
            logid=LOGID_UTM_IPS,
            cat="utm:ips",
            subtype="ips",
            level=event.level,
            eventtime=event.eventtime,
            eventtype=eventtype,
            ips_severity=e["ips_severity"],
        )
        ext["src"] = require(event.src, "src")
        ext["spt"] = require(event.spt, "spt")
        ext["dst"] = require(event.dst, "dst")
        ext["dpt"] = require(event.dpt, "dpt")
        ext["proto"] = require(event.proto, "proto")
        ext["act"] = event.action
        ext["FTNTFGTservice"] = e["service"]
        ext["FTNTFGTpolicyid"] = e["policyid"]
        ext["FTNTFGTattack"] = e["attack"]
        ext["FTNTFGTattackid"] = e["attackid"]
        ext["FTNTFGThostname"] = e["hostname"]
        ext["request"] = e["request"]
        ext["FTNTFGTdirection"] = e.get("direction", "incoming")
        ext["FTNTFGTprofile"] = e.get("profile", "default")
        ext["externalId"] = require(event.session_id, "session_id")
        ext["cnt"] = e.get("cnt", "1")
        ext["FTNTFGTmsg"] = e["msg"]
        return self._header(LOGID_UTM_IPS, f"utm:ips {eventtype} {event.action}", event.level), ext

    def _event_vpn(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        is_fail = event.action == "ssl-login-fail"
        logid = LOGID_VPN_FAIL if is_fail else LOGID_VPN_SUCCESS
        name = "event:vpn ssl-login-fail" if is_fail else "event:vpn ssl-login"
        ext: dict[str, str] = {}
        self._common_prefix(
            ext,
            logid=logid,
            cat="event:vpn",
            subtype="vpn",
            level=event.level,
            eventtime=event.eventtime,
        )
        ext["FTNTFGTlogdesc"] = e["logdesc"]
        ext["FTNTFGTaction"] = e.get("fgt_action", event.action)
        ext["duser"] = require(event.duser, "duser")
        ext["src"] = require(event.src, "src")
        ext["FTNTFGTremip"] = e.get("remip", require(event.src, "src"))
        # Synthetic GeoIP tag, present only for geovelocity scenarios (REP-011). The
        # seven golden lines omit it, so it stays optional and never shifts their order.
        if "srccountry" in e:
            ext["FTNTFGTsrccountry"] = e["srccountry"]
        ext["FTNTFGTtunneltype"] = e["tunneltype"]
        if not is_fail:
            ext["FTNTFGTtunnelid"] = e["tunnelid"]
            ext["FTNTFGTgroup"] = e["group"]
        ext["FTNTFGTreason"] = e["reason"]
        ext["FTNTFGTmsg"] = e["msg"]
        return self._header(logid, name, event.level), ext

    def _event_system(self, event: EventRecord) -> tuple[CefHeader, dict[str, str]]:
        e = event.extra
        fgt_action = e.get("fgt_action", event.action)
        status = e["status"]
        ext: dict[str, str] = {}
        self._common_prefix(
            ext,
            logid=LOGID_EVENT_SYSTEM,
            cat="event:system",
            subtype="system",
            level=event.level,
            eventtime=event.eventtime,
        )
        ext["FTNTFGTlogdesc"] = e["logdesc"]
        ext["FTNTFGTaction"] = fgt_action
        ext["FTNTFGTstatus"] = status
        ext["duser"] = require(event.duser, "duser")
        ext["src"] = require(event.src, "src")
        ext["FTNTFGTui"] = e["ui"]
        ext["FTNTFGTmethod"] = e["method"]
        ext["FTNTFGTreason"] = e["reason"]
        ext["FTNTFGTmsg"] = e["msg"]
        name = f"event:system {fgt_action} {status}"
        return self._header(LOGID_EVENT_SYSTEM, name, event.level), ext
