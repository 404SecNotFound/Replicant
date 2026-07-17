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
"""Synthetic entity and asset model.

Builds one coherent world of synthetic hosts, external peers, a resolver, users,
and ports so a multi-event scenario lines up (blueprint s13). Enforces safety rule
2: every address pool must fall inside RFC1918 or IANA documentation ranges. A
configuration that reaches outside those ranges raises at construction time, so
Replicant can never fabricate a log that names a real host.
"""

from __future__ import annotations

import ipaddress
import itertools
from dataclasses import dataclass, field

# RFC1918 private space plus IANA documentation ranges (RFC 5737). Every default
# and configured subnet must be contained in one of these (safety rule 2).
_ALLOWED_RANGES: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)

# Parent domains for synthetic DNS. example.net is an IANA documentation domain;
# *.invalid is reserved as non-resolvable (RFC 6761). Never a real domain.
_DEFAULT_PARENTS: tuple[str, ...] = ("example.net", "cdn.invalid", "sync.example.net")

_DEFAULT_USERS: tuple[str, ...] = (
    "jsmith",
    "adoe",
    "mkhan",
    "rlopez",
    "kwong",
    "tosei",
    "bpatel",
    "nsingh",
)


def _assert_synthetic(network: ipaddress.IPv4Network) -> ipaddress.IPv4Network:
    for allowed in _ALLOWED_RANGES:
        if network.subnet_of(allowed):
            return network
    raise ValueError(
        f"subnet {network} is outside the synthetic ranges (RFC1918 / documentation); "
        "refusing to build a non-synthetic entity pool"
    )


def _hosts(cidr: str, limit: int | None = None) -> list[str]:
    network = _assert_synthetic(ipaddress.IPv4Network(cidr))
    hosts = network.hosts()
    if limit is not None:
        return [str(host) for host in itertools.islice(hosts, limit)]
    return [str(host) for host in hosts]


@dataclass
class EntityConfig:
    internal_subnet: str = "10.20.30.0/24"
    target_subnet: str = "10.20.40.0/24"
    sweep_subnet: str = "10.50.0.0/16"
    adversary_subnet: str = "203.0.113.0/24"
    benign_subnet: str = "198.51.100.0/24"
    resolver: str = "10.20.0.53"
    c2_ports: tuple[int, ...] = (443, 8443, 8080, 53)
    scan_ports: tuple[int, ...] = (445, 3389, 22, 23, 80)
    parents: tuple[str, ...] = _DEFAULT_PARENTS
    users: tuple[str, ...] = _DEFAULT_USERS
    host_limit: int = 254
    external_limit: int = 254
    sweep_limit: int = 8192


@dataclass
class EntityModel:
    """Materialized, deterministic synthetic pools sampled by the scenario engine."""

    internal_hosts: list[str]
    internal_targets: list[str]
    sweep_hosts: list[str]
    adversary_external: list[str]
    benign_external: list[str]
    resolver: str
    c2_ports: list[int]
    scan_ports: list[int]
    parents: list[str]
    users: list[str]
    countries: dict[str, str] = field(default_factory=dict)

    @classmethod
    def build(cls, config: EntityConfig | None = None) -> EntityModel:
        cfg = config or EntityConfig()
        # Validate the resolver is synthetic too.
        _assert_synthetic(ipaddress.IPv4Network(f"{cfg.resolver}/32"))
        adversary = _hosts(cfg.adversary_subnet, cfg.external_limit)
        benign = _hosts(cfg.benign_subnet, cfg.external_limit)
        # Synthetic GeoIP tags: split each external pool across two country tags so
        # a geovelocity scenario (phase 2) has distant blocks to draw from.
        countries: dict[str, str] = {}
        for idx, ip in enumerate(adversary):
            countries[ip] = "Wadiya" if idx % 2 == 0 else "Molvania"
        for idx, ip in enumerate(benign):
            countries[ip] = "Genovia" if idx % 2 == 0 else "Elbonia"
        return cls(
            internal_hosts=_hosts(cfg.internal_subnet, cfg.host_limit),
            internal_targets=_hosts(cfg.target_subnet, cfg.host_limit),
            sweep_hosts=_hosts(cfg.sweep_subnet, cfg.sweep_limit),
            adversary_external=adversary,
            benign_external=benign,
            resolver=cfg.resolver,
            c2_ports=list(cfg.c2_ports),
            scan_ports=list(cfg.scan_ports),
            parents=list(cfg.parents),
            users=list(cfg.users),
            countries=countries,
        )

    def summary(self) -> dict[str, object]:
        """Compact description of the pools for the run manifest."""

        return {
            "internal_hosts": len(self.internal_hosts),
            "internal_targets": len(self.internal_targets),
            "sweep_hosts": len(self.sweep_hosts),
            "adversary_external": len(self.adversary_external),
            "benign_external": len(self.benign_external),
            "resolver": self.resolver,
            "parents": self.parents,
            "user_pool": len(self.users),
        }
