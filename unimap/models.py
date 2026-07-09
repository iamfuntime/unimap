from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("high", "medium", "low", "info", "error")


@dataclass
class Target:
    raw: str
    host: str
    is_ip: bool = False


@dataclass
class Service:
    port: int
    proto: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    tunnel: str = ""


@dataclass
class Finding:
    source_tool: str
    severity: str
    title: str
    detail: str = ""
    evidence_path: str = ""


@dataclass
class HostResult:
    target: Target
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
