from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..models import Finding, Service, Target


class Phase(enum.IntEnum):
    DISCOVERY = 1
    PORTSCAN = 2
    SERVICE_ID = 3
    ENUM = 4
    VULN = 5
    CREDS = 6
    REPORT = 7


@dataclass
class HostContext:
    target: Target
    outdir: Path
    config: Config
    lab: bool = False
    brute: bool = False
    available: set[str] = field(default_factory=set)
    ports_mode: str = "top"
    open_ports: list[int] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)

    def services_named(self, *names: str) -> list[Service]:
        wanted = set(names)
        return [s for s in self.services if s.name in wanted]

    def http_services(self) -> list[Service]:
        out: list[Service] = []
        for s in self.services:
            if "http" in s.name or s.tunnel == "ssl" or s.port in {80, 443}:
                out.append(s)
        return out


def http_url(host: str, s: Service) -> str:
    """Base URL for an HTTP(S) service on host. Shared by http/vuln plugins."""
    https = s.tunnel == "ssl" or "https" in s.name or s.port == 443
    return f"{'https' if https else 'http'}://{host}:{s.port}"


class Plugin(ABC):
    name: str = "plugin"
    phase: Phase = Phase.ENUM
    lab_only: bool = False
    brute: bool = False
    requires: list[str] = []

    def matches(self, ctx: HostContext) -> bool:
        return True

    @abstractmethod
    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        ...


REGISTRY: list[type[Plugin]] = []


def register(cls: type[Plugin]) -> type[Plugin]:
    REGISTRY.append(cls)
    return cls
