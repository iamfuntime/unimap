from __future__ import annotations

import re

from ..models import Finding
from .base import HostContext, Phase, Plugin, register

_OPEN_RE = re.compile(r"Open\s+\S+?:(\d+)")
_ARROW_RE = re.compile(r"->\s*\[([\d,\s]+)\]")


def parse_rustscan(text: str) -> list[int]:
    ports: set[int] = set()
    for m in _OPEN_RE.finditer(text):
        ports.add(int(m.group(1)))
    for m in _ARROW_RE.finditer(text):
        for token in m.group(1).split(","):
            token = token.strip()
            if token.isdigit():
                ports.add(int(token))
    return sorted(ports)


@register
class RustScanPortScan(Plugin):
    name = "rustscan"
    phase = Phase.PORTSCAN
    requires = ["rustscan"]

    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        argv = ["rustscan", "-a", ctx.target.host, "-g"]
        result = await runner.run("rustscan", argv, timeout=ctx.config.tool_timeout)
        ports = parse_rustscan(result.stdout)
        ctx.open_ports = ports
        return [
            Finding(
                source_tool="rustscan",
                severity="info" if ports else "low",
                title=f"{len(ports)} open ports",
                detail=", ".join(str(p) for p in ports),
                evidence_path=result.artifact_path,
            )
        ]
