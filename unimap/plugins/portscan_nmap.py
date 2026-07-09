from __future__ import annotations

from ..models import Finding
from .base import HostContext, Phase, Plugin, register


def parse_nmap_grepable(text: str) -> list[int]:
    ports: set[int] = set()
    for line in text.splitlines():
        if "Ports:" not in line:
            continue
        segment = line.split("Ports:", 1)[1]
        for entry in segment.split(","):
            parts = entry.strip().split("/")
            if len(parts) >= 2 and parts[1] == "open" and parts[0].isdigit():
                ports.add(int(parts[0]))
    return sorted(ports)


@register
class NmapPortScan(Plugin):
    name = "nmap-portscan"
    phase = Phase.PORTSCAN
    requires = ["nmap"]

    def matches(self, ctx: HostContext) -> bool:
        return "rustscan" not in ctx.available

    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        scope = ["-p-"] if ctx.ports_mode == "all" else ["--top-ports", str(ctx.config.top_ports)]
        argv = ["nmap", "-sS", "-Pn", "-T4", *scope, "-oG", "-", ctx.target.host]
        result = await runner.run("nmap-portscan", argv, timeout=ctx.config.tool_timeout)
        ports = parse_nmap_grepable(result.stdout)
        ctx.open_ports = ports
        return [
            Finding(
                source_tool="nmap",
                severity="info" if ports else "low",
                title=f"{len(ports)} open ports",
                detail=", ".join(str(p) for p in ports),
                evidence_path=result.artifact_path,
            )
        ]
