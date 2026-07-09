from __future__ import annotations

from ..models import Finding
from .base import HostContext, Phase, Plugin, register


@register
class DnsNmap(Plugin):
    name = "dns-nmap"
    phase = Phase.ENUM
    requires = ["nmap"]

    def matches(self, ctx: HostContext) -> bool:
        return bool(ctx.services_named("domain", "dns"))

    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        argv = ["nmap", "-Pn", "-p53", "--script", "dns-nsid,dns-recursion", ctx.target.host]
        result = await runner.run("dns-nmap", argv, timeout=ctx.config.tool_timeout)
        return [
            Finding(
                source_tool="nmap",
                severity="info",
                title="DNS enumeration",
                detail="\n".join(result.stdout.splitlines()[:20]),
                evidence_path=result.artifact_path,
            )
        ]
