from __future__ import annotations

from ..models import Finding
from .base import HostContext, Phase, Plugin, register


@register
class NetexecSpray(Plugin):
    name = "netexec"
    phase = Phase.CREDS
    lab_only = True
    brute = True
    requires = ["netexec"]

    def matches(self, ctx: HostContext) -> bool:
        return bool(ctx.services_named("microsoft-ds", "netbios-ssn"))

    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        # Null-session share listing only (spray with real creds is out of MVP scope).
        argv = ["netexec", "smb", ctx.target.host, "-u", "", "-p", "", "--shares"]
        result = await runner.run("netexec", argv, timeout=ctx.config.tool_timeout)
        return [
            Finding(
                source_tool="netexec",
                severity="info",
                title="netexec SMB null-session share check",
                detail="\n".join(result.stdout.splitlines()[:20]),
                evidence_path=result.artifact_path,
            )
        ]
