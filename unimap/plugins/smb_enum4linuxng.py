from __future__ import annotations

from ..models import Finding
from .base import HostContext, Phase, Plugin, register

_NULL_MARKERS = ("allows sessions using username ''", "Share:", "Mapping: OK")


@register
class Enum4linuxNg(Plugin):
    name = "enum4linux-ng"
    phase = Phase.ENUM
    requires = ["enum4linux-ng"]

    def matches(self, ctx: HostContext) -> bool:
        return bool(ctx.services_named("microsoft-ds", "netbios-ssn"))

    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        argv = ["enum4linux-ng", "-A", ctx.target.host]
        result = await runner.run("enum4linux-ng", argv, timeout=ctx.config.tool_timeout)
        findings: list[Finding] = [
            Finding(
                source_tool="enum4linux-ng",
                severity="info",
                title="SMB enumeration",
                detail="\n".join(result.stdout.splitlines()[:20]),
                evidence_path=result.artifact_path,
            )
        ]
        if any(m in result.stdout for m in _NULL_MARKERS):
            findings.append(
                Finding(
                    source_tool="enum4linux-ng",
                    severity="low",
                    title="SMB null session / shares accessible",
                    detail="Null-session or share access indicators found — enumerate shares and users.",
                    evidence_path=result.artifact_path,
                )
            )
        return findings
