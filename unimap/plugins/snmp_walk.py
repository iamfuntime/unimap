from __future__ import annotations

from ..models import Finding
from .base import HostContext, Phase, Plugin, register


@register
class SnmpWalk(Plugin):
    # LATENT until UDP discovery lands: SNMP is 161/udp, but both portscanners
    # are TCP-only, so an "snmp" service is never surfaced in a real run and
    # matches() stays False. This plugin only fires once a UDP discovery step
    # (e.g. nmap -sU -p161) populates ctx.services with a udp/snmp entry.
    # See the plan's Backlog: "UDP port discovery".
    name = "snmpwalk"
    phase = Phase.ENUM
    requires = ["snmpwalk"]

    def matches(self, ctx: HostContext) -> bool:
        return bool(ctx.services_named("snmp"))

    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        findings: list[Finding] = []
        for community in ctx.config.community_strings:
            argv = ["snmpwalk", "-v2c", "-c", community, ctx.target.host]
            result = await runner.run(f"snmpwalk-{community}", argv, timeout=ctx.config.tool_timeout)
            if result.stdout.strip():
                findings.append(
                    Finding(
                        source_tool="snmpwalk",
                        severity="low",
                        title=f"SNMP readable with community '{community}'",
                        detail=result.stdout.splitlines()[0][:300],
                        evidence_path=result.artifact_path,
                    )
                )
        return findings
