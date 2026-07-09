from __future__ import annotations

import re

from ..models import Finding
from .base import HostContext, Phase, Plugin, http_url, register

_NUCLEI_RE = re.compile(r"\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(\S+)")
_VALID_SEV = {"info", "low", "medium", "high", "critical"}


def parse_nuclei(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        m = _NUCLEI_RE.search(line)
        if not m:
            continue
        template, _proto, sev, url = m.groups()
        sev = sev.lower()
        severity = "high" if sev == "critical" else (sev if sev in _VALID_SEV else "info")
        findings.append(
            Finding(source_tool="nuclei", severity=severity, title=f"{template} @ {url}", detail=line.strip())
        )
    return findings


@register
class NucleiScan(Plugin):
    name = "nuclei"
    phase = Phase.VULN
    lab_only = True
    requires = ["nuclei"]

    def matches(self, ctx: HostContext) -> bool:
        return bool(ctx.http_services())

    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        urls = [http_url(ctx.target.host, s) for s in ctx.http_services()]
        argv = ["nuclei", "-silent", "-nc", "-u", ",".join(urls)]
        result = await runner.run("nuclei", argv, timeout=ctx.config.tool_timeout)
        findings = parse_nuclei(result.stdout)
        for f in findings:
            f.evidence_path = result.artifact_path
        return findings
