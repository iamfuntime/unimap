from __future__ import annotations

from ..models import Finding
from .base import HostContext, Phase, Plugin, http_url, register


@register
class HttpxProbe(Plugin):
    name = "httpx"
    phase = Phase.ENUM
    requires = ["httpx"]

    def matches(self, ctx: HostContext) -> bool:
        return bool(ctx.http_services())

    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        findings: list[Finding] = []
        for s in ctx.http_services():
            url = http_url(ctx.target.host, s)
            argv = ["httpx", "-u", url, "-title", "-status-code", "-tech-detect", "-no-color", "-silent"]
            result = await runner.run(f"httpx-{s.port}", argv, timeout=ctx.config.tool_timeout)
            line = result.stdout.strip()
            if line:
                findings.append(
                    Finding(
                        source_tool="httpx",
                        severity="info",
                        title=f"HTTP probe :{s.port}",
                        detail=line.splitlines()[0][:300],
                        evidence_path=result.artifact_path,
                    )
                )
        return findings
