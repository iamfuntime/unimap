from __future__ import annotations

import re

from ..models import Finding
from .base import HostContext, Phase, Plugin, http_url, register

_FEROX_RE = re.compile(r"^\s*(\d{3})\s+\w+\s+.*?(\d+)c\s+(https?://\S+)")


def parse_feroxbuster(text: str) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        m = _FEROX_RE.search(line)
        if m:
            rows.append((m.group(1), m.group(2), m.group(3)))
    return rows


@register
class Feroxbuster(Plugin):
    name = "feroxbuster"
    phase = Phase.ENUM
    requires = ["feroxbuster"]

    def matches(self, ctx: HostContext) -> bool:
        return bool(ctx.http_services())

    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        findings: list[Finding] = []
        for s in ctx.http_services():
            url = http_url(ctx.target.host, s)
            out_file = ctx.outdir / "artifacts" / f"ferox-{s.port}.txt"
            argv = [
                "feroxbuster", "-u", url, "-w", ctx.config.http_wordlist,
                "-q", "-k", "--no-state", "-o", str(out_file),
            ]
            result = await runner.run(f"feroxbuster-{s.port}", argv, timeout=ctx.config.tool_timeout)
            for status, size, found_url in parse_feroxbuster(result.stdout):
                findings.append(
                    Finding(
                        source_tool="feroxbuster",
                        severity="info",
                        title=f"{status} {found_url}",
                        detail=f"size={size}",
                        evidence_path=result.artifact_path,
                    )
                )
        return findings
