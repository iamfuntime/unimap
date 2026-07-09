from __future__ import annotations

import asyncio
import traceback
from pathlib import Path

from .config import Config
from .models import Finding, HostResult, Target
from .plugins.base import REGISTRY, HostContext, Phase, Plugin


class Engine:
    def __init__(
        self,
        config: Config,
        runner,
        *,
        lab: bool = False,
        brute: bool = False,
        available: set[str] | None = None,
        ports_mode: str = "top",
        plugins: list[Plugin] | None = None,
    ):
        self.config = config
        self.runner = runner
        self.lab = lab
        self.brute = brute
        self.available = available if available is not None else set()
        self.ports_mode = ports_mode
        self.sem = asyncio.Semaphore(max(1, config.concurrency))
        self.plugins = plugins if plugins is not None else [cls() for cls in REGISTRY]

    def _gate_ok(self, p: Plugin) -> bool:
        if p.lab_only and not self.lab:
            return False
        if p.brute and not (self.lab and self.brute):
            return False
        if any(req not in self.available for req in p.requires):
            return False
        return True

    async def _run_plugin(self, plugin: Plugin, ctx: HostContext) -> list[Finding]:
        async with self.sem:
            try:
                return await plugin.run(ctx, self.runner)
            except Exception as exc:  # surfaced as a Finding, never crashes the run
                return [
                    Finding(
                        source_tool=plugin.name,
                        severity="error",
                        title=f"{plugin.name} crashed",
                        detail=f"{exc!r}\n{traceback.format_exc()}",
                    )
                ]

    async def scan_host(self, target: Target, outdir: Path) -> HostResult:
        outdir = Path(outdir)
        (outdir / "artifacts").mkdir(parents=True, exist_ok=True)
        ctx = HostContext(
            target=target,
            outdir=outdir,
            config=self.config,
            lab=self.lab,
            brute=self.brute,
            available=set(self.available),
            ports_mode=self.ports_mode,
        )
        findings: list[Finding] = []
        for phase in sorted(Phase):
            if phase == Phase.REPORT:
                continue
            selected = [
                p for p in self.plugins
                if p.phase == phase and self._gate_ok(p) and p.matches(ctx)
            ]
            if not selected:
                continue
            results = await asyncio.gather(*(self._run_plugin(p, ctx) for p in selected))
            for group in results:
                findings.extend(group)
        artifacts = sorted(str(p) for p in (outdir / "artifacts").glob("*"))
        return HostResult(target=target, services=ctx.services, findings=findings, artifacts=artifacts)
