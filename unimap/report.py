from __future__ import annotations

import json
from pathlib import Path

import yaml

from .models import HostResult, Service

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "error": 4}


def load_next_steps(path) -> dict:
    return yaml.safe_load(Path(path).read_text()) or {}


def suggested_next_steps(services: list[Service], next_steps: dict) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for s in services:
        for key in (s.name, str(s.port)):
            if key in next_steps and key not in seen:
                seen.add(key)
                out.extend(next_steps[key])
    return out


def render_markdown(result: HostResult, next_steps: dict) -> str:
    host = result.target.host
    lines = [f"# UniMap Report — {host}", "", f"Original target: `{result.target.raw}`", ""]

    lines += ["## Open Services", ""]
    if result.services:
        lines += ["| Port | Proto | Service | Product | Version |",
                  "|------|-------|---------|---------|---------|"]
        for s in sorted(result.services, key=lambda x: x.port):
            lines.append(f"| {s.port} | {s.proto} | {s.name} | {s.product} | {s.version} |")
    else:
        lines.append("_No open services found._")
    lines.append("")

    lines += ["## Findings", ""]
    ordered = sorted(result.findings, key=lambda f: _SEV_ORDER.get(f.severity, 9))
    if ordered:
        for f in ordered:
            lines.append(f"- **[{f.severity}] {f.title}** ({f.source_tool})")
            if f.detail:
                lines.append(f"  - {f.detail.splitlines()[0][:300]}")
    else:
        lines.append("_No findings._")
    lines.append("")

    steps = [s.replace("{host}", host) for s in suggested_next_steps(result.services, next_steps)]
    lines += ["## Suggested Next Steps", ""]
    if steps:
        lines += [f"- [ ] {st}" for st in steps]
    else:
        lines.append("_No suggestions for the discovered services._")
    lines.append("")
    return "\n".join(lines)


def write_report(result: HostResult, outdir, next_steps: dict) -> tuple[Path, Path]:
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / "result.json"
    md_path = outdir / "report.md"
    json_path.write_text(json.dumps(result.to_dict(), indent=2))
    md_path.write_text(render_markdown(result, next_steps))
    return json_path, md_path
