from __future__ import annotations

import argparse
import asyncio
import pkgutil
import sys
from importlib import import_module, resources
from pathlib import Path

from . import plugins as _plugins_pkg
from .check import available_binaries, required_binaries, run_check
from .config import load_config
from .engine import Engine
from .report import load_next_steps, write_report
from .runner import SubprocessRunner
from .targets import TargetError, parse_targets


def _load_all_plugins() -> None:
    for mod in pkgutil.iter_modules(_plugins_pkg.__path__):
        if mod.name != "base":
            import_module(f"unimap.plugins.{mod.name}")


def _load_next_steps_data() -> dict:
    with resources.as_file(resources.files("unimap.data") / "next_steps.yaml") as p:
        return load_next_steps(p)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="unimap", description="UniMap v2 recon orchestrator")
    p.add_argument("-t", "--target", help="target IP / hostname / CIDR / @file")
    p.add_argument("-o", "--outdir", default="unimap-out", help="output directory")
    p.add_argument("-c", "--config", default=None, help="YAML config path")
    p.add_argument("--concurrency", type=int, default=None, help="max concurrent tools")
    grp = p.add_mutually_exclusive_group()
    grp.add_argument("--top-ports", dest="ports_mode", action="store_const", const="top")
    grp.add_argument("--all-ports", dest="ports_mode", action="store_const", const="all")
    p.set_defaults(ports_mode="top")
    p.add_argument("--lab", action="store_true", help="unlock multi-target, vuln scans, heavier enum")
    p.add_argument("--brute", action="store_true", help="enable credential attacks (requires --lab)")
    p.add_argument("--check", action="store_true", help="report installed/missing tools and exit")
    return p


async def _run(targets, base_out: Path, config, args, available, next_steps) -> int:
    for target in targets:
        host_out = base_out / target.host
        runner = SubprocessRunner(artifact_dir=host_out / "artifacts", default_timeout=config.tool_timeout)
        engine = Engine(
            config, runner, lab=args.lab, brute=args.brute,
            available=available, ports_mode=args.ports_mode,
        )
        result = await engine.scan_host(target, host_out)
        _, md_path = write_report(result, host_out, next_steps)
        print(f"[+] {target.host}: {len(result.services)} services, "
              f"{len(result.findings)} findings -> {md_path}")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    _load_all_plugins()

    if args.check:
        return run_check()
    if not args.target:
        print("error: -t/--target is required (or use --check)", file=sys.stderr)
        return 2
    if args.brute and not args.lab:
        print("error: --brute requires --lab", file=sys.stderr)
        return 2

    config = load_config(args.config)
    if args.concurrency:
        config.concurrency = args.concurrency

    try:
        targets = parse_targets(args.target, lab=args.lab)
    except TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    available = {n for n, path in available_binaries(required_binaries()).items() if path}
    next_steps = _load_next_steps_data()
    return asyncio.run(_run(targets, Path(args.outdir), config, args, available, next_steps))
