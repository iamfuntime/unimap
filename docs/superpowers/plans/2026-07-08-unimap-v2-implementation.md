# UniMap v2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild UniMap as a Python 3.10+ asyncio recon orchestrator with a phased plugin engine, structured output, and a mockable subprocess layer that makes the whole suite testable without any pentest tools installed.

**Architecture:** Primitives (`models`, `targets`, `config`, `runner`) sit under a plugin framework (`plugins/base.py` = `Phase` enum + `Plugin` ABC + registry). Each tool is one plugin file that reads a shared mutable `HostContext`, calls the injected runner, parses output, and returns `Finding`s. `engine.py` walks phases in order (barrier between phases so service-id can consume portscan results), running matching+gated plugins concurrently under a semaphore. `report.py` renders JSON + Markdown; `cli.py` wires it together.

**Tech Stack:** Python 3.12 (WSL Ubuntu-24.04), `asyncio`, `pyyaml`, `pytest`, `xml.etree` for nmap XML, stdlib `ipaddress`/`socket` for targets.

## Global Constraints

- Python **>= 3.10** (target runtime 3.12.3). Use `from __future__ import annotations` in every module so `list[int]` / `X | None` annotations work.
- **Runtime is WSL `Ubuntu-24.04`.** Invoke via the PowerShell tool: `wsl -d Ubuntu-24.04 bash "/mnt/c/Users/Seth Feldman/git/unimap/scripts/dev.sh" <cmd>`. Never call `wsl` through the Git Bash tool (it mangles `/mnt/c` paths and expands `$vars`).
- **No `shell=True`, ever.** All process spawns go through `runner.py` using `asyncio.create_subprocess_exec` with argv lists.
- **Reconnaissance/enumeration only** — no exploitation. Vuln scanning is `--lab`-gated; credential attacks are `--lab --brute`-gated (double gate).
- **Only `nmap` missing is fatal at scan time** (portscan fallback). Every other missing tool disables its plugin via the `requires` gate.
- Dependencies stay minimal: `pyyaml` only for runtime (add `rich` later when structured logging lands — deferred, YAGNI).
- Frequent commits: one commit per task, message prefix `feat:` / `test:` / `chore:`.

---

## File Structure

```
unimap/                              # repo root (Windows FS)
  pyproject.toml                     # Task 1
  scripts/dev.sh                     # Task 1 — WSL venv/test/run harness
  conftest.py                        # Task 1 — puts repo root on sys.path
  unimap/                            # package
    __init__.py                      # Task 1
    __main__.py                      # Task 15
    models.py                        # Task 2 — Target/Service/Finding/HostResult
    targets.py                       # Task 3 — parse_targets + TargetError
    config.py                        # Task 4 — Config + load_config
    runner.py                        # Task 5 — ToolResult + SubprocessRunner
    engine.py                        # Task 12 — Engine (phased scheduler)
    report.py                        # Task 13 — render + write_report
    check.py                         # Task 14 — doctor / availability
    cli.py                           # Task 15 — argparse + wiring
    data/
      __init__.py                    # Task 13 (importlib.resources anchor)
      next_steps.yaml                # Task 13
    plugins/
      __init__.py                    # Task 1
      base.py                        # Task 6 — Phase/Plugin/HostContext/registry
      servicescan_nmap.py            # Task 7
      portscan_rustscan.py           # Task 8
      portscan_nmap.py               # Task 8
      http_httpx.py                  # Task 9
      http_feroxbuster.py            # Task 9
      smb_enum4linuxng.py            # Task 10
      snmp_walk.py                   # Task 10
      dns_nmap.py                    # Task 10
      vuln_nuclei.py                 # Task 11
      creds_netexec.py               # Task 11
  tests/
    __init__.py                      # Task 1
    fakes.py                         # Task 5 — FakeRunner
    test_*.py                        # per task
```

---

*(Tasks follow. Each is an independently testable, independently committable unit. Implement in order — later tasks consume interfaces defined by earlier ones.)*

## Task 1: Project scaffolding & WSL dev harness

**Files:**
- Create: `pyproject.toml`, `conftest.py`, `scripts/dev.sh`
- Create: `unimap/__init__.py`, `unimap/plugins/__init__.py`, `tests/__init__.py`
- Test: `tests/test_smoke.py`

**Interfaces:**
- Produces: importable package `unimap` (version `2.0.0`); console script `unimap`; `scripts/dev.sh {setup|test|run}` harness; venv at `~/.venvs/unimap` inside WSL.

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "unimap"
version = "2.0.0"
description = "Async recon orchestrator for pentest labs (OSCP/CTF)"
requires-python = ">=3.10"
dependencies = ["pyyaml>=6"]

[project.optional-dependencies]
dev = ["pytest>=8"]

[project.scripts]
unimap = "unimap.cli:main"

[tool.setuptools.packages.find]
include = ["unimap*"]

[tool.setuptools.package-data]
"unimap.data" = ["*.yaml"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Create package init files**

`unimap/__init__.py`:
```python
__version__ = "2.0.0"
```
`unimap/plugins/__init__.py`: empty file.
`tests/__init__.py`: empty file.
`conftest.py` (repo root, ensures `tests` is importable as a package):
```python
# empty on purpose — presence makes repo root the pytest rootdir / on sys.path
```

- [ ] **Step 3: Write `scripts/dev.sh`**

```bash
#!/usr/bin/env bash
# UniMap dev harness — run inside WSL Ubuntu-24.04.
# Usage: dev.sh {setup|test|run ...}
set -euo pipefail
REPO="/mnt/c/Users/Seth Feldman/git/unimap"
VENV="$HOME/.venvs/unimap"
cd "$REPO"
case "${1:-}" in
  setup)
    python3 -m venv "$VENV"
    "$VENV/bin/pip" install --upgrade pip >/dev/null
    "$VENV/bin/pip" install -e ".[dev]"
    ;;
  test)
    shift
    "$VENV/bin/python" -m pytest "$@"
    ;;
  run)
    shift
    "$VENV/bin/python" -m unimap "$@"
    ;;
  *)
    echo "usage: dev.sh {setup|test|run ...}" >&2; exit 2 ;;
esac
```

- [ ] **Step 4: Write the smoke test** — `tests/test_smoke.py`

```python
import unimap

def test_package_version():
    assert unimap.__version__ == "2.0.0"
```

- [ ] **Step 5: Set up the venv (installs the package editable)**

From PowerShell:
`wsl -d Ubuntu-24.04 bash "/mnt/c/Users/Seth Feldman/git/unimap/scripts/dev.sh" setup`
Expected: pip finishes with `Successfully installed ... unimap-2.0.0`.

- [ ] **Step 6: Run the smoke test**

`wsl -d Ubuntu-24.04 bash "/mnt/c/Users/Seth Feldman/git/unimap/scripts/dev.sh" test tests/test_smoke.py -v`
Expected: `1 passed`.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml conftest.py scripts/dev.sh unimap/__init__.py unimap/plugins/__init__.py tests/__init__.py tests/test_smoke.py
git commit -m "chore: scaffold unimap v2 package and WSL dev harness"
```

---

## Task 2: Data models

**Files:**
- Create: `unimap/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces: `Target(raw:str, host:str, is_ip:bool=False)`; `Service(port:int, proto:str="tcp", name:str="", product:str="", version:str="", tunnel:str="")`; `Finding(source_tool:str, severity:str, title:str, detail:str="", evidence_path:str="")`; `HostResult(target:Target, services:list[Service]=[], findings:list[Finding]=[], artifacts:list[str]=[])` with `.to_dict() -> dict`.

- [ ] **Step 1: Write the failing test** — `tests/test_models.py`

```python
import json
from unimap.models import Target, Service, Finding, HostResult

def test_hostresult_to_dict_roundtrips():
    t = Target(raw="10.10.10.10", host="10.10.10.10", is_ip=True)
    r = HostResult(
        target=t,
        services=[Service(port=80, proto="tcp", name="http")],
        findings=[Finding(source_tool="nmap", severity="info", title="port 80 open")],
        artifacts=["scan.txt"],
    )
    d = r.to_dict()
    assert d["target"]["host"] == "10.10.10.10"
    assert d["services"][0]["port"] == 80
    assert d["findings"][0]["severity"] == "info"
    assert d["artifacts"] == ["scan.txt"]

def test_hostresult_json_serializable():
    r = HostResult(target=Target(raw="h", host="h"))
    assert json.dumps(r.to_dict())  # must not raise

def test_defaults_are_independent():
    a = HostResult(target=Target(raw="a", host="a"))
    b = HostResult(target=Target(raw="b", host="b"))
    a.findings.append(Finding("t", "info", "x"))
    assert b.findings == []  # default_factory, not shared mutable
```

- [ ] **Step 2: Run to verify it fails**

`dev.sh test tests/test_models.py -v` → FAIL (`ModuleNotFoundError: unimap.models`).

- [ ] **Step 3: Write `unimap/models.py`**

```python
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("high", "medium", "low", "info", "error")


@dataclass
class Target:
    raw: str
    host: str
    is_ip: bool = False


@dataclass
class Service:
    port: int
    proto: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    tunnel: str = ""


@dataclass
class Finding:
    source_tool: str
    severity: str
    title: str
    detail: str = ""
    evidence_path: str = ""


@dataclass
class HostResult:
    target: Target
    services: list[Service] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
```

- [ ] **Step 4: Run to verify it passes**

`dev.sh test tests/test_models.py -v` → `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add unimap/models.py tests/test_models.py
git commit -m "feat: add core data models (Target/Service/Finding/HostResult)"
```

---

## Task 3: Target parsing & normalization

**Files:**
- Create: `unimap/targets.py`
- Test: `tests/test_targets.py`

**Interfaces:**
- Consumes: `Target` from `unimap.models`.
- Produces: `TargetError(Exception)`; `parse_targets(spec:str, *, lab:bool, resolve=<callable host->list[str]>, read_file=<callable path->str>) -> list[Target]`. Enforces single-host unless `lab`. CIDR and `@file` require `lab`.

- [ ] **Step 1: Write the failing test** — `tests/test_targets.py`

```python
import pytest
from unimap.targets import parse_targets, TargetError

def test_single_ipv4_default():
    ts = parse_targets("10.10.10.10", lab=False)
    assert len(ts) == 1
    assert ts[0].host == "10.10.10.10"
    assert ts[0].is_ip is True

def test_cidr_rejected_without_lab():
    with pytest.raises(TargetError):
        parse_targets("10.10.10.0/30", lab=False)

def test_cidr_expands_in_lab():
    ts = parse_targets("10.10.10.0/30", lab=True)
    assert [t.host for t in ts] == ["10.10.10.1", "10.10.10.2"]

def test_file_input_lab(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("10.0.0.1\n10.0.0.2\n")
    ts = parse_targets(f"@{f}", lab=True)
    assert [t.host for t in ts] == ["10.0.0.1", "10.0.0.2"]

def test_file_input_rejected_without_lab(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("10.0.0.1\n")
    with pytest.raises(TargetError):
        parse_targets(f"@{f}", lab=False)

def test_multiple_hosts_rejected_without_lab():
    with pytest.raises(TargetError):
        parse_targets("10.0.0.1,10.0.0.2", lab=False)

def test_hostname_resolves():
    ts = parse_targets("example.com", lab=False, resolve=lambda h: ["93.184.216.34"])
    assert ts[0].host == "93.184.216.34"
    assert ts[0].raw == "example.com"

def test_blank_and_comment_lines_skipped(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("# header\n10.0.0.1\n\n")
    ts = parse_targets(f"@{f}", lab=True)
    assert [t.host for t in ts] == ["10.0.0.1"]
```

- [ ] **Step 2: Run to verify it fails** — `dev.sh test tests/test_targets.py -v` → FAIL (import error).

- [ ] **Step 3: Write `unimap/targets.py`**

```python
from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from typing import Callable

from .models import Target


class TargetError(Exception):
    pass


def _default_resolve(host: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for info in socket.getaddrinfo(host, None):
        addr = info[4][0]
        if addr not in seen:
            seen.add(addr)
            out.append(addr)
    return out


def _default_read_file(path: str) -> str:
    return Path(path).read_text()


def _expand_token(token: str, *, lab: bool, resolve: Callable[[str], list[str]]) -> list[Target]:
    token = token.strip()
    if not token or token.startswith("#"):
        return []
    if "/" in token:
        if not lab:
            raise TargetError(f"CIDR '{token}' requires --lab")
        net = ipaddress.ip_network(token, strict=False)
        hosts = list(net.hosts()) or [net.network_address]
        return [Target(raw=token, host=str(ip), is_ip=True) for ip in hosts]
    try:
        ip = ipaddress.ip_address(token)
        return [Target(raw=token, host=str(ip), is_ip=True)]
    except ValueError:
        pass
    addrs = resolve(token)
    if not addrs:
        raise TargetError(f"could not resolve '{token}'")
    return [Target(raw=token, host=addrs[0], is_ip=True)]


def parse_targets(
    spec: str,
    *,
    lab: bool,
    resolve: Callable[[str], list[str]] = _default_resolve,
    read_file: Callable[[str], str] = _default_read_file,
) -> list[Target]:
    targets: list[Target] = []
    if spec.startswith("@"):
        if not lab:
            raise TargetError("file input (@file) requires --lab")
        for line in read_file(spec[1:]).splitlines():
            targets.extend(_expand_token(line, lab=lab, resolve=resolve))
    else:
        for token in spec.split(","):
            targets.extend(_expand_token(token, lab=lab, resolve=resolve))
    if not targets:
        raise TargetError("no valid targets parsed")
    if not lab and len(targets) > 1:
        raise TargetError("multiple targets require --lab (exam-compliant mode is single-host)")
    return targets
```

- [ ] **Step 4: Run to verify it passes** — `dev.sh test tests/test_targets.py -v` → `8 passed`.

- [ ] **Step 5: Commit**

```bash
git add unimap/targets.py tests/test_targets.py
git commit -m "feat: add target parsing with single-host/lab gating"
```

---

## Task 4: Configuration

**Files:**
- Create: `unimap/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `Config` dataclass with fields `concurrency:int=5`, `tool_timeout:int=300`, `top_ports:int=1000`, `http_wordlist:str`, `community_strings:list[str]=["public","private"]`, `tools:dict[str,str]={}`. `load_config(path:str|None) -> Config` merges a YAML file over defaults, ignoring unknown keys.

- [ ] **Step 1: Write the failing test** — `tests/test_config.py`

```python
from unimap.config import Config, load_config

def test_defaults():
    c = load_config(None)
    assert c.concurrency == 5
    assert c.tool_timeout == 300
    assert c.community_strings == ["public", "private"]

def test_yaml_overrides(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("concurrency: 12\ntool_timeout: 60\n")
    c = load_config(str(p))
    assert c.concurrency == 12
    assert c.tool_timeout == 60
    assert c.community_strings == ["public", "private"]  # untouched default

def test_unknown_keys_ignored(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("bogus_key: 1\nconcurrency: 3\n")
    c = load_config(str(p))
    assert c.concurrency == 3
    assert not hasattr(c, "bogus_key")
```

- [ ] **Step 2: Run to verify it fails** — `dev.sh test tests/test_config.py -v` → FAIL (import error).

- [ ] **Step 3: Write `unimap/config.py`**

```python
from __future__ import annotations

from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Config:
    concurrency: int = 5
    tool_timeout: int = 300
    top_ports: int = 1000
    http_wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"
    community_strings: list[str] = field(default_factory=lambda: ["public", "private"])
    tools: dict[str, str] = field(default_factory=dict)


def load_config(path: str | None) -> Config:
    cfg = Config()
    if not path:
        return cfg
    data: dict[str, Any] = yaml.safe_load(Path(path).read_text()) or {}
    known = {f.name for f in fields(Config)}
    for key, value in data.items():
        if key in known:
            setattr(cfg, key, value)
    return cfg
```

- [ ] **Step 4: Run to verify it passes** — `dev.sh test tests/test_config.py -v` → `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add unimap/config.py tests/test_config.py
git commit -m "feat: add YAML-backed configuration with sane defaults"
```

---

## Task 5: Async subprocess runner + FakeRunner

**Files:**
- Create: `unimap/runner.py`
- Create: `tests/fakes.py`
- Test: `tests/test_runner.py`

**Interfaces:**
- Produces: `ToolResult(name, argv, returncode, stdout, stderr, artifact_path, timed_out=False)` (dataclass); `SubprocessRunner(artifact_dir, default_timeout=300)` with `async run(name:str, argv:list[str], *, timeout:int|None=None) -> ToolResult`. Writes each invocation's captured output to `<artifact_dir>/<name>.txt`.
- Produces (tests): `FakeRunner(scripted:dict[str,ToolResult]|None=None)` with same `.run(...)` signature, `.set(name, *, stdout="", stderr="", returncode=0)` chainable helper, and `.calls` list of `(name, argv)`.
- **Runner contract** (structural, used everywhere): any object with `async run(name, argv, *, timeout=None) -> ToolResult`.

- [ ] **Step 1: Write the failing test** — `tests/test_runner.py`

```python
import asyncio
import sys
from pathlib import Path

from unimap.runner import SubprocessRunner


def test_runner_captures_stdout(tmp_path):
    runner = SubprocessRunner(artifact_dir=tmp_path)
    res = asyncio.run(runner.run("echo", [sys.executable, "-c", "print('hello')"]))
    assert res.returncode == 0
    assert "hello" in res.stdout
    assert Path(res.artifact_path).exists()
    assert "hello" in Path(res.artifact_path).read_text()


def test_runner_missing_binary_returns_127(tmp_path):
    runner = SubprocessRunner(artifact_dir=tmp_path)
    res = asyncio.run(runner.run("nope", ["definitely-not-a-real-binary-xyz"]))
    assert res.returncode == 127
    assert res.timed_out is False


def test_runner_timeout(tmp_path):
    runner = SubprocessRunner(artifact_dir=tmp_path, default_timeout=1)
    res = asyncio.run(
        runner.run("sleep", [sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    )
    assert res.timed_out is True
    assert res.returncode != 0
```

- [ ] **Step 2: Run to verify it fails** — `dev.sh test tests/test_runner.py -v` → FAIL (import error).

- [ ] **Step 3: Write `unimap/runner.py`**

```python
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ToolResult:
    name: str
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    artifact_path: str
    timed_out: bool = False


class SubprocessRunner:
    def __init__(self, artifact_dir, default_timeout: int = 300):
        self.artifact_dir = Path(artifact_dir)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.default_timeout = default_timeout

    async def run(self, name: str, argv: list[str], *, timeout: int | None = None) -> ToolResult:
        timeout = timeout or self.default_timeout
        artifact = self.artifact_dir / f"{name}.txt"
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            artifact.write_text(f"$ {' '.join(argv)}\n[error] binary not found\n")
            return ToolResult(name, list(argv), 127, "", "binary not found", str(artifact))

        timed_out = False
        try:
            out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            rc = proc.returncode if proc.returncode is not None else -1
        except asyncio.TimeoutError:
            timed_out = True
            proc.kill()
            await proc.wait()
            out_b, err_b, rc = b"", b"", -9

        stdout = out_b.decode(errors="replace")
        stderr = err_b.decode(errors="replace")
        artifact.write_text(
            f"$ {' '.join(argv)}\n\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n"
            + ("\n[timed out]\n" if timed_out else "")
        )
        return ToolResult(name, list(argv), rc, stdout, stderr, str(artifact), timed_out)
```

- [ ] **Step 4: Write `tests/fakes.py`**

```python
from __future__ import annotations

from unimap.runner import ToolResult


class FakeRunner:
    """Scripted stand-in for SubprocessRunner — no real processes."""

    def __init__(self, scripted: dict[str, ToolResult] | None = None):
        self.scripted: dict[str, ToolResult] = scripted or {}
        self.calls: list[tuple[str, list[str]]] = []

    def set(self, name: str, *, stdout: str = "", stderr: str = "", returncode: int = 0) -> "FakeRunner":
        self.scripted[name] = ToolResult(name, [name], returncode, stdout, stderr, f"/fake/{name}.txt")
        return self

    async def run(self, name: str, argv: list[str], *, timeout: int | None = None) -> ToolResult:
        self.calls.append((name, list(argv)))
        r = self.scripted.get(name)
        if r is not None:
            return ToolResult(name, list(argv), r.returncode, r.stdout, r.stderr, r.artifact_path, r.timed_out)
        return ToolResult(name, list(argv), 0, "", "", f"/fake/{name}.txt")
```

- [ ] **Step 5: Run to verify it passes** — `dev.sh test tests/test_runner.py -v` → `3 passed`.

- [ ] **Step 6: Commit**

```bash
git add unimap/runner.py tests/fakes.py tests/test_runner.py
git commit -m "feat: add async subprocess runner and FakeRunner test double"
```

---

## Task 6: Plugin framework (base)

**Files:**
- Create: `unimap/plugins/base.py`
- Test: `tests/test_base.py`

**Interfaces:**
- Consumes: `Target`, `Service`, `Finding` (models); `Config`.
- Produces:
  - `Phase(IntEnum)`: `DISCOVERY=1, PORTSCAN=2, SERVICE_ID=3, ENUM=4, VULN=5, CREDS=6, REPORT=7`.
  - `HostContext(target, outdir:Path, config:Config, lab=False, brute=False, available:set[str]={}, ports_mode="top", open_ports:list[int]=[], services:list[Service]=[])` with `.services_named(*names)->list[Service]` and `.http_services()->list[Service]`.
  - `Plugin(ABC)` with class attrs `name:str`, `phase:Phase`, `lab_only:bool=False`, `brute:bool=False`, `requires:list[str]=[]`; methods `matches(ctx)->bool` (default `True`) and `abstract async run(ctx, runner)->list[Finding]`.
  - `http_url(host:str, s:Service)->str` — module-level helper returning the base URL for an HTTP(S) service (`https` when `tunnel=="ssl"` or `"https" in name` or `port==443`). Shared by the httpx/feroxbuster/nuclei plugins so the scheme rule lives in one place.
  - `REGISTRY:list[type[Plugin]]` and `register(cls)` decorator.
- **Pipeline contract:** plugins communicate state by *mutating* `ctx` — portscan sets `ctx.open_ports`, service-id appends to `ctx.services`; `run()` returns only `Finding`s.

- [ ] **Step 1: Write the failing test** — `tests/test_base.py`

```python
from pathlib import Path

from unimap.config import Config
from unimap.models import Service, Target
from unimap.plugins.base import REGISTRY, HostContext, Phase, Plugin, http_url, register


def _ctx():
    return HostContext(target=Target(raw="h", host="h"), outdir=Path("."), config=Config())


def test_phase_ordering():
    assert Phase.PORTSCAN < Phase.SERVICE_ID < Phase.ENUM < Phase.VULN < Phase.CREDS


def test_http_url_scheme():
    assert http_url("10.0.0.1", Service(port=80, name="http")) == "http://10.0.0.1:80"
    assert http_url("10.0.0.1", Service(port=443, name="https", tunnel="ssl")) == "https://10.0.0.1:443"
    assert http_url("10.0.0.1", Service(port=8080, name="http-proxy")) == "http://10.0.0.1:8080"


def test_register_adds_to_registry():
    before = len(REGISTRY)

    @register
    class Dummy(Plugin):
        name = "dummy"
        phase = Phase.ENUM

        async def run(self, ctx, runner):
            return []

    assert len(REGISTRY) == before + 1
    assert Dummy in REGISTRY


def test_http_services_filter():
    ctx = _ctx()
    ctx.services = [
        Service(port=80, name="http"),
        Service(port=22, name="ssh"),
        Service(port=8443, name="https"),
        Service(port=8080, name="http-proxy"),
    ]
    assert sorted(s.port for s in ctx.http_services()) == [80, 8080, 8443]


def test_services_named():
    ctx = _ctx()
    ctx.services = [Service(port=445, name="microsoft-ds"), Service(port=22, name="ssh")]
    assert [s.port for s in ctx.services_named("microsoft-ds", "netbios-ssn")] == [445]


def test_plugin_is_abstract():
    import pytest

    with pytest.raises(TypeError):
        Plugin()  # abstract run()
```

- [ ] **Step 2: Run to verify it fails** — `dev.sh test tests/test_base.py -v` → FAIL (import error).

- [ ] **Step 3: Write `unimap/plugins/base.py`**

```python
from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..models import Finding, Service, Target


class Phase(enum.IntEnum):
    DISCOVERY = 1
    PORTSCAN = 2
    SERVICE_ID = 3
    ENUM = 4
    VULN = 5
    CREDS = 6
    REPORT = 7


_HTTP_NAMES = {"http", "https", "http-proxy", "http-alt", "https-alt", "ssl/http"}


@dataclass
class HostContext:
    target: Target
    outdir: Path
    config: Config
    lab: bool = False
    brute: bool = False
    available: set[str] = field(default_factory=set)
    ports_mode: str = "top"
    open_ports: list[int] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)

    def services_named(self, *names: str) -> list[Service]:
        wanted = set(names)
        return [s for s in self.services if s.name in wanted]

    def http_services(self) -> list[Service]:
        out: list[Service] = []
        for s in self.services:
            if s.name in _HTTP_NAMES or "http" in s.name or s.tunnel == "ssl":
                out.append(s)
        return out


def http_url(host: str, s: Service) -> str:
    """Base URL for an HTTP(S) service on host. Shared by http/vuln plugins."""
    https = s.tunnel == "ssl" or "https" in s.name or s.port == 443
    return f"{'https' if https else 'http'}://{host}:{s.port}"


class Plugin(ABC):
    name: str = "plugin"
    phase: Phase = Phase.ENUM
    lab_only: bool = False
    brute: bool = False
    requires: list[str] = []

    def matches(self, ctx: HostContext) -> bool:
        return True

    @abstractmethod
    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        ...


REGISTRY: list[type[Plugin]] = []


def register(cls: type[Plugin]) -> type[Plugin]:
    REGISTRY.append(cls)
    return cls
```

- [ ] **Step 4: Run to verify it passes** — `dev.sh test tests/test_base.py -v` → `6 passed`.

- [ ] **Step 5: Commit**

```bash
git add unimap/plugins/base.py tests/test_base.py
git commit -m "feat: add plugin framework (Phase, Plugin, HostContext, registry)"
```

---

## Task 7: nmap service-ID plugin (XML parser)

**Files:**
- Create: `unimap/plugins/servicescan_nmap.py`
- Test: `tests/test_servicescan_nmap.py`

**Interfaces:**
- Consumes: `HostContext.open_ports`, `runner`, `ctx.services` (appends).
- Produces: `parse_nmap_xml(xml_text:str) -> tuple[list[Service], list[Finding]]`; plugin class `NmapServiceScan` (`phase=SERVICE_ID`, `requires=["nmap"]`, matches when `ctx.open_ports`). Runs `nmap -sV -sC -Pn -p <ports> -oX <file>`; parses XML from the `-oX` file if present, else from stdout (mocked runs); extends `ctx.services`; returns one info `Finding` per service plus one per NSE script.

- [ ] **Step 1: Write the failing test** — `tests/test_servicescan_nmap.py`

```python
import asyncio
from pathlib import Path

from unimap.config import Config
from unimap.models import Target
from unimap.plugins.base import HostContext
from unimap.plugins.servicescan_nmap import NmapServiceScan, parse_nmap_xml
from tests.fakes import FakeRunner

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <ports>
   <port protocol="tcp" portid="22">
     <state state="open"/>
     <service name="ssh" product="OpenSSH" version="8.9p1"/>
   </port>
   <port protocol="tcp" portid="80">
     <state state="open"/>
     <service name="http" product="Apache httpd" version="2.4.52"/>
     <script id="http-title" output="Test Page"/>
   </port>
   <port protocol="tcp" portid="443">
     <state state="closed"/>
     <service name="https"/>
   </port>
  </ports>
 </host>
</nmaprun>"""


def test_parse_services_and_scripts():
    services, findings = parse_nmap_xml(NMAP_XML)
    assert [s.port for s in services] == [22, 80]
    ssh = services[0]
    assert ssh.name == "ssh" and ssh.product == "OpenSSH" and ssh.version == "8.9p1"
    assert any("http-title" in f.title for f in findings)


def test_parse_skips_closed_ports():
    services, _ = parse_nmap_xml(NMAP_XML)
    assert 443 not in [s.port for s in services]


def test_plugin_populates_services(tmp_path):
    (tmp_path / "artifacts").mkdir()
    ctx = HostContext(target=Target(raw="h", host="10.0.0.1"), outdir=tmp_path, config=Config())
    ctx.open_ports = [22, 80]
    runner = FakeRunner().set("nmap-service", stdout=NMAP_XML)
    findings = asyncio.run(NmapServiceScan().run(ctx, runner))
    assert [s.port for s in ctx.services] == [22, 80]
    assert any(f.source_tool == "nmap" for f in findings)


def test_plugin_matches_only_with_open_ports():
    ctx = HostContext(target=Target(raw="h", host="h"), outdir=Path("."), config=Config())
    assert NmapServiceScan().matches(ctx) is False
    ctx.open_ports = [80]
    assert NmapServiceScan().matches(ctx) is True
```

- [ ] **Step 2: Run to verify it fails** — `dev.sh test tests/test_servicescan_nmap.py -v` → FAIL (import error).

- [ ] **Step 3: Write `unimap/plugins/servicescan_nmap.py`**

```python
from __future__ import annotations

import xml.etree.ElementTree as ET

from ..models import Finding, Service
from .base import HostContext, Phase, Plugin, register


def parse_nmap_xml(xml_text: str) -> tuple[list[Service], list[Finding]]:
    services: list[Service] = []
    findings: list[Finding] = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port.get("portid", "0"))
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            name = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            tunnel = svc.get("tunnel", "") if svc is not None else ""
            services.append(
                Service(port=portid, proto=proto, name=name, product=product, version=version, tunnel=tunnel)
            )
            for script in port.findall("script"):
                findings.append(
                    Finding(
                        source_tool="nmap",
                        severity="info",
                        title=f"{portid}/{proto} {script.get('id')}",
                        detail=(script.get("output") or "").strip(),
                    )
                )
    return services, findings


@register
class NmapServiceScan(Plugin):
    name = "nmap-service"
    phase = Phase.SERVICE_ID
    requires = ["nmap"]

    def matches(self, ctx: HostContext) -> bool:
        return bool(ctx.open_ports)

    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        ports = ",".join(str(p) for p in sorted(ctx.open_ports))
        xml_path = ctx.outdir / "artifacts" / "nmap-service.xml"
        argv = ["nmap", "-sV", "-sC", "-Pn", "-p", ports, "-oX", str(xml_path), ctx.target.host]
        result = await runner.run("nmap-service", argv, timeout=ctx.config.tool_timeout)
        try:
            xml_text = xml_path.read_text()
        except FileNotFoundError:
            xml_text = result.stdout
        try:
            services, script_findings = parse_nmap_xml(xml_text)
        except ET.ParseError:
            return [
                Finding(
                    source_tool="nmap",
                    severity="error",
                    title="nmap XML parse failed",
                    detail=result.stderr[:500],
                    evidence_path=result.artifact_path,
                )
            ]
        ctx.services.extend(services)
        findings: list[Finding] = []
        for s in services:
            findings.append(
                Finding(
                    source_tool="nmap",
                    severity="info",
                    title=f"{s.port}/{s.proto} {s.name}".strip(),
                    detail=" ".join(x for x in (s.product, s.version) if x),
                    evidence_path=result.artifact_path,
                )
            )
        for f in script_findings:
            f.evidence_path = result.artifact_path
            findings.append(f)
        return findings
```

- [ ] **Step 4: Run to verify it passes** — `dev.sh test tests/test_servicescan_nmap.py -v` → `4 passed`.

- [ ] **Step 5: Commit**

```bash
git add unimap/plugins/servicescan_nmap.py tests/test_servicescan_nmap.py
git commit -m "feat: add nmap service-id plugin with XML parser"
```

---

## Task 8: Portscan plugins (rustscan + nmap fallback)

**Files:**
- Create: `unimap/plugins/portscan_rustscan.py`, `unimap/plugins/portscan_nmap.py`
- Test: `tests/test_portscan.py`

**Interfaces:**
- Consumes: `runner`, `ctx.available`, `ctx.ports_mode`, `ctx.config.top_ports`; sets `ctx.open_ports`.
- Produces: `parse_rustscan(text)->list[int]`; `RustScanPortScan` (`phase=PORTSCAN`, `requires=["rustscan"]`, always matches). `parse_nmap_grepable(text)->list[int]`; `NmapPortScan` (`phase=PORTSCAN`, `requires=["nmap"]`, matches only when `"rustscan" not in ctx.available` — prevents double-run).

- [ ] **Step 1: Write the failing test** — `tests/test_portscan.py`

```python
import asyncio
from pathlib import Path

from unimap.config import Config
from unimap.models import Target
from unimap.plugins.base import HostContext
from unimap.plugins.portscan_rustscan import RustScanPortScan, parse_rustscan
from unimap.plugins.portscan_nmap import NmapPortScan, parse_nmap_grepable
from tests.fakes import FakeRunner


def _ctx(**kw):
    return HostContext(target=Target(raw="h", host="10.0.0.1"), outdir=Path("."), config=Config(), **kw)


def test_parse_rustscan_arrow_format():
    assert parse_rustscan("10.0.0.1 -> [22,80,443]") == [22, 80, 443]


def test_parse_rustscan_open_format():
    text = "Open 10.0.0.1:22\nOpen 10.0.0.1:80\n"
    assert parse_rustscan(text) == [22, 80]


def test_rustscan_sets_open_ports():
    ctx = _ctx()
    runner = FakeRunner().set("rustscan", stdout="10.0.0.1 -> [22,80]")
    findings = asyncio.run(RustScanPortScan().run(ctx, runner))
    assert ctx.open_ports == [22, 80]
    assert findings[0].source_tool == "rustscan"


def test_parse_nmap_grepable():
    text = "Host: 10.0.0.1 () Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 443/closed/tcp//https///\n"
    assert parse_nmap_grepable(text) == [22, 80]


def test_nmap_fallback_matches_only_without_rustscan():
    p = NmapPortScan()
    assert p.matches(_ctx(available={"nmap"})) is True
    assert p.matches(_ctx(available={"nmap", "rustscan"})) is False


def test_nmap_fallback_sets_open_ports():
    ctx = _ctx(available={"nmap"})
    grep = "Host: 10.0.0.1 () Ports: 22/open/tcp//ssh///, 3306/open/tcp//mysql///\n"
    runner = FakeRunner().set("nmap-portscan", stdout=grep)
    asyncio.run(NmapPortScan().run(ctx, runner))
    assert ctx.open_ports == [22, 3306]
```

- [ ] **Step 2: Run to verify it fails** — `dev.sh test tests/test_portscan.py -v` → FAIL (import error).

- [ ] **Step 3: Write `unimap/plugins/portscan_rustscan.py`**

```python
from __future__ import annotations

import re

from ..models import Finding
from .base import HostContext, Phase, Plugin, register

_OPEN_RE = re.compile(r"Open\s+\S+?:(\d+)")
_ARROW_RE = re.compile(r"->\s*\[([\d,\s]+)\]")


def parse_rustscan(text: str) -> list[int]:
    ports: set[int] = set()
    for m in _OPEN_RE.finditer(text):
        ports.add(int(m.group(1)))
    for m in _ARROW_RE.finditer(text):
        for token in m.group(1).split(","):
            token = token.strip()
            if token.isdigit():
                ports.add(int(token))
    return sorted(ports)


@register
class RustScanPortScan(Plugin):
    name = "rustscan"
    phase = Phase.PORTSCAN
    requires = ["rustscan"]

    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        argv = ["rustscan", "-a", ctx.target.host, "-g"]
        result = await runner.run("rustscan", argv, timeout=ctx.config.tool_timeout)
        ports = parse_rustscan(result.stdout)
        ctx.open_ports = ports
        return [
            Finding(
                source_tool="rustscan",
                severity="info" if ports else "low",
                title=f"{len(ports)} open ports",
                detail=", ".join(str(p) for p in ports),
                evidence_path=result.artifact_path,
            )
        ]
```

- [ ] **Step 4: Write `unimap/plugins/portscan_nmap.py`**

```python
from __future__ import annotations

from ..models import Finding
from .base import HostContext, Phase, Plugin, register


def parse_nmap_grepable(text: str) -> list[int]:
    ports: set[int] = set()
    for line in text.splitlines():
        if "Ports:" not in line:
            continue
        segment = line.split("Ports:", 1)[1]
        for entry in segment.split(","):
            parts = entry.strip().split("/")
            if len(parts) >= 2 and parts[1] == "open" and parts[0].isdigit():
                ports.add(int(parts[0]))
    return sorted(ports)


@register
class NmapPortScan(Plugin):
    name = "nmap-portscan"
    phase = Phase.PORTSCAN
    requires = ["nmap"]

    def matches(self, ctx: HostContext) -> bool:
        return "rustscan" not in ctx.available

    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        scope = ["-p-"] if ctx.ports_mode == "all" else ["--top-ports", str(ctx.config.top_ports)]
        argv = ["nmap", "-sS", "-Pn", "-T4", *scope, "-oG", "-", ctx.target.host]
        result = await runner.run("nmap-portscan", argv, timeout=ctx.config.tool_timeout)
        ports = parse_nmap_grepable(result.stdout)
        ctx.open_ports = ports
        return [
            Finding(
                source_tool="nmap",
                severity="info" if ports else "low",
                title=f"{len(ports)} open ports",
                detail=", ".join(str(p) for p in ports),
                evidence_path=result.artifact_path,
            )
        ]
```

- [ ] **Step 5: Run to verify it passes** — `dev.sh test tests/test_portscan.py -v` → `6 passed`.

- [ ] **Step 6: Commit**

```bash
git add unimap/plugins/portscan_rustscan.py unimap/plugins/portscan_nmap.py tests/test_portscan.py
git commit -m "feat: add rustscan portscan plugin with nmap fallback"
```

---

## Task 9: HTTP enumeration plugins (httpx + feroxbuster)

**Files:**
- Create: `unimap/plugins/http_httpx.py`, `unimap/plugins/http_feroxbuster.py`
- Test: `tests/test_http_plugins.py`

**Interfaces:**
- Consumes: `ctx.http_services()`, `ctx.target.host`, `ctx.config.http_wordlist`, `ctx.outdir`.
- Produces: `HttpxProbe` (`phase=ENUM`, `requires=["httpx"]`, matches when http services present); `parse_feroxbuster(text)->list[tuple[status,size,url]]`; `Feroxbuster` (`phase=ENUM`, `requires=["feroxbuster"]`).
- **Uses** `http_url(host, service)` imported from `.base` for the scheme rule (`https` when `tunnel=="ssl"` or `"https" in name` or `port==443`, else `http`). Do NOT redefine it locally.

- [ ] **Step 1: Write the failing test** — `tests/test_http_plugins.py`

```python
import asyncio
from pathlib import Path

from unimap.config import Config
from unimap.models import Service, Target
from unimap.plugins.base import HostContext
from unimap.plugins.http_httpx import HttpxProbe
from unimap.plugins.http_feroxbuster import Feroxbuster, parse_feroxbuster
from tests.fakes import FakeRunner


def _ctx(tmp_path, services):
    (tmp_path / "artifacts").mkdir(exist_ok=True)
    ctx = HostContext(target=Target(raw="h", host="10.0.0.1"), outdir=tmp_path, config=Config())
    ctx.services = services
    return ctx


def test_httpx_probes_each_http_service(tmp_path):
    ctx = _ctx(tmp_path, [Service(port=80, name="http"), Service(port=22, name="ssh")])
    runner = FakeRunner().set("httpx-80", stdout="http://10.0.0.1:80 [200] [Apache]")
    findings = asyncio.run(HttpxProbe().run(ctx, runner))
    assert any("200" in f.detail for f in findings)
    assert [c[0] for c in runner.calls] == ["httpx-80"]  # ssh not probed


def test_httpx_matches_only_with_http():
    ctx = HostContext(target=Target(raw="h", host="h"), outdir=Path("."), config=Config())
    assert HttpxProbe().matches(ctx) is False
    ctx.services = [Service(port=80, name="http")]
    assert HttpxProbe().matches(ctx) is True


def test_parse_feroxbuster():
    line = "200      GET      100l      523w    10000c http://10.0.0.1/admin"
    rows = parse_feroxbuster(line + "\n404 GET 1l 1w 20c http://10.0.0.1/nope\n")
    assert ("200", "10000", "http://10.0.0.1/admin") in rows


def test_feroxbuster_emits_findings(tmp_path):
    ctx = _ctx(tmp_path, [Service(port=443, name="https", tunnel="ssl")])
    out = "200      GET      10l      20w     4096c https://10.0.0.1:443/login"
    runner = FakeRunner().set("feroxbuster-443", stdout=out)
    findings = asyncio.run(Feroxbuster().run(ctx, runner))
    assert any("/login" in f.title for f in findings)
    # https scheme derived from tunnel=ssl
    argv = runner.calls[0][1]
    assert any(a.startswith("https://10.0.0.1:443") for a in argv)
```

- [ ] **Step 2: Run to verify it fails** — `dev.sh test tests/test_http_plugins.py -v` → FAIL (import error).

- [ ] **Step 3: Write `unimap/plugins/http_httpx.py`**

```python
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
```

- [ ] **Step 4: Write `unimap/plugins/http_feroxbuster.py`**

```python
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
```

- [ ] **Step 5: Run to verify it passes** — `dev.sh test tests/test_http_plugins.py -v` → `4 passed`.

- [ ] **Step 6: Commit**

```bash
git add unimap/plugins/http_httpx.py unimap/plugins/http_feroxbuster.py tests/test_http_plugins.py
git commit -m "feat: add httpx and feroxbuster HTTP enumeration plugins"
```

---

## Task 10: SMB / SNMP / DNS enumeration plugins

**Files:**
- Create: `unimap/plugins/smb_enum4linuxng.py`, `unimap/plugins/snmp_walk.py`, `unimap/plugins/dns_nmap.py`
- Test: `tests/test_enum_plugins.py`

**Interfaces:**
- `Enum4linuxNg` (`phase=ENUM`, `requires=["enum4linux-ng"]`, matches on `services_named("microsoft-ds","netbios-ssn")`). Runs `enum4linux-ng -A <host>`; emits one finding capturing the first output lines, plus a `low` finding if a null-session/shares marker is seen.
- `SnmpWalk` (`phase=ENUM`, `requires=["snmpwalk"]`, matches on `services_named("snmp")`). Walks each community string; emits a finding per community that returns data.
- `DnsNmap` (`phase=ENUM`, `requires=["nmap"]`, matches on `services_named("domain","dns")`). Runs `nmap -Pn -p53 --script dns-nsid,dns-recursion <host>`; captures output.

- [ ] **Step 1: Write the failing test** — `tests/test_enum_plugins.py`

```python
import asyncio
from pathlib import Path

from unimap.config import Config
from unimap.models import Service, Target
from unimap.plugins.base import HostContext
from unimap.plugins.smb_enum4linuxng import Enum4linuxNg
from unimap.plugins.snmp_walk import SnmpWalk
from unimap.plugins.dns_nmap import DnsNmap
from tests.fakes import FakeRunner


def _ctx(tmp_path, services):
    (tmp_path / "artifacts").mkdir(exist_ok=True)
    ctx = HostContext(target=Target(raw="h", host="10.0.0.1"), outdir=tmp_path, config=Config())
    ctx.services = services
    return ctx


def test_smb_matches_on_smb_services():
    ctx = HostContext(target=Target(raw="h", host="h"), outdir=Path("."), config=Config())
    assert Enum4linuxNg().matches(ctx) is False
    ctx.services = [Service(port=445, name="microsoft-ds")]
    assert Enum4linuxNg().matches(ctx) is True


def test_smb_captures_output(tmp_path):
    ctx = _ctx(tmp_path, [Service(port=445, name="microsoft-ds")])
    runner = FakeRunner().set("enum4linux-ng", stdout="[+] Server allows sessions using username '', password ''\nShare: ADMIN$")
    findings = asyncio.run(Enum4linuxNg().run(ctx, runner))
    assert any(f.source_tool == "enum4linux-ng" for f in findings)
    assert any(f.severity == "low" for f in findings)  # null-session marker


def test_snmp_walks_each_community(tmp_path):
    ctx = _ctx(tmp_path, [Service(port=161, proto="udp", name="snmp")])
    runner = FakeRunner()
    runner.set("snmpwalk-public", stdout="SNMPv2-MIB::sysDescr.0 = STRING: Linux box")
    runner.set("snmpwalk-private", stdout="")
    findings = asyncio.run(SnmpWalk().run(ctx, runner))
    assert any("public" in f.title for f in findings)
    assert all("private" not in f.title for f in findings)  # empty walk -> no finding


def test_dns_runs_nse(tmp_path):
    ctx = _ctx(tmp_path, [Service(port=53, name="domain")])
    runner = FakeRunner().set("dns-nmap", stdout="| dns-recursion: Recursion appears to be enabled")
    findings = asyncio.run(DnsNmap().run(ctx, runner))
    assert any("dns" in f.title.lower() or f.source_tool == "nmap" for f in findings)
```

- [ ] **Step 2: Run to verify it fails** — `dev.sh test tests/test_enum_plugins.py -v` → FAIL (import error).

- [ ] **Step 3: Write `unimap/plugins/smb_enum4linuxng.py`**

```python
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
```

- [ ] **Step 4: Write `unimap/plugins/snmp_walk.py`**

```python
from __future__ import annotations

from ..models import Finding
from .base import HostContext, Phase, Plugin, register


@register
class SnmpWalk(Plugin):
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
```

- [ ] **Step 5: Write `unimap/plugins/dns_nmap.py`**

```python
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
```

- [ ] **Step 6: Run to verify it passes** — `dev.sh test tests/test_enum_plugins.py -v` → `5 passed`.

- [ ] **Step 7: Commit**

```bash
git add unimap/plugins/smb_enum4linuxng.py unimap/plugins/snmp_walk.py unimap/plugins/dns_nmap.py tests/test_enum_plugins.py
git commit -m "feat: add SMB/SNMP/DNS enumeration plugins"
```

---

## Task 11: Gated plugins — nuclei (vuln) & netexec (creds)

**Files:**
- Create: `unimap/plugins/vuln_nuclei.py`, `unimap/plugins/creds_netexec.py`
- Test: `tests/test_gated_plugins.py`

**Interfaces:**
- `NucleiScan` (`phase=VULN`, `lab_only=True`, `requires=["nuclei"]`, matches on `ctx.http_services()`). `parse_nuclei(text)` maps lines like `[template-id] [protocol] [severity] url` to findings.
- `NetexecSpray` (`phase=CREDS`, `lab_only=True`, `brute=True`, `requires=["netexec"]`, matches on SMB services). Runs a **spray** (single password across users) — emits an info finding recording the invocation (the engine gate, not the plugin, decides whether it runs).
- Gating itself (`lab_only`/`brute`) is enforced by the **engine** (Task 12), not these plugins — these tests only check `matches()`/`run()`/parse behavior.

- [ ] **Step 1: Write the failing test** — `tests/test_gated_plugins.py`

```python
import asyncio
from pathlib import Path

from unimap.config import Config
from unimap.models import Service, Target
from unimap.plugins.base import HostContext, Phase
from unimap.plugins.vuln_nuclei import NucleiScan, parse_nuclei
from unimap.plugins.creds_netexec import NetexecSpray
from tests.fakes import FakeRunner


def _ctx(tmp_path, services):
    (tmp_path / "artifacts").mkdir(exist_ok=True)
    ctx = HostContext(target=Target(raw="h", host="10.0.0.1"), outdir=tmp_path, config=Config())
    ctx.services = services
    return ctx


def test_nuclei_is_lab_gated():
    assert NucleiScan.lab_only is True
    assert NucleiScan.phase == Phase.VULN


def test_parse_nuclei_maps_severity():
    line = "[apache-detect] [http] [info] http://10.0.0.1\n[CVE-2021-1234] [http] [high] http://10.0.0.1/x"
    findings = parse_nuclei(line)
    sevs = {f.severity for f in findings}
    assert "high" in sevs and "info" in sevs


def test_nuclei_runs_on_http(tmp_path):
    ctx = _ctx(tmp_path, [Service(port=80, name="http")])
    runner = FakeRunner().set("nuclei", stdout="[CVE-2021-1234] [http] [high] http://10.0.0.1/x")
    findings = asyncio.run(NucleiScan().run(ctx, runner))
    assert any(f.severity == "high" for f in findings)


def test_netexec_is_double_gated():
    assert NetexecSpray.lab_only is True
    assert NetexecSpray.brute is True
    assert NetexecSpray.phase == Phase.CREDS


def test_netexec_matches_smb():
    ctx = HostContext(target=Target(raw="h", host="h"), outdir=Path("."), config=Config())
    assert NetexecSpray().matches(ctx) is False
    ctx.services = [Service(port=445, name="microsoft-ds")]
    assert NetexecSpray().matches(ctx) is True
```

- [ ] **Step 2: Run to verify it fails** — `dev.sh test tests/test_gated_plugins.py -v` → FAIL (import error).

- [ ] **Step 3: Write `unimap/plugins/vuln_nuclei.py`**

```python
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
        argv = ["nuclei", "-silent", "-nc", "-u", *urls]
        result = await runner.run("nuclei", argv, timeout=ctx.config.tool_timeout)
        findings = parse_nuclei(result.stdout)
        for f in findings:
            f.evidence_path = result.artifact_path
        return findings
```

- [ ] **Step 4: Write `unimap/plugins/creds_netexec.py`**

```python
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
```

- [ ] **Step 5: Run to verify it passes** — `dev.sh test tests/test_gated_plugins.py -v` → `5 passed`.

- [ ] **Step 6: Commit**

```bash
git add unimap/plugins/vuln_nuclei.py unimap/plugins/creds_netexec.py tests/test_gated_plugins.py
git commit -m "feat: add lab-gated nuclei and brute-gated netexec plugins"
```

---

## Task 12: Engine (phased scheduler)

**Files:**
- Create: `unimap/engine.py`
- Test: `tests/test_engine.py`

**Interfaces:**
- Consumes: `Config`, runner, `REGISTRY`, `Phase`, `Plugin`, `HostContext`, `HostResult`, `Target`, `Finding`.
- Produces: `Engine(config, runner, *, lab=False, brute=False, available:set[str]|None=None, ports_mode="top", plugins:list[Plugin]|None=None)` with `async scan_host(target:Target, outdir:Path) -> HostResult`.
- **Behavior:** phases run in `Phase` order (barrier between phases); within a phase, gated+matching plugins run concurrently under `Semaphore(config.concurrency)`. Gate = `lab_only ⇒ lab`, `brute ⇒ lab and brute`, `requires ⊆ available`. A plugin raising becomes an `error`-severity `Finding` (crash isolation). REPORT phase is skipped (handled by `report.py`). Default `plugins` = `[cls() for cls in REGISTRY]`.

- [ ] **Step 1: Write the failing test** — `tests/test_engine.py`

```python
import asyncio

from unimap.config import Config
from unimap.engine import Engine
from unimap.models import Finding, Service, Target
from unimap.plugins.base import HostContext, Phase, Plugin
from tests.fakes import FakeRunner


class FakePortscan(Plugin):
    name = "fps"; phase = Phase.PORTSCAN; requires = []
    async def run(self, ctx, runner):
        ctx.open_ports = [80]
        return [Finding("fps", "info", "ports")]


class FakeServiceId(Plugin):
    name = "fsi"; phase = Phase.SERVICE_ID; requires = []
    def matches(self, ctx): return bool(ctx.open_ports)
    async def run(self, ctx, runner):
        ctx.services = [Service(port=80, name="http")]
        return [Finding("fsi", "info", "svc")]


class FakeHttp(Plugin):
    name = "fhttp"; phase = Phase.ENUM; requires = []
    def matches(self, ctx): return any(s.name == "http" for s in ctx.services)
    async def run(self, ctx, runner): return [Finding("fhttp", "info", "http enum")]


class LabOnly(Plugin):
    name = "lab"; phase = Phase.VULN; lab_only = True; requires = []
    async def run(self, ctx, runner): return [Finding("lab", "info", "vuln")]


class BruteOnly(Plugin):
    name = "br"; phase = Phase.CREDS; lab_only = True; brute = True; requires = []
    async def run(self, ctx, runner): return [Finding("br", "info", "creds")]


def _engine(**kw):
    plugins = [FakePortscan(), FakeServiceId(), FakeHttp(), LabOnly(), BruteOnly()]
    return Engine(Config(), FakeRunner(), plugins=plugins, **kw)


def _scan(engine, tmp_path):
    return asyncio.run(engine.scan_host(Target(raw="h", host="h"), tmp_path))


def test_pipeline_flows_ports_to_services_to_enum(tmp_path):
    res = _scan(_engine(), tmp_path)
    titles = [f.title for f in res.findings]
    assert "ports" in titles and "svc" in titles and "http enum" in titles
    assert [s.port for s in res.services] == [80]


def test_lab_plugin_skipped_by_default(tmp_path):
    res = _scan(_engine(lab=False), tmp_path)
    assert "vuln" not in [f.title for f in res.findings]


def test_lab_plugin_runs_with_lab(tmp_path):
    res = _scan(_engine(lab=True), tmp_path)
    assert "vuln" in [f.title for f in res.findings]


def test_brute_needs_lab_and_brute(tmp_path):
    assert "creds" not in [f.title for f in _scan(_engine(lab=True), tmp_path).findings]
    assert "creds" in [f.title for f in _scan(_engine(lab=True, brute=True), tmp_path).findings]


def test_requires_gate_skips_when_tool_absent(tmp_path):
    class NeedsTool(Plugin):
        name = "nt"; phase = Phase.ENUM; requires = ["madeuptool"]
        async def run(self, ctx, runner): return [Finding("nt", "info", "ran")]
    eng = Engine(Config(), FakeRunner(), plugins=[NeedsTool()], available=set())
    assert _scan(eng, tmp_path).findings == []


def test_plugin_crash_becomes_error_finding(tmp_path):
    class Boom(Plugin):
        name = "boom"; phase = Phase.ENUM; requires = []
        async def run(self, ctx, runner): raise RuntimeError("kaboom")
    eng = Engine(Config(), FakeRunner(), plugins=[Boom()])
    res = _scan(eng, tmp_path)
    assert any(f.severity == "error" and "boom" in f.title for f in res.findings)
```

- [ ] **Step 2: Run to verify it fails** — `dev.sh test tests/test_engine.py -v` → FAIL (import error).

- [ ] **Step 3: Write `unimap/engine.py`**

```python
from __future__ import annotations

import asyncio
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
        self.sem = asyncio.Semaphore(config.concurrency)
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
                        detail=repr(exc),
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
```

- [ ] **Step 4: Run to verify it passes** — `dev.sh test tests/test_engine.py -v` → `6 passed`.

- [ ] **Step 5: Commit**

```bash
git add unimap/engine.py tests/test_engine.py
git commit -m "feat: add phased async engine with gating and crash isolation"
```

---

## Task 13: Reporting (JSON + Markdown + next-steps data)

**Files:**
- Create: `unimap/report.py`, `unimap/data/__init__.py`, `unimap/data/next_steps.yaml`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `HostResult`, `Service`.
- Produces: `load_next_steps(path)->dict`; `suggested_next_steps(services, next_steps)->list[str]` (dedup by service name then port key; returns raw `{host}` templates); `render_markdown(result, next_steps)->str`; `write_report(result, outdir, next_steps)->tuple[Path,Path]` writing `result.json` + `report.md`.
- **next_steps.yaml** keys are service names or port strings; values are lists of `{host}`-templated suggestion strings.

- [ ] **Step 1: Write the failing test** — `tests/test_report.py`

```python
import json

from unimap.models import Finding, HostResult, Service, Target
from unimap.report import render_markdown, suggested_next_steps, write_report


def _result():
    return HostResult(
        target=Target(raw="box.htb", host="10.10.10.5"),
        services=[
            Service(port=80, proto="tcp", name="http", product="Apache", version="2.4"),
            Service(port=445, proto="tcp", name="microsoft-ds"),
        ],
        findings=[
            Finding("nmap", "info", "80/tcp http"),
            Finding("rustscan", "low", "0 open ports"),
        ],
    )


NEXT = {"http": ["Browse http://{host}"], "microsoft-ds": ["Null session on {host}"]}


def test_markdown_has_services_findings_and_next_steps():
    md = render_markdown(_result(), NEXT)
    assert "# UniMap Report — 10.10.10.5" in md
    assert "| 80 | tcp | http |" in md
    assert "Browse http://10.10.10.5" in md
    assert "Null session on 10.10.10.5" in md


def test_suggested_next_steps_dedup_and_order():
    steps = suggested_next_steps(_result().services, NEXT)
    assert steps == ["Browse http://{host}", "Null session on {host}"]


def test_write_report_creates_both_files(tmp_path):
    j, m = write_report(_result(), tmp_path, NEXT)
    assert j.exists() and m.exists()
    data = json.loads(j.read_text())
    assert data["target"]["host"] == "10.10.10.5"
    assert data["services"][0]["port"] == 80


def test_empty_services_renders_placeholder():
    r = HostResult(target=Target(raw="h", host="h"))
    md = render_markdown(r, {})
    assert "No open services found" in md
```

- [ ] **Step 2: Run to verify it fails** — `dev.sh test tests/test_report.py -v` → FAIL (import error).

- [ ] **Step 3: Write `unimap/report.py`**

```python
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
```

- [ ] **Step 4: Write `unimap/data/__init__.py`** — empty file (makes `unimap.data` an importlib.resources anchor).

- [ ] **Step 5: Write `unimap/data/next_steps.yaml`**

```yaml
http:
  - "Browse http://{host} — review page source, robots.txt, comments"
  - "Content discovery: feroxbuster -u http://{host} with a larger wordlist"
https:
  - "Inspect the TLS cert for hostnames (add to /etc/hosts): openssl s_client -connect {host}:443"
  - "Browse https://{host} and content-discover"
microsoft-ds:
  - "Null session: enum4linux-ng -A {host}"
  - "Check EternalBlue: nmap -p445 --script smb-vuln-ms17-010 {host}"
  - "List shares: netexec smb {host} -u '' -p '' --shares"
netbios-ssn:
  - "Enumerate SMB: enum4linux-ng -A {host}"
ssh:
  - "Note the version and banner; only test creds if in scope (--lab --brute)"
ftp:
  - "Try anonymous login: ftp {host} (user: anonymous)"
snmp:
  - "Walk common community strings: snmpwalk -v2c -c public {host}"
domain:
  - "Attempt a zone transfer: dig axfr @{host} <domain>"
mysql:
  - "Test default/blank root creds if in scope; check version for known CVEs"
```

- [ ] **Step 6: Run to verify it passes** — `dev.sh test tests/test_report.py -v` → `4 passed`.

- [ ] **Step 7: Commit**

```bash
git add unimap/report.py unimap/data/__init__.py unimap/data/next_steps.yaml tests/test_report.py
git commit -m "feat: add JSON+Markdown reporting with suggested next steps"
```

---

## Task 14: Doctor / tool availability (`--check`)

**Files:**
- Create: `unimap/check.py`
- Test: `tests/test_check.py`

**Interfaces:**
- Consumes: `REGISTRY` (to gather `requires`), `shutil.which`.
- Produces: `INSTALL_HINTS:dict[str,str]`; `required_binaries()->set[str]` (union of every registered plugin's `requires`); `available_binaries(names=None)->dict[str,str|None]`; `run_check()->int` (prints table, returns 0).
- **Note:** `run_check` relies on plugins being imported so `REGISTRY` is populated — the CLI (Task 15) imports them before calling.

- [ ] **Step 1: Write the failing test** — `tests/test_check.py`

```python
from unimap import check


def test_available_binaries_reports_present_and_missing(monkeypatch):
    monkeypatch.setattr(check.shutil, "which", lambda n: "/usr/bin/" + n if n == "nmap" else None)
    table = check.available_binaries(["nmap", "rustscan"])
    assert table["nmap"] == "/usr/bin/nmap"
    assert table["rustscan"] is None


def test_run_check_returns_zero_and_prints(monkeypatch, capsys):
    monkeypatch.setattr(check.shutil, "which", lambda n: None)
    rc = check.run_check()
    out = capsys.readouterr().out
    assert rc == 0
    assert "tool check" in out.lower()
    assert "MISSING" in out


def test_required_binaries_nonempty_after_plugin_import():
    import unimap.plugins.servicescan_nmap  # noqa: F401 — registers a plugin needing nmap
    assert "nmap" in check.required_binaries()
```

- [ ] **Step 2: Run to verify it fails** — `dev.sh test tests/test_check.py -v` → FAIL (import error).

- [ ] **Step 3: Write `unimap/check.py`**

```python
from __future__ import annotations

import shutil

from .plugins.base import REGISTRY

INSTALL_HINTS: dict[str, str] = {
    "nmap": "apt install nmap",
    "rustscan": "cargo install rustscan  (or grab a release from github.com/RustScan/RustScan)",
    "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "feroxbuster": "apt install feroxbuster",
    "enum4linux-ng": "pipx install enum4linux-ng",
    "snmpwalk": "apt install snmp",
    "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "netexec": "pipx install netexec",
}


def required_binaries() -> set[str]:
    bins: set[str] = set()
    for cls in REGISTRY:
        bins.update(cls.requires)
    return bins


def available_binaries(names=None) -> dict[str, str | None]:
    names = names if names is not None else required_binaries()
    return {n: shutil.which(n) for n in sorted(names)}


def run_check() -> int:
    table = available_binaries()
    missing = [n for n, path in table.items() if path is None]
    print("UniMap tool check\n")
    for name, path in table.items():
        if path:
            print(f"  [+] {name}: {path}")
        else:
            hint = INSTALL_HINTS.get(name, "see the tool's docs")
            print(f"  [-] {name}: MISSING — {hint}")
    print()
    if missing:
        print(f"{len(missing)} tool(s) missing. Plugins that need them will be skipped.")
    else:
        print("All known tools present.")
    return 0
```

- [ ] **Step 4: Run to verify it passes** — `dev.sh test tests/test_check.py -v` → `3 passed`.

- [ ] **Step 5: Commit**

```bash
git add unimap/check.py tests/test_check.py
git commit -m "feat: add --check doctor for tool availability and install hints"
```

---

## Task 15: CLI & entrypoint

**Files:**
- Create: `unimap/cli.py`, `unimap/__main__.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: everything above.
- Produces: `build_parser()->argparse.ArgumentParser`; `main(argv=None)->int`. Flags: `-t/--target`, `-o/--outdir` (default `unimap-out`), `-c/--config`, `--concurrency`, `--top-ports`/`--all-ports` (mutually exclusive → `ports_mode`), `--lab`, `--brute`, `--check`.
- **Gating in CLI:** `--brute` without `--lab` → error, exit 2. `--check` short-circuits (no target needed). Missing `-t` when not `--check` → error, exit 2.
- `_load_all_plugins()` imports every `unimap/plugins/*.py` except `base` so `REGISTRY` is populated before the engine/doctor read it.

- [ ] **Step 1: Write the failing test** — `tests/test_cli.py`

```python
from unimap.cli import build_parser, main


def test_parser_defaults():
    args = build_parser().parse_args(["-t", "10.0.0.1"])
    assert args.ports_mode == "top"
    assert args.lab is False
    assert args.outdir == "unimap-out"


def test_all_ports_flag():
    args = build_parser().parse_args(["-t", "10.0.0.1", "--all-ports"])
    assert args.ports_mode == "all"


def test_brute_requires_lab(capsys):
    rc = main(["-t", "10.0.0.1", "--brute"])
    assert rc == 2
    assert "requires --lab" in capsys.readouterr().err


def test_missing_target_without_check(capsys):
    rc = main([])
    assert rc == 2
    assert "target" in capsys.readouterr().err.lower()


def test_check_mode_short_circuits(monkeypatch, capsys):
    import unimap.check as check
    monkeypatch.setattr(check.shutil, "which", lambda n: None)
    rc = main(["--check"])
    assert rc == 0
    assert "tool check" in capsys.readouterr().out.lower()


def test_full_run_with_no_tools_writes_report(monkeypatch, tmp_path, capsys):
    # No tools available -> every plugin gated out -> empty-but-valid report.
    import unimap.check as check
    monkeypatch.setattr(check.shutil, "which", lambda n: None)
    rc = main(["-t", "10.0.0.1", "-o", str(tmp_path)])
    assert rc == 0
    report = tmp_path / "10.0.0.1" / "report.md"
    assert report.exists()
    assert "UniMap Report" in report.read_text()
```

- [ ] **Step 2: Run to verify it fails** — `dev.sh test tests/test_cli.py -v` → FAIL (import error).

- [ ] **Step 3: Write `unimap/cli.py`**

```python
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
```

- [ ] **Step 4: Write `unimap/__main__.py`**

```python
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run to verify it passes** — `dev.sh test tests/test_cli.py -v` → `6 passed`.

- [ ] **Step 6: Run the full suite** — `dev.sh test -q`. Expected: all tests pass (≈ 50+).

- [ ] **Step 7: Smoke-run the CLI end-to-end** (no tools needed — everything gates out cleanly)

`wsl -d Ubuntu-24.04 bash "/mnt/c/Users/Seth Feldman/git/unimap/scripts/dev.sh" run --check`
Expected: tool-check table with all tools MISSING and install hints.
`... dev.sh run -t 127.0.0.1 -o /tmp/unimap-smoke`
Expected: `[+] 127.0.0.1: 0 services, ... findings -> .../report.md` and the report file exists.

- [ ] **Step 8: Commit**

```bash
git add unimap/cli.py unimap/__main__.py tests/test_cli.py
git commit -m "feat: add CLI, entrypoint, and end-to-end wiring"
```

---

## Task 16: README rewrite & v1 archival

**Files:**
- Modify: `README.md`
- Delete: `unimap.py`, `src/` (v1 Python-2 orchestrator)
- Create: `docs/v1-archive/` note (optional — see Step 2)

**Interfaces:** none (docs + cleanup). Do this only after Task 15's full suite passes — v2 is at MVP parity.

- [ ] **Step 1: Rewrite `README.md`**

Replace the body with v2 usage. Required content:
```markdown
# UniMap v2

Async reconnaissance orchestrator for pentest labs (OSCP/CTF). Recon and
enumeration only — never exploitation.

## Install (WSL Ubuntu)

    python3 -m venv ~/.venvs/unimap
    ~/.venvs/unimap/bin/pip install -e ".[dev]"

## Usage

    unimap -t 10.10.10.10                 # exam-compliant: single host
    unimap -t 10.10.10.10 --all-ports     # full 65535 sweep
    unimap --check                        # show installed vs missing tools
    unimap -t 10.10.10.0/24 --lab         # multi-host (lab only)
    unimap -t 10.10.10.10 --lab --brute   # + credential attacks (double-gated)

Output lands in `unimap-out/<host>/`: `result.json`, `report.md`, and raw
tool output under `artifacts/`.

## Modes

- **default** — exam-compliant: single host, portscan → nmap `-sV -sC` →
  per-service enum → report. No vuln scanner, no brute.
- **`--lab`** — unlocks CIDR/`@file` targets, nuclei vuln scanning, heavier enum.
- **`--brute`** — requires `--lab`; enables credential attacks (off by default).

## Development

    scripts/dev.sh setup      # create venv + editable install
    scripts/dev.sh test       # run the pytest suite (no real tools needed)

Design spec: `docs/superpowers/specs/2026-07-08-unimap-v2-modernization-design.md`.
Adding a tool = one new file in `unimap/plugins/` subclassing `Plugin`.
```

- [ ] **Step 2: Remove v1 code**

```bash
git rm unimap.py
git rm -r src
```
(Git history preserves v1; no separate archive needed.)

- [ ] **Step 3: Verify nothing imports v1** — `dev.sh test -q`. Expected: full suite still passes.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: rewrite README for v2 and remove v1 orchestrator"
```

---

## Backlog (post-parity — NOT part of this plan's tasks)

These are additive plugin files following the exact pattern of Tasks 7–11
(one file, subclass `Plugin`, parse output, return `Finding`s). Pull each into
its own future task/plan when needed — do not implement inline here:

- `http_nikto.py`, `http_whatweb.py` — more HTTP enum (default gate).
- `dns_dnsx.py`, DNS AXFR attempt via `dig` — richer DNS (default gate).
- `ftp_nmap.py`, `smtp_nmap.py`, `rdp_nmap.py` — targeted non-brute NSE (default gate).
- `enum4linux-ng` JSON (`-oJ`) structured parsing → real share/user `Finding`s.
- `creds_hydra.py` — targeted credential attack (`--lab --brute`).
- `rich`-based structured logging (spec §13) replacing `print`.
- Multi-host outer concurrency (currently hosts run sequentially in `_run`).

---

## Self-Review (author checklist — completed)

**Spec coverage** (design §s → task):
- §5 components → Tasks 2–15 (one module each). ✓
- §6 phases → `Phase` enum (Task 6) + engine ordering (Task 12). ✓
- §7 plugin model → Task 6; §10 catalog → Tasks 7–11 (MVP subset; rest in Backlog). ✓
- §8 CLI/modes → Task 15; §9 target model → Task 3. ✓
- §11 data model → Task 2; §12 output → Task 13. ✓
- §13 concurrency/robustness → Task 12 (semaphore, crash→Finding); timeouts → Task 5. ✓
- §14 environment → Task 1 (`scripts/dev.sh`, WSL venv). ✓
- §16 testing → every task is TDD with a mockable runner. ✓
- **Deferred (documented, not dropped):** `rich` logging, Ctrl-C partial-report,
  full plugin catalog, multi-host concurrency → Backlog. These are YAGNI for MVP parity.

**Type consistency:** Runner contract `run(name, argv, *, timeout=None)->ToolResult`
used identically by `SubprocessRunner`, `FakeRunner`, every plugin, and the engine.
`Plugin.run(ctx, runner)->list[Finding]` uniform. `HostContext` field names
(`open_ports`, `services`, `available`, `ports_mode`) consistent across base/plugins/engine.
`ports_mode ∈ {"top","all"}` set by CLI, read by `NmapPortScan`. ✓

**Placeholder scan:** every code step contains complete, runnable code; no TBD/TODO. ✓
