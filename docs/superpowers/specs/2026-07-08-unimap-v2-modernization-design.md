# UniMap v2 — Modernization Design

- **Date:** 2026-07-08
- **Status:** Approved design — ready for implementation planning
- **Author:** Seth Feldman (with Claude Code)
- **Supersedes:** UniMap v1 (Python 2 orchestrator at repo root)

## 1. Summary

UniMap v2 is a clean-slate rewrite of UniMap as a **Python 3.10+ asyncio recon
orchestrator** for penetration-test reconnaissance. It preserves v1's core idea
— fast port sweep, then deep scan, then targeted per-service enumeration, then a
report — but rebuilds it on actively-maintained tools and a plugin architecture,
and eliminates v1's Python-2 syntax, dead tools, and correctness bugs.

The tool does **reconnaissance and enumeration only**. It never exploits. This
keeps the scope focused and keeps a default run compliant with OSCP exam rules.

## 2. Goals

- Run on modern systems (Python 3.10+, current Kali/Ubuntu tooling).
- Replace abandoned tools (unicornscan, amap, dirb) with maintained equivalents.
- Be **exam-compliant by default**; unlock aggressive tooling behind `--lab`.
- Produce **structured output** (per-host JSON) plus a human-readable **Markdown
  report** with a generated "suggested next steps" section for OSCP note-taking.
- Be **extensible**: adding a new tool is one new plugin file, no engine changes.
- **Fail safe**: a missing optional tool disables its plugin with a logged hint;
  only a missing `nmap` is fatal.

## 3. Non-goals (YAGNI / out of scope)

- No exploitation of any kind.
- No full dependency-graph (DAG) scheduler — phases are sufficient.
- No HTML report, no web UI, no database backend.
- No auto-installation of third-party tools (detect + hint only).
- No Windows-native runtime support (Linux/WSL only — see §14).

## 4. Design decisions (recorded from brainstorming)

| # | Decision | Choice |
|---|----------|--------|
| D1 | Modernization scope | Clean rewrite (not in-place port) |
| D2 | Primary use context | OSCP / CTF labs |
| D3 | Exam safety | Exam-compliant default + `--lab` flag to unlock the rest |
| D4 | Target inputs | Single host (exam default); IPv4/IPv6/hostname/CIDR/file (`--lab`) |
| D5 | Output | Per-host JSON + consolidated Markdown report w/ next-steps |
| D6 | Engine | Plugin registry + phased async scheduler (not DAG, not flat queue) |
| D7 | Credential attacks | Double-gated behind `--lab --brute`, off by default |
| D8 | Environment | WSL2 + Ubuntu; repo on Windows FS, runtime in Ubuntu (see §14) |

## 5. Architecture

```
cli.py ──> config.py ──> targets.py ──> Engine (engine.py)
                                          │ phased scheduler
                                          │ bounded semaphore
                                          ▼
                                   Plugin registry (plugins/)
   discovery → portscan → service-id → enumeration → [vuln] → [creds] → report
                                          │
                                   runner.py: async subprocess + artifact capture
                                          │
                                   models.py: HostResult / Service / Finding
                                          ▼
                                   report.py: per-host JSON + Markdown
```

### Components

- **`cli.py`** — argument parsing, mode flags (`--lab`, `--brute`, `--check`).
- **`config.py`** — configuration: tool paths, wordlists, timeouts, community
  strings, concurrency defaults. Loaded from a YAML file with sane built-ins.
- **`targets.py`** — parse and normalize target input into `Target` objects;
  resolve hostnames, expand CIDR, read `@file`. Enforces the single-host limit
  unless `--lab`.
- **`models.py`** — dataclasses: `Target`, `Service`, `Finding`, `HostResult`.
  All JSON-serializable.
- **`runner.py`** — the only place that spawns processes. Uses
  `asyncio.create_subprocess_exec` with **argv lists** (never `shell=True`).
  Captures stdout/stderr to an artifact file and returns them for parsing.
  Enforces per-tool timeouts.
- **`engine.py`** — the phased scheduler. Iterates phases in order; within a
  phase, selects plugins whose `matches()` fires and whose gate is satisfied,
  and runs them concurrently under a global semaphore.
- **`plugins/`** — one module per tool, each subclassing `Plugin` (see §7).
- **`report.py`** — renders `HostResult` to `result.json` and `report.md`.
- **`data/next_steps.yaml`** — service → suggested manual next steps, used to
  generate the report's "Suggested Next Steps" section.

## 6. Phases

Ordered pipeline. Each phase consumes the structured results of prior phases.

1. **discovery** — (multi-host/`--lab`) host liveness (nmap `-sn` / equivalent).
   Single-host default skips or does a light check.
2. **portscan** — fast full/`--top-ports` sweep → set of open ports.
3. **service-id** — nmap `-sV -sC` (XML output) on open ports → `Service` list.
4. **enumeration** — per-service plugins fan out (HTTP, SMB, DNS, SNMP, …).
5. **vuln** *(`--lab`)* — nuclei against discovered services.
6. **creds** *(`--lab --brute`)* — credential attacks (spray / targeted).
7. **report** — aggregate → JSON + Markdown.

## 7. Plugin model

```python
class Plugin(ABC):
    name: str
    phase: Phase             # which phase this runs in
    lab_only: bool = False   # requires --lab
    brute: bool = False      # additionally requires --brute
    requires: list[str]      # external binaries needed (for availability check)

    def matches(self, ctx: HostContext) -> bool:
        """True if this plugin should run for the current host/services."""

    async def run(self, ctx: HostContext, runner: Runner) -> list[Finding]:
        """Invoke the tool via runner, parse output, return structured findings."""
```

The engine is tool-agnostic: it only calls `matches()` / `run()` and enforces
`lab_only` / `brute` gating and binary availability (`requires`). This is what
makes v2 resistant to the "frozen hardcoded tool/CVE list" problem that afflicts
v1 — new tooling is additive.

## 8. CLI & modes

```
unimap -t <target> [-o outdir] [--top-ports | --all-ports]
       [--lab] [--brute] [-c config.yaml] [--concurrency N] [--check]
```

- **Default (exam-compliant):** single host; discovery → rustscan sweep →
  nmap `-sV -sC` → per-service enumeration → report. No vuln scanner, no brute.
- **`--lab`:** unlocks multi-target / CIDR / file input, nuclei vuln scanning,
  and heavier enumeration plugins.
- **`--brute`:** requires `--lab`; enables the `creds` phase. Off unless asked
  for explicitly (double gate).
- **`--check`:** "doctor" mode — reports installed vs missing tools with install
  hints, then exits. No scanning.

## 9. Target model (D4)

`targets.py` accepts:

- IPv4 (`10.10.10.10`), IPv6, hostname (resolved to address(es)).
- CIDR (`10.10.10.0/24`) — **`--lab` only**.
- `@file` — newline-delimited targets — **`--lab` only**.

Exam-compliant mode accepts exactly one resolved host. All inputs normalize to a
list of `Target` objects so the engine treats single vs many uniformly.

## 10. Tool plugin catalog (D3 gating applied)

| Phase | Plugin(s) | Replaces (v1) | Gate |
|-------|-----------|---------------|------|
| portscan | **RustScan** (fallback: nmap `-sS`) | unicornscan | default |
| service-id | **nmap `-sV -sC`** (XML → structured) | amap + basic nmap | default |
| enum: HTTP | **httpx**, **feroxbuster**, **nikto**, whatweb | dirb/gobuster/curl | default |
| enum: SMB | **enum4linux-ng**, smbclient, nmap smb-* | enum4linux/nbtscan | default |
| enum: DNS | dnsx / nmap dns-* + AXFR attempt | — | default |
| enum: SNMP | snmp-check / snmpwalk (`public`,`private`) | onesixtyone/snmpwalk | default |
| enum: FTP/SSH/SMTP/RDP/DB | targeted nmap NSE (non-brute) | scattered NSE | default |
| vuln | **nuclei** (http + network templates) | frozen 2006–2017 NSE CVE list | `--lab` |
| creds | **netexec** (spray), hydra (targeted) | hydra/medusa/ncrack | `--lab --brute` |

`nuclei` is `--lab`-gated because a templated mass-vulnerability scanner is the
class of tool OffSec restricts on the exam. Credential attacks are further gated
behind `--brute` because low-value password lists against SSH/FTP/RDP are noisy
and lockout-prone; when enabled, prefer **spraying** (one password across many
users) via netexec over per-account brute force.

## 11. Data model

```python
@dataclass
class Service:
    port: int
    proto: str            # tcp/udp
    name: str             # http, microsoft-ds, ...
    product: str = ""
    version: str = ""
    tunnel: str = ""      # e.g. ssl

@dataclass
class Finding:
    source_tool: str
    severity: str         # info | low | medium | high | error
    title: str
    detail: str
    evidence_path: str = ""   # path to raw artifact

@dataclass
class HostResult:
    target: Target
    services: list[Service]
    findings: list[Finding]
    artifacts: list[str]
```

## 12. Output & reporting (D5)

Per run, under `outdir/<host>/`:

- `artifacts/` — each tool's raw stdout/stderr, unmodified (preserves the
  "grep the real output" workflow).
- `result.json` — the serialized `HostResult` (queryable machine data).
- `report.md` — consolidated human-readable report. Its final **Suggested Next
  Steps** section is generated by mapping discovered services against
  `data/next_steps.yaml` (e.g. *445/SMB open → try enum4linux-ng null session,
  check smb-vuln-ms17-010, `netexec smb <ip> -u '' -p ''`*).

## 13. Concurrency, robustness, error handling

- **Concurrency:** `asyncio` with a global semaphore (default 5 concurrent
  tools; `--concurrency` to tune). Multi-host (`--lab`) adds outer concurrency
  over hosts, inner over plugins.
- **Timeouts:** every tool invocation has a per-tool timeout so a hung tool
  never stalls the run.
- **Cancellation:** `Ctrl-C` cancels in-flight tasks cleanly and still writes a
  partial report.
- **Logging:** structured logging via `rich`. No silent `except: pass`; a tool
  failure becomes an `error`-severity `Finding` surfaced in the report.
- **No shell:** all process spawns use argv lists via
  `asyncio.create_subprocess_exec`. This removes v1's shell-injection surface
  and the `endswith('/' or '\\')` class of parsing bugs entirely.
- **Availability:** at startup (and via `--check`), detect each plugin's
  `requires` binaries; missing → plugin skipped with an install hint.

## 14. Environment & platform (D8)

- No native Python or WSL is currently installed on the dev machine.
- Runtime is **WSL2 + Ubuntu**. Python 3.10+.
- The git repo stays on the Windows filesystem
  (`C:\Users\Seth Feldman\git\unimap`); files are edited from Windows and the
  code/tests run inside Ubuntu against `/mnt/c/Users/Seth Feldman/git/unimap`.
- Pentest tools install via `apt` plus a few via `git`/`go`
  (rustscan, nuclei, netexec, feroxbuster, enum4linux-ng as applicable).
- **Building** the tool (code + test suite) needs only Python — the test suite
  mocks the subprocess layer, so no real tools or targets are required to run
  tests. **Running** real scans needs the tools installed in Ubuntu.

## 15. Project structure

```
unimap/                        # repo root
  pyproject.toml               # packaging, console_script `unimap`
  docs/superpowers/specs/      # this spec
  unimap/                      # package
    __init__.py
    __main__.py                # entrypoint
    cli.py
    config.py
    models.py
    engine.py
    runner.py
    targets.py
    report.py
    plugins/
      base.py                  # Plugin ABC + registry
      portscan_rustscan.py
      servicescan_nmap.py
      http_httpx.py
      http_feroxbuster.py
      http_nikto.py
      smb_enum4linuxng.py
      ...                      # one file per tool
    data/
      next_steps.yaml
  tests/
    test_targets.py
    test_parsers.py            # golden-file parser tests
    test_report.py
    test_engine.py
  README.md
```

v1 files (`unimap.py`, `src/`) remain until v2 reaches parity, then are removed
or archived in the same change that lands the console entrypoint.

## 16. Testing strategy

- **Framework:** `pytest`, test-driven.
- **Parser tests:** feed sample `nmap` XML, RustScan output, and
  `enum4linux-ng` output fixtures → assert the resulting `Service`/`Finding`
  objects (golden-file style).
- **Target tests:** parsing/normalization/expansion, including the single-host
  vs `--lab` gate.
- **Report tests:** render a fixed `HostResult` → assert JSON + Markdown output.
- **Engine tests:** plugin `matches()` selection, phase ordering, and `--lab` /
  `--brute` gating, with the subprocess layer mocked.
- The subprocess layer is injectable/mockable so the whole suite runs on any
  machine with Python — no real tools or live targets needed.

## 17. Open questions

None blocking. Fast-scanner default is RustScan with an nmap SYN fallback; naabu
is a viable alternative to revisit if RustScan install proves painful on Ubuntu.
