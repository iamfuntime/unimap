# UniMap v2

Async reconnaissance orchestrator for pentest labs (OSCP/CTF). Recon and
enumeration only — never exploitation.

## Requirements

- **Python 3.10+** (developed and tested on 3.12).
- The external recon tools you want to run, on your `$PATH` — e.g. `nmap`,
  `rustscan`, `httpx`, `feroxbuster`, `enum4linux-ng`, `snmpwalk`, `nuclei`,
  `netexec`. All are optional: a missing tool simply disables the plugin that
  needs it (only `nmap` is load-bearing, and it has a fallback). Run
  `unimap --check` to see what's detected on your system.

## Install

Runs on any OS with Python 3.10+ — Kali, Parrot, Ubuntu, Debian, Arch, macOS,
and so on. Nothing here is distro-specific; if `python3` and your tools are
present, it works. Install into a virtualenv (recommended everywhere, and
required on distros that enforce PEP 668 / "externally managed" Python):

    python3 -m venv ~/.venvs/unimap
    ~/.venvs/unimap/bin/pip install .
    ~/.venvs/unimap/bin/unimap --check

Activate the venv (or add its `bin/` to `$PATH`) to call `unimap` directly. The
only runtime dependency is PyYAML; the tools above are invoked as external
processes, never bundled.

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

    pip install -e ".[dev]"   # editable install + test deps (pytest)
    pytest                    # subprocess layer is mocked — no real tools needed

The editable install works on a native Linux filesystem. On the Windows
`/mnt/c` mount under WSL it fails — DrvFS rejects the `chmod` on `egg-info` —
so use the bundled harness there, which installs deps directly and imports the
package straight from the source tree (`sys.path`), no editable install:

    scripts/dev.sh setup      # venv + deps
    scripts/dev.sh test       # run the pytest suite

Design spec: `docs/superpowers/specs/2026-07-08-unimap-v2-modernization-design.md`.
Adding a tool = one new file in `unimap/plugins/` subclassing `Plugin`.
