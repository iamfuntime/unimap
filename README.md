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
