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
