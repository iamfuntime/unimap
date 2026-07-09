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
