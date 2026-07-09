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
