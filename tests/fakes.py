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
