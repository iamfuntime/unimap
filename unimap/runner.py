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
        if timeout is None:
            timeout = self.default_timeout
        artifact = self.artifact_dir / f"{name}.txt"
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
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
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
            out_b, err_b, rc = b"", b"", -9

        stdout = out_b.decode(errors="replace")
        stderr = err_b.decode(errors="replace")
        artifact.write_text(
            f"$ {' '.join(argv)}\n\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n"
            + ("\n[timed out]\n" if timed_out else "")
        )
        return ToolResult(name, list(argv), rc, stdout, stderr, str(artifact), timed_out)
