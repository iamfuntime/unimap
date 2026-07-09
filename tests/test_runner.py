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
