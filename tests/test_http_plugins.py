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
