import asyncio

from unimap.config import Config
from unimap.engine import Engine
from unimap.models import Finding, Service, Target
from unimap.plugins.base import HostContext, Phase, Plugin
from tests.fakes import FakeRunner


class FakePortscan(Plugin):
    name = "fps"; phase = Phase.PORTSCAN; requires = []
    async def run(self, ctx, runner):
        ctx.open_ports = [80]
        return [Finding("fps", "info", "ports")]


class FakeServiceId(Plugin):
    name = "fsi"; phase = Phase.SERVICE_ID; requires = []
    def matches(self, ctx): return bool(ctx.open_ports)
    async def run(self, ctx, runner):
        ctx.services = [Service(port=80, name="http")]
        return [Finding("fsi", "info", "svc")]


class FakeHttp(Plugin):
    name = "fhttp"; phase = Phase.ENUM; requires = []
    def matches(self, ctx): return any(s.name == "http" for s in ctx.services)
    async def run(self, ctx, runner): return [Finding("fhttp", "info", "http enum")]


class LabOnly(Plugin):
    name = "lab"; phase = Phase.VULN; lab_only = True; requires = []
    async def run(self, ctx, runner): return [Finding("lab", "info", "vuln")]


class BruteOnly(Plugin):
    name = "br"; phase = Phase.CREDS; lab_only = True; brute = True; requires = []
    async def run(self, ctx, runner): return [Finding("br", "info", "creds")]


def _engine(**kw):
    plugins = [FakePortscan(), FakeServiceId(), FakeHttp(), LabOnly(), BruteOnly()]
    return Engine(Config(), FakeRunner(), plugins=plugins, **kw)


def _scan(engine, tmp_path):
    return asyncio.run(engine.scan_host(Target(raw="h", host="h"), tmp_path))


def test_pipeline_flows_ports_to_services_to_enum(tmp_path):
    res = _scan(_engine(), tmp_path)
    titles = [f.title for f in res.findings]
    assert "ports" in titles and "svc" in titles and "http enum" in titles
    assert [s.port for s in res.services] == [80]


def test_lab_plugin_skipped_by_default(tmp_path):
    res = _scan(_engine(lab=False), tmp_path)
    assert "vuln" not in [f.title for f in res.findings]


def test_lab_plugin_runs_with_lab(tmp_path):
    res = _scan(_engine(lab=True), tmp_path)
    assert "vuln" in [f.title for f in res.findings]


def test_brute_needs_lab_and_brute(tmp_path):
    assert "creds" not in [f.title for f in _scan(_engine(lab=True), tmp_path).findings]
    assert "creds" in [f.title for f in _scan(_engine(lab=True, brute=True), tmp_path).findings]


def test_requires_gate_skips_when_tool_absent(tmp_path):
    class NeedsTool(Plugin):
        name = "nt"; phase = Phase.ENUM; requires = ["madeuptool"]
        async def run(self, ctx, runner): return [Finding("nt", "info", "ran")]
    eng = Engine(Config(), FakeRunner(), plugins=[NeedsTool()], available=set())
    assert _scan(eng, tmp_path).findings == []


def test_plugin_crash_becomes_error_finding(tmp_path):
    class Boom(Plugin):
        name = "boom"; phase = Phase.ENUM; requires = []
        async def run(self, ctx, runner): raise RuntimeError("kaboom")
    eng = Engine(Config(), FakeRunner(), plugins=[Boom()])
    res = _scan(eng, tmp_path)
    assert any(f.severity == "error" and "boom" in f.title for f in res.findings)
