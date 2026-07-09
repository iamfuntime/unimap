import asyncio
from pathlib import Path

from unimap.config import Config
from unimap.models import Service, Target
from unimap.plugins.base import HostContext, Phase
from unimap.plugins.vuln_nuclei import NucleiScan, parse_nuclei
from unimap.plugins.creds_netexec import NetexecSpray
from tests.fakes import FakeRunner


def _ctx(tmp_path, services):
    (tmp_path / "artifacts").mkdir(exist_ok=True)
    ctx = HostContext(target=Target(raw="h", host="10.0.0.1"), outdir=tmp_path, config=Config())
    ctx.services = services
    return ctx


def test_nuclei_is_lab_gated():
    assert NucleiScan.lab_only is True
    assert NucleiScan.phase == Phase.VULN


def test_parse_nuclei_maps_severity():
    line = "[apache-detect] [http] [info] http://10.0.0.1\n[CVE-2021-1234] [http] [high] http://10.0.0.1/x"
    findings = parse_nuclei(line)
    sevs = {f.severity for f in findings}
    assert "high" in sevs and "info" in sevs


def test_nuclei_runs_on_http(tmp_path):
    ctx = _ctx(tmp_path, [Service(port=80, name="http")])
    runner = FakeRunner().set("nuclei", stdout="[CVE-2021-1234] [http] [high] http://10.0.0.1/x")
    findings = asyncio.run(NucleiScan().run(ctx, runner))
    assert any(f.severity == "high" for f in findings)


def test_netexec_is_double_gated():
    assert NetexecSpray.lab_only is True
    assert NetexecSpray.brute is True
    assert NetexecSpray.phase == Phase.CREDS


def test_netexec_matches_smb():
    ctx = HostContext(target=Target(raw="h", host="h"), outdir=Path("."), config=Config())
    assert NetexecSpray().matches(ctx) is False
    ctx.services = [Service(port=445, name="microsoft-ds")]
    assert NetexecSpray().matches(ctx) is True
