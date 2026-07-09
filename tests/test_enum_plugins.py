import asyncio
from pathlib import Path

from unimap.config import Config
from unimap.models import Service, Target
from unimap.plugins.base import HostContext
from unimap.plugins.smb_enum4linuxng import Enum4linuxNg
from unimap.plugins.snmp_walk import SnmpWalk
from unimap.plugins.dns_nmap import DnsNmap
from tests.fakes import FakeRunner


def _ctx(tmp_path, services):
    (tmp_path / "artifacts").mkdir(exist_ok=True)
    ctx = HostContext(target=Target(raw="h", host="10.0.0.1"), outdir=tmp_path, config=Config())
    ctx.services = services
    return ctx


def test_smb_matches_on_smb_services():
    ctx = HostContext(target=Target(raw="h", host="h"), outdir=Path("."), config=Config())
    assert Enum4linuxNg().matches(ctx) is False
    ctx.services = [Service(port=445, name="microsoft-ds")]
    assert Enum4linuxNg().matches(ctx) is True


def test_smb_captures_output(tmp_path):
    ctx = _ctx(tmp_path, [Service(port=445, name="microsoft-ds")])
    runner = FakeRunner().set("enum4linux-ng", stdout="[+] Server allows sessions using username '', password ''\nShare: ADMIN$")
    findings = asyncio.run(Enum4linuxNg().run(ctx, runner))
    assert any(f.source_tool == "enum4linux-ng" for f in findings)
    assert any(f.severity == "low" for f in findings)  # null-session marker


def test_snmp_walks_each_community(tmp_path):
    ctx = _ctx(tmp_path, [Service(port=161, proto="udp", name="snmp")])
    runner = FakeRunner()
    runner.set("snmpwalk-public", stdout="SNMPv2-MIB::sysDescr.0 = STRING: Linux box")
    runner.set("snmpwalk-private", stdout="")
    findings = asyncio.run(SnmpWalk().run(ctx, runner))
    assert any("public" in f.title for f in findings)
    assert all("private" not in f.title for f in findings)  # empty walk -> no finding


def test_dns_runs_nse(tmp_path):
    ctx = _ctx(tmp_path, [Service(port=53, name="domain")])
    runner = FakeRunner().set("dns-nmap", stdout="| dns-recursion: Recursion appears to be enabled")
    findings = asyncio.run(DnsNmap().run(ctx, runner))
    assert any("dns" in f.title.lower() or f.source_tool == "nmap" for f in findings)


def test_snmp_matches_only_on_snmp():
    ctx = HostContext(target=Target(raw="h", host="h"), outdir=Path("."), config=Config())
    assert SnmpWalk().matches(ctx) is False
    ctx.services = [Service(port=161, proto="udp", name="snmp")]
    assert SnmpWalk().matches(ctx) is True


def test_dns_matches_only_on_dns():
    ctx = HostContext(target=Target(raw="h", host="h"), outdir=Path("."), config=Config())
    assert DnsNmap().matches(ctx) is False
    ctx.services = [Service(port=53, name="domain")]
    assert DnsNmap().matches(ctx) is True
