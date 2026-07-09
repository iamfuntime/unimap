import asyncio
from pathlib import Path

from unimap.config import Config
from unimap.models import Target
from unimap.plugins.base import HostContext
from unimap.plugins.portscan_rustscan import RustScanPortScan, parse_rustscan
from unimap.plugins.portscan_nmap import NmapPortScan, parse_nmap_grepable
from tests.fakes import FakeRunner


def _ctx(**kw):
    return HostContext(target=Target(raw="h", host="10.0.0.1"), outdir=Path("."), config=Config(), **kw)


def test_parse_rustscan_arrow_format():
    assert parse_rustscan("10.0.0.1 -> [22,80,443]") == [22, 80, 443]


def test_parse_rustscan_open_format():
    text = "Open 10.0.0.1:22\nOpen 10.0.0.1:80\n"
    assert parse_rustscan(text) == [22, 80]


def test_rustscan_sets_open_ports():
    ctx = _ctx()
    runner = FakeRunner().set("rustscan", stdout="10.0.0.1 -> [22,80]")
    findings = asyncio.run(RustScanPortScan().run(ctx, runner))
    assert ctx.open_ports == [22, 80]
    assert findings[0].source_tool == "rustscan"


def test_parse_nmap_grepable():
    text = "Host: 10.0.0.1 () Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 443/closed/tcp//https///\n"
    assert parse_nmap_grepable(text) == [22, 80]


def test_nmap_fallback_matches_only_without_rustscan():
    p = NmapPortScan()
    assert p.matches(_ctx(available={"nmap"})) is True
    assert p.matches(_ctx(available={"nmap", "rustscan"})) is False


def test_nmap_fallback_sets_open_ports():
    ctx = _ctx(available={"nmap"})
    grep = "Host: 10.0.0.1 () Ports: 22/open/tcp//ssh///, 3306/open/tcp//mysql///\n"
    runner = FakeRunner().set("nmap-portscan", stdout=grep)
    asyncio.run(NmapPortScan().run(ctx, runner))
    assert ctx.open_ports == [22, 3306]
