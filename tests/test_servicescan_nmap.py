import asyncio
from pathlib import Path

from unimap.config import Config
from unimap.models import Target
from unimap.plugins.base import HostContext
from unimap.plugins.servicescan_nmap import NmapServiceScan, parse_nmap_xml
from tests.fakes import FakeRunner

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <ports>
   <port protocol="tcp" portid="22">
     <state state="open"/>
     <service name="ssh" product="OpenSSH" version="8.9p1"/>
   </port>
   <port protocol="tcp" portid="80">
     <state state="open"/>
     <service name="http" product="Apache httpd" version="2.4.52"/>
     <script id="http-title" output="Test Page"/>
   </port>
   <port protocol="tcp" portid="443">
     <state state="closed"/>
     <service name="https"/>
   </port>
  </ports>
 </host>
</nmaprun>"""


def test_parse_services_and_scripts():
    services, findings = parse_nmap_xml(NMAP_XML)
    assert [s.port for s in services] == [22, 80]
    ssh = services[0]
    assert ssh.name == "ssh" and ssh.product == "OpenSSH" and ssh.version == "8.9p1"
    assert any("http-title" in f.title for f in findings)


def test_parse_skips_closed_ports():
    services, _ = parse_nmap_xml(NMAP_XML)
    assert 443 not in [s.port for s in services]


def test_plugin_populates_services(tmp_path):
    (tmp_path / "artifacts").mkdir()
    ctx = HostContext(target=Target(raw="h", host="10.0.0.1"), outdir=tmp_path, config=Config())
    ctx.open_ports = [22, 80]
    runner = FakeRunner().set("nmap-service", stdout=NMAP_XML)
    findings = asyncio.run(NmapServiceScan().run(ctx, runner))
    assert [s.port for s in ctx.services] == [22, 80]
    assert any(f.source_tool == "nmap" for f in findings)


def test_plugin_matches_only_with_open_ports():
    ctx = HostContext(target=Target(raw="h", host="h"), outdir=Path("."), config=Config())
    assert NmapServiceScan().matches(ctx) is False
    ctx.open_ports = [80]
    assert NmapServiceScan().matches(ctx) is True


def test_plugin_ignores_stale_oX_file(tmp_path):
    (tmp_path / "artifacts").mkdir()
    stale = tmp_path / "artifacts" / "nmap-service.xml"
    stale.write_text(
        '<?xml version="1.0"?><nmaprun><host><ports>'
        '<port protocol="tcp" portid="21"><state state="open"/><service name="ftp"/></port>'
        '</ports></host></nmaprun>'
    )
    ctx = HostContext(target=Target(raw="h", host="10.0.0.1"), outdir=tmp_path, config=Config())
    ctx.open_ports = [22]
    runner = FakeRunner().set("nmap-service", stdout=NMAP_XML)
    asyncio.run(NmapServiceScan().run(ctx, runner))
    # Stale ftp:21 must be cleared; services come from this run's stdout (22, 80).
    assert [s.port for s in ctx.services] == [22, 80]
