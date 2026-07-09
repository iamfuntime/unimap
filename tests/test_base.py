from pathlib import Path

from unimap.config import Config
from unimap.models import Service, Target
from unimap.plugins.base import REGISTRY, HostContext, Phase, Plugin, http_url, register


def _ctx():
    return HostContext(target=Target(raw="h", host="h"), outdir=Path("."), config=Config())


def test_phase_ordering():
    assert Phase.PORTSCAN < Phase.SERVICE_ID < Phase.ENUM < Phase.VULN < Phase.CREDS


def test_http_url_scheme():
    assert http_url("10.0.0.1", Service(port=80, name="http")) == "http://10.0.0.1:80"
    assert http_url("10.0.0.1", Service(port=443, name="https", tunnel="ssl")) == "https://10.0.0.1:443"
    assert http_url("10.0.0.1", Service(port=8080, name="http-proxy")) == "http://10.0.0.1:8080"


def test_register_adds_to_registry():
    before = len(REGISTRY)

    @register
    class Dummy(Plugin):
        name = "dummy"
        phase = Phase.ENUM

        async def run(self, ctx, runner):
            return []

    assert len(REGISTRY) == before + 1
    assert Dummy in REGISTRY


def test_http_services_filter():
    ctx = _ctx()
    ctx.services = [
        Service(port=80, name="http"),
        Service(port=22, name="ssh"),
        Service(port=8443, name="https"),
        Service(port=8080, name="http-proxy"),
    ]
    assert sorted(s.port for s in ctx.http_services()) == [80, 8080, 8443]


def test_http_services_includes_unnamed_web_ports():
    ctx = _ctx()
    ctx.services = [
        Service(port=443, name=""),
        Service(port=80, name="tcpwrapped"),
        Service(port=22, name="ssh"),
    ]
    assert sorted(s.port for s in ctx.http_services()) == [80, 443]
    unnamed_443 = next(s for s in ctx.services if s.port == 443)
    assert http_url("10.0.0.1", unnamed_443) == "https://10.0.0.1:443"


def test_services_named():
    ctx = _ctx()
    ctx.services = [Service(port=445, name="microsoft-ds"), Service(port=22, name="ssh")]
    assert [s.port for s in ctx.services_named("microsoft-ds", "netbios-ssn")] == [445]


def test_plugin_is_abstract():
    import pytest

    with pytest.raises(TypeError):
        Plugin()  # abstract run()
