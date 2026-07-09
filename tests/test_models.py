import json
from unimap.models import Target, Service, Finding, HostResult

def test_hostresult_to_dict_roundtrips():
    t = Target(raw="10.10.10.10", host="10.10.10.10", is_ip=True)
    r = HostResult(
        target=t,
        services=[Service(port=80, proto="tcp", name="http")],
        findings=[Finding(source_tool="nmap", severity="info", title="port 80 open")],
        artifacts=["scan.txt"],
    )
    d = r.to_dict()
    assert d["target"]["host"] == "10.10.10.10"
    assert d["services"][0]["port"] == 80
    assert d["findings"][0]["severity"] == "info"
    assert d["artifacts"] == ["scan.txt"]

def test_hostresult_json_serializable():
    r = HostResult(target=Target(raw="h", host="h"))
    assert json.dumps(r.to_dict())  # must not raise

def test_defaults_are_independent():
    a = HostResult(target=Target(raw="a", host="a"))
    b = HostResult(target=Target(raw="b", host="b"))
    a.findings.append(Finding("t", "info", "x"))
    assert b.findings == []  # default_factory, not shared mutable
