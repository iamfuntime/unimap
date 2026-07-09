import json

from unimap.models import Finding, HostResult, Service, Target
from unimap.report import render_markdown, suggested_next_steps, write_report


def _result():
    return HostResult(
        target=Target(raw="box.htb", host="10.10.10.5"),
        services=[
            Service(port=80, proto="tcp", name="http", product="Apache", version="2.4"),
            Service(port=445, proto="tcp", name="microsoft-ds"),
        ],
        findings=[
            Finding("nmap", "info", "80/tcp http"),
            Finding("rustscan", "low", "0 open ports"),
        ],
    )


NEXT = {"http": ["Browse http://{host}"], "microsoft-ds": ["Null session on {host}"]}


def test_markdown_has_services_findings_and_next_steps():
    md = render_markdown(_result(), NEXT)
    assert "# UniMap Report — 10.10.10.5" in md
    assert "| 80 | tcp | http |" in md
    assert "Browse http://10.10.10.5" in md
    assert "Null session on 10.10.10.5" in md


def test_suggested_next_steps_dedup_and_order():
    steps = suggested_next_steps(_result().services, NEXT)
    assert steps == ["Browse http://{host}", "Null session on {host}"]


def test_write_report_creates_both_files(tmp_path):
    j, m = write_report(_result(), tmp_path, NEXT)
    assert j.exists() and m.exists()
    data = json.loads(j.read_text())
    assert data["target"]["host"] == "10.10.10.5"
    assert data["services"][0]["port"] == 80


def test_empty_services_renders_placeholder():
    r = HostResult(target=Target(raw="h", host="h"))
    md = render_markdown(r, {})
    assert "No open services found" in md
