from unimap import check
import unimap.plugins.servicescan_nmap  # noqa: F401 — populate REGISTRY so run_check() has tools to report


def test_available_binaries_reports_present_and_missing(monkeypatch):
    monkeypatch.setattr(check.shutil, "which", lambda n: "/usr/bin/" + n if n == "nmap" else None)
    table = check.available_binaries(["nmap", "rustscan"])
    assert table["nmap"] == "/usr/bin/nmap"
    assert table["rustscan"] is None


def test_run_check_returns_zero_and_prints(monkeypatch, capsys):
    monkeypatch.setattr(check.shutil, "which", lambda n: None)
    rc = check.run_check()
    out = capsys.readouterr().out
    assert rc == 0
    assert "tool check" in out.lower()
    assert "MISSING" in out


def test_required_binaries_nonempty_after_plugin_import():
    import unimap.plugins.servicescan_nmap  # noqa: F401 — registers a plugin needing nmap
    assert "nmap" in check.required_binaries()
