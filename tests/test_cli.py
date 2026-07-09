from unimap.cli import build_parser, main


def test_parser_defaults():
    args = build_parser().parse_args(["-t", "10.0.0.1"])
    assert args.ports_mode == "top"
    assert args.lab is False
    assert args.outdir == "unimap-out"


def test_all_ports_flag():
    args = build_parser().parse_args(["-t", "10.0.0.1", "--all-ports"])
    assert args.ports_mode == "all"


def test_concurrency_zero_parses_as_explicit_zero():
    # 0 must remain distinguishable from "not passed" (None) downstream.
    args = build_parser().parse_args(["-t", "10.0.0.1", "--concurrency", "0"])
    assert args.concurrency == 0


def test_brute_requires_lab(capsys):
    rc = main(["-t", "10.0.0.1", "--brute"])
    assert rc == 2
    assert "requires --lab" in capsys.readouterr().err


def test_missing_target_without_check(capsys):
    rc = main([])
    assert rc == 2
    assert "target" in capsys.readouterr().err.lower()


def test_check_mode_short_circuits(monkeypatch, capsys):
    import unimap.check as check
    monkeypatch.setattr(check.shutil, "which", lambda n: None)
    rc = main(["--check"])
    assert rc == 0
    assert "tool check" in capsys.readouterr().out.lower()


def test_bad_config_path_exits_2(tmp_path, capsys):
    rc = main(["-t", "10.0.0.1", "-c", str(tmp_path / "nope.yaml")])
    assert rc == 2
    assert capsys.readouterr().err.strip()


def test_full_run_with_no_tools_writes_report(monkeypatch, tmp_path, capsys):
    # No tools available -> every plugin gated out -> empty-but-valid report.
    import unimap.check as check
    monkeypatch.setattr(check.shutil, "which", lambda n: None)
    rc = main(["-t", "10.0.0.1", "-o", str(tmp_path)])
    assert rc == 0
    report = tmp_path / "10.0.0.1" / "report.md"
    assert report.exists()
    assert "UniMap Report" in report.read_text()
