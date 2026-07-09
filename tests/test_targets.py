import pytest
from unimap.targets import parse_targets, TargetError

def test_single_ipv4_default():
    ts = parse_targets("10.10.10.10", lab=False)
    assert len(ts) == 1
    assert ts[0].host == "10.10.10.10"
    assert ts[0].is_ip is True

def test_cidr_rejected_without_lab():
    with pytest.raises(TargetError):
        parse_targets("10.10.10.0/30", lab=False)

def test_cidr_expands_in_lab():
    ts = parse_targets("10.10.10.0/30", lab=True)
    assert [t.host for t in ts] == ["10.10.10.1", "10.10.10.2"]

def test_file_input_lab(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("10.0.0.1\n10.0.0.2\n")
    ts = parse_targets(f"@{f}", lab=True)
    assert [t.host for t in ts] == ["10.0.0.1", "10.0.0.2"]

def test_file_input_rejected_without_lab(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("10.0.0.1\n")
    with pytest.raises(TargetError):
        parse_targets(f"@{f}", lab=False)

def test_multiple_hosts_rejected_without_lab():
    with pytest.raises(TargetError):
        parse_targets("10.0.0.1,10.0.0.2", lab=False)

def test_hostname_resolves():
    ts = parse_targets("example.com", lab=False, resolve=lambda h: ["93.184.216.34"])
    assert ts[0].host == "93.184.216.34"
    assert ts[0].raw == "example.com"

def test_blank_and_comment_lines_skipped(tmp_path):
    f = tmp_path / "t.txt"
    f.write_text("# header\n10.0.0.1\n\n")
    ts = parse_targets(f"@{f}", lab=True)
    assert [t.host for t in ts] == ["10.0.0.1"]
