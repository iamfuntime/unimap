import pytest

from unimap.config import Config, load_config

def test_defaults():
    c = load_config(None)
    assert c.concurrency == 5
    assert c.tool_timeout == 300
    assert c.community_strings == ["public", "private"]

def test_yaml_overrides(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("concurrency: 12\ntool_timeout: 60\n")
    c = load_config(str(p))
    assert c.concurrency == 12
    assert c.tool_timeout == 60
    assert c.community_strings == ["public", "private"]  # untouched default

def test_unknown_keys_ignored(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("bogus_key: 1\nconcurrency: 3\n")
    c = load_config(str(p))
    assert c.concurrency == 3
    assert not hasattr(c, "bogus_key")

def test_non_dict_yaml_raises(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("- a\n- b\n")
    with pytest.raises(ValueError):
        load_config(str(p))

def test_empty_yaml_returns_defaults(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("   \n")
    c = load_config(str(p))
    assert c.concurrency == 5
    assert c.tool_timeout == 300
