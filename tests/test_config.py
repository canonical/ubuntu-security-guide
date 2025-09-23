from collections import namedtuple
import configparser
import logging
from pathlib import Path

from usg.config import (
    load_config, get_artifact_destination_path, override_config_with_cli_args, DEFAULT_CONFIG
)
from usg import constants

def test_load_config_defaults():
    # Should load defaults if no config file is provided
    cfg = load_config()
    for section, options in DEFAULT_CONFIG.items():
        assert cfg.has_section(section)
        for key, value in options.items():
            assert cfg.get(section, key) == str(value)


def test_load_config_with_file(tmp_path):
    # Create a config file that overrides a default
    config_file = tmp_path / "usgtest.ini"
    config_file.write_text("""
[cli]
log_file = /tmp/test.log
product = testproduct
""")
    cfg = load_config(str(config_file))
    assert cfg.get("cli", "log_file") == "/tmp/test.log"
    assert cfg.get("cli", "product") == "testproduct"


def test_load_config_file_not_exist(tmp_path, caplog):
    # Should fall back to defaults
    caplog.set_level(logging.INFO)
    missing_file = tmp_path / "doesnotexist.ini"
    cfg = load_config(str(missing_file))
    for section in DEFAULT_CONFIG:
        assert cfg.has_section(section)
    assert "does not exist. Using defaults." in caplog.text


def test_load_config_invalid_file(tmp_path, caplog):
    # Should log error and use defaults if config file is invalid
    caplog.set_level(logging.ERROR)
    bad_file = tmp_path / "bad.ini"
    bad_file.write_text("[cli\nbad")
    with caplog.at_level("ERROR"):
        cfg = load_config(str(bad_file))
    assert "Failed to load config" in caplog.text
    for section in DEFAULT_CONFIG:
        assert cfg.has_section(section)


def test_get_artifact_path(monkeypatch):
    # Test that artifact paths are correctly resolved and formatted
    monkeypatch.setattr(constants, "STATE_DIR", Path("/test_state_dir"))

    test_config = configparser.ConfigParser()
    test_config.read_dict(
        {
            "openscap_backend": {
                "audit_report": "relative_dir/{DATE}-{PROFILE_ID}.html",
                "audit_results": "/abs_dir/{DATE}-{PROFILE_ID}.xml",
                "audit_oval_results": "ssg-{PRODUCT}-oval.xml.results-{DATE}.xml",
            }
        }
    )
    report_path = get_artifact_destination_path(
        test_config, "audit_report", "TEST_TS", "TEST_ID", "TEST_PRODUCT"
    )
    results_path = get_artifact_destination_path(
        test_config, "audit_results", "TEST_TS", "TEST_ID", "TEST_PRODUCT"
    )
    oval_results_path = get_artifact_destination_path(
        test_config, "audit_oval_results", "TEST_TS", "TEST_ID", "TEST_PRODUCT"
    )
    assert report_path == Path("/test_state_dir/relative_dir/TEST_TS-TEST_ID.html")
    assert results_path == Path("/abs_dir/TEST_TS-TEST_ID.xml")
    assert oval_results_path == Path(
        "/test_state_dir/ssg-TEST_PRODUCT-oval.xml.results-TEST_TS.xml"
    )


def test_override_config_with_cli_args():
    # test that CLI values correctly override the config
    test_config = configparser.ConfigParser()
    test_config.read_dict(
        {
            "openscap_backend": {
                "audit_report": "original",
                "audit_results": "original",
                "fix_script": "original",
            }
        }
    )
    for command, option in [
        ("audit", "html_file"),
        ("audit", "notavalidoption"),
        ("generate-fix", "output")
    ]:
        args = namedtuple('args', ['command', option])(command, Path('overriden'))
        override_config_with_cli_args(test_config, args)
    
    overriden = str(Path('overriden').resolve())
    assert test_config.get("openscap_backend", "audit_report") == overriden
    assert test_config.get("openscap_backend", "audit_results") == "original"
    assert test_config.get("openscap_backend", "fix_script") == overriden
