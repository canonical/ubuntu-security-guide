# Ubuntu Security Guide
# Copyright (C) 2025 Canonical Ltd.
#
# SPDX-License-Identifier: GPL-3.0-only
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

import importlib
import json
import os
import sys
from pathlib import Path
import logging

import pytest
from pytest import MonkeyPatch

from usg import cli, exceptions, results, constants, utils, __version__
from usg.cli import init_logging, load_benchmark_version_state, save_benchmark_version_state
from usg.exceptions import LockError, StateFileError, USGError
from usg.usg import USG
from usg.results import AuditResults, BackendArtifacts

logger = logging.getLogger(__name__)

@pytest.fixture
def patch_usg_and_cli(tmp_path_factory, dummy_benchmarks):
    # patch the usg module:
    # - set benchmarks to dummy benchmarks fixture
    # - set state_dir to a tmp path
    # - set default product to match dummy_benchmarks
    # - set check_perms, verify_integrity, and acquire_lock to no-ops
    # - patch USG with a dummy USG class overriding audit, generate_fix, fix
    # - change working directory to a tmp dir and create tailoring file in it
    # - patch load state functions to always return "latest" (always clean slate and no state file)
    #   and set save_state to noop
    mp = MonkeyPatch()

    tmp_state_dir = tmp_path_factory.mktemp("var_dir")

    dummy_cfg = tmp_state_dir / "usg.conf"
    dummy_cfg.write_text("")
    mp.setattr(constants, "BENCHMARK_METADATA_PATH", dummy_benchmarks)
    mp.setattr(constants, "STATE_DIR", tmp_state_dir)
    mp.setattr(constants, "CLI_STATE_FILE", tmp_state_dir / "state.json")
    mp.setattr(constants, "CONFIG_PATH", dummy_cfg)
    mp.setattr(constants, "LOCK_PATH", tmp_state_dir / "usg.lock")
    mp.setattr(constants, "CLI_LOG_FILE", tmp_state_dir / "usg.log")
    mp.setattr(constants, "DEFAULT_PRODUCT", "ubuntu2404")

    mp.setattr(utils, "check_perms", lambda *a, **k: None)
    mp.setattr(utils, "verify_integrity", lambda *a, **k: None)
    mp.setattr(cli, "acquire_lock", lambda: None)

    class DummyUSG(USG):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

        def audit(self, profile, debug=False, oval_results=False) -> tuple[AuditResults, BackendArtifacts]:
            print(
                f"Audit called with profile_id={profile.profile_id},"
                f"tailoring_file={profile.tailoring_file},"
                f"debug={debug},"
                f"oval_results={oval_results}."
                f"Benchmark={profile.benchmark_id}"
            )
            output_files = BackendArtifacts()
            output_files.add_artifact("audit_results", "test_results_contents")
            return AuditResults(), output_files

        def generate_fix(self, profile) -> BackendArtifacts:
            print(
                f"Generate fix called with profile_id={profile.profile_id},"
                f"tailoring_file={profile.tailoring_file}."
                f"Benchmark={profile.benchmark_id}"
            )
            output_files = BackendArtifacts()
            output_files.add_artifact("fix_script", "test_fix_contents")
            return output_files

        def fix(self, profile, audit_results_file=None) -> BackendArtifacts:
            fn = audit_results_file.name if audit_results_file else "None"
            print(
                f"Fix called with profile_id={profile.profile_id},"
                f"tailoring_file={profile.tailoring_file}."
                f"Benchmark={profile.benchmark_id}"
                f"audit_results_file={fn}"
            )
            output_files = BackendArtifacts()
            output_files.add_artifact("fix_script", "test_fix_contents")
            return output_files

    mp.setattr(cli, "USG", DummyUSG)
    mp.setattr(os, "geteuid", lambda: 0)
    mp.setattr(cli, "load_benchmark_version_state", lambda *a: "latest")
    mp.setattr(cli, "save_benchmark_version_state", lambda *a: None)


    # cd into a tmp dir and create a tailoring file in it
    # (hack to use hardcoded tailoring name in parametrized tests)
    test_dir = tmp_path_factory.mktemp("test_dir")
    os.chdir(test_dir)
    tailoring_file = test_dir / "tailoring.xml"
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="/usr/share/usg-benchmarks/ubuntu2404_CIS_1"/>
  <Profile id="tailored_profile">
    <select idref="xccdf_org.ssgproject.content_rule_test_rule" selected="true"/>
  </Profile>
</Tailoring>
"""
    tailoring_file.write_text(tailoring_xml)

    yield

    mp.undo()


def test_cli_non_root_user_error(monkeypatch, capsys):
    # test that non-root users cannot run the tool
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit) as e:
        cli.cli()
    assert e.value.code == 1
    captured = capsys.readouterr()
    assert (
        captured.err.strip()
        == "Error: this script must be run with super-user privileges."
    )

def test_cli_lock_error(monkeypatch, capsys):
    # test that failure to acquire lock is properly handled
    def fake_acquire_lock(*a, **kw):
        raise LockError("test lock failed")
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "acquire_lock", fake_acquire_lock)
    with pytest.raises(SystemExit) as e:
        cli.cli()
    assert e.value.code == 1
    captured = capsys.readouterr()
    assert captured.err.strip() == "test lock failed"

def test_command_error(patch_usg_and_cli, monkeypatch, capsys):
    # test that commands raising USGError are properly handled
    def fake_list(*a, **kw):
        raise USGError
    monkeypatch.setattr(cli, "command_list", fake_list)
    sys.argv = ["usg", "list"]
    with pytest.raises(SystemExit) as e:
        cli.cli()
    assert e.value.code == 1
    captured = capsys.readouterr()
    assert "Error: 'list' command failed" in captured.err

def test_usg_init_error(patch_usg_and_cli, monkeypatch, capsys):
    # test that USG initialization error is properly handled
    def fake_init(*a, **kw):
        raise USGError
    monkeypatch.setattr(cli.USG, "__init__", fake_init)
    sys.argv = ["usg", "list"]
    with pytest.raises(SystemExit) as e:
        cli.cli()
    assert e.value.code == 1
    captured = capsys.readouterr()
    assert "failed to initialize USG" in captured.err

@pytest.mark.parametrize(
    "cli_args,expected_stdout,expected_stderr,expected_exit_code",
    [
        # base commands
        ([], "Available commands are:", None, 2),
        (["--help"], "Available commands are:", None, 0),
        (["--version"], __version__.replace(".4.", ".04."), None, 0),
        (["notacommand"], None, "invalid choice:", 2),
        # list command
        (["list"], "Listing available profiles...", None, None),
        (["list", "asd"], None, "unrecognized arguments: asd", 2),
        (["list", "--all"], "v1.0.0", None, None),
        (["list", "--machine-readable"], "cis_level1_server:CIS:ubuntu2404:v2.0.0", None, None),
        (["list"], "v2.0.0", None, None),
        # successful commands with profile argument
        (["info", "cis_level1_server"], "ubuntu2404_CIS_3", None, None),
        (["audit", "cis_level1_server"], "ubuntu2404_CIS_3", None, None),
        (["fix", "cis_level1_server"], "ubuntu2404_CIS_3", None, None),
        (["generate-fix", "cis_level1_server"], "ubuntu2404_CIS_3", None, None),
        # successful commands with profile and version
        (["info", "cis_level1_server", "-b", "v1.0.0"], "ubuntu2404_CIS_1", None, None),
        (["audit", "cis_level1_server", "-b", "v1.0.0"], "ubuntu2404_CIS_1", None, None),
        (["fix", "cis_level1_server", "-b", "v1.0.0"], "ubuntu2404_CIS_1", None, None),
        (["generate-fix", "cis_level1_server", "-b", "v1.0.0"], "ubuntu2404_CIS_1", None, None),
        # successful commands with tailoring file
        (["info", "-t", "tailoring.xml"], "ubuntu2404_CIS_1", None, None),
        (["audit", "-t", "tailoring.xml"], "ubuntu2404_CIS_1", None, None),
        (["fix", "-t", "tailoring.xml"], "ubuntu2404_CIS_1", None, None),
        (["generate-fix", "-t", "tailoring.xml"], "ubuntu2404_CIS_1", None, None),
        # failed commands without a profile or a tailoring file
        (["info"], None, "Error: a profile or a tailoring file must be provided.", 2),
        (["audit"], None, "Error: a profile or a tailoring file must be provided.", 2),
        (["fix"], None, "Error: a profile or a tailoring file must be provided.", 2),
        (["generate-fix"], None, "Error: a profile or a tailoring file must be provided.", 2),
        # failed commands with bad profile
        (["info", "bad_profile"], None, "See `usg list --all` for list of available profiles.", 1),
        (["audit", "bad_profile"], None, "See `usg list --all` for list of available profiles.", 1),
        (["fix", "bad_profile"], None, "See `usg list --all` for list of available profiles.", 1),
        (["generate-fix", "bad_profile"], None, "See `usg list --all` for list of available profiles.", 1),
        # failed commands with bad version
        (["info", "cis_level1_server", "-b", "v10"], None, "See `usg list --all` for list of available profiles.", 1),
        (["audit", "cis_level1_server", "-b", "v10"], None, "See `usg list --all` for list of available profiles.", 1),
        (["fix", "cis_level1_server", "-b", "v10"], None, "See `usg list --all` for list of available profiles.", 1),
        (["generate-fix", "cis_level1_server", "-b", "v10"], None, "See `usg list --all` for list of available profiles.", 1),
        # failed commands with both a profile and a tailoring file
        (["info", "cis_level1_server", "-t", "tailoring.xml"], None, "You cannot provide both a tailoring file and a profile!", 2),
        (["audit", "cis_level1_server", "-t", "tailoring.xml"], None, "You cannot provide both a tailoring file and a profile!", 2),
        (["fix", "cis_level1_server", "-t", "tailoring.xml"], None, "You cannot provide both a tailoring file and a profile!", 2),
        (["generate-fix", "cis_level1_server", "-t", "tailoring.xml"], None, "You cannot provide both a tailoring file and a profile!", 2),
        # failed commands with both a tailoring file and a version
        (["info", "-b", "v1.0.0", "-t", "tailoring.xml"], None, "--benchmark-version cannot be used with a tailoring file.", 2),
        (["audit", "--benchmark-version", "v1.0.0", "-t", "tailoring.xml"], None, "--benchmark-version cannot be used with a tailoring file.", 2),
        (["fix", "-b", "v1.0.0", "-t", "tailoring.xml"], None, "--benchmark-version cannot be used with a tailoring file.", 2),
        (["generate-fix", "-b", "v1.0.0", "-t", "tailoring.xml"], None, "--benchmark-version cannot be used with a tailoring file.", 2),
        # audit command with extra arguments
        (["audit", "cis_level1_server", "--oval-results"], "oval_results=True", None, None),
        (["audit", "cis_level1_server", "--debug"], "debug=True", None, None),
        (["audit", "cis_level1_server", "--debug", "--oval-results"], "debug=True,oval_results=True", None, None),
        # generate-tailoring without required arguments
        (["generate-tailoring"], None, "following arguments are required:", 2),
        (["generate-tailoring", "cis_level1_server"], None, "following arguments are required:", 2),
        # fix command with extra arguments
        (["fix", "cis_level1_server"], "audit_results_file=None", None, None),
        (["fix", "cis_level1_server", "--only-failed"], "audit_results_file=test_results_content", None, None),
    ],
)
def test_cli_invocation(
    patch_usg_and_cli,
    capsys,
    cli_args,
    expected_stdout,
    expected_stderr,
    expected_exit_code,
):
    # Test the CLI with various arguments and verify the output
    sys.argv = ["usg", *cli_args]
    if expected_exit_code is not None:
        with pytest.raises(SystemExit) as e:
            cli.cli()
        assert e.value.code == expected_exit_code
    else:
        cli.cli()

    captured = capsys.readouterr()
    if expected_stdout is not None:
        assert expected_stdout in captured.out
    if expected_stderr is not None:
        assert expected_stderr in captured.err


@pytest.mark.parametrize(
    "cli_args,benchmark_id",
    [
        (
            ["generate-tailoring", "cis_level1_server", "gen-tail-out.xml"],
            "ubuntu2404_CIS_3",
        ),
        (
            ["generate-tailoring", "cis_level1_server", "gen-tail-out.xml", "-b", "v1.0.0",],
            "ubuntu2404_CIS_1",
        ),
    ],
)
def test_cli_generate_tailoring(
    patch_usg_and_cli, tmp_path, capsys, cli_args, benchmark_id
):
    # Test that the CLI correctly generates a tailoring file
    sys.argv = ["usg", *cli_args]
    cli.cli()
    captured = capsys.readouterr()
    assert Path("gen-tail-out.xml").exists()
    assert "generate-tailoring command completed" in captured.out


def test_cli_generate_tailoring_os_error(patch_usg_and_cli, capsys):
    # Test error if file cannot be written
    sys.argv = ["usg", "generate-tailoring", "cis_level1_server", "/dev/null/nonwritable/test.xml"]
    with pytest.raises(SystemExit) as e:
        cli.cli()
    assert e.value.code == 1
    captured = capsys.readouterr()
    assert not Path("/dev/null/nonwritable/test.xml").exists()
    assert "Failed to write file" in captured.err
    

def test_cli_default_tailoring_file(patch_usg_and_cli, monkeypatch, capsys, caplog, tmp_path):
    # Test if default tailoring file is loaded
    default_tailoring_file = tmp_path / "default-tailoring.xml"
    default_tailoring_file.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="/usr/share/usg-benchmarks/ubuntu2404_CIS_3"/>
  <Profile id="tailored_profile">
    <select idref="xccdf_org.ssgproject.content_rule_test_rule" selected="true"/>
  </Profile>
</Tailoring>
""")
    sys.argv = ["usg", "info"]
    
    # ensure it fails when tailoring doesn't exist
    monkeypatch.setattr(constants, "DEFAULT_TAILORING_PATH", "/dev/null/tailoring_file")
    with pytest.raises(SystemExit) as e:
        cli.cli()    

    monkeypatch.setattr(constants, "DEFAULT_TAILORING_PATH", default_tailoring_file)
    cli.cli() # should not fail
    captured = capsys.readouterr()
    assert f"Using the default tailoring file at {default_tailoring_file}" in captured.out
    assert "tailored_profile" in captured.out


def test_load_benchmark_version_state(tmp_path, monkeypatch):
    # Test that the benchmark version is correctly loaded from the state file
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(constants, "CLI_STATE_FILE", state_file)

    # missing file should default to "latest" version
    assert load_benchmark_version_state("cis_level1_server") == "latest"

    Path(state_file).write_text(json.dumps({
        "benchmark_versions": {
            "cis_level1_server": "test_version"
        }
    }))
    assert load_benchmark_version_state("cis_level1_server") == "test_version"

    # missing benchmark profile defaults to "latest" version
    assert load_benchmark_version_state("missing_profile") == "latest"


def test_load_benchmark_version_state_error(tmp_path, monkeypatch):
    # Test that corrupt/unreadable state file results in error
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(constants, "CLI_STATE_FILE", state_file)

    # non-json
    Path(state_file).write_text("test")
    with pytest.raises(StateFileError, match="Corrupted"):
        load_benchmark_version_state("cis_level1_server")

    # bad data
    Path(state_file).write_text(json.dumps({
        "bad_key_for_benchmark_versions": {
            "cis_level1_server": "test_version"
        }
    }))
    with pytest.raises(StateFileError, match="Corrupted"):
        load_benchmark_version_state("cis_level1_server")


def test_save_benchmark_version_state(tmp_path, monkeypatch):
    # Test that benchmark version state is stored correctly to state file
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(constants, "CLI_STATE_FILE", state_file)

    # non-existing file should be created
    Path(state_file).unlink(missing_ok=True)
    save_benchmark_version_state("cis_level1_server", "test_version")
    assert load_benchmark_version_state("cis_level1_server") == "test_version"

    # existing file should be updated
    save_benchmark_version_state("cis_level1_server", "test_version2")
    assert load_benchmark_version_state("cis_level1_server") == "test_version2"


def test_save_benchmark_version_state_corrupted_error(tmp_path, monkeypatch):
    # Test that corrupted state file raises error
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(constants, "CLI_STATE_FILE", state_file)

    # corrupt state data
    Path(state_file).write_text("asd")
    with pytest.raises(StateFileError, match="Corrupted"):
        save_benchmark_version_state("cis_level1_server", "test_version")


def test_save_benchmark_version_state_write_error(tmp_path, monkeypatch):
    # Test that permission failure when saving state file raises error
    monkeypatch.setattr(constants, "CLI_STATE_FILE", "/dev/null/notwritable/usg.json")
    with pytest.raises(StateFileError, match="Failed to write to state file"):
        save_benchmark_version_state("cis_level1_server", "test_version2")


def test_benchmark_version_state_integration(patch_usg_and_cli, capsys, monkeypatch, tmp_path):
    # test that cli commands retain benchmark version across runs

    # hack to undo monkepatches to load/save_state functions done in patch_usg_and_cli
    from usg.cli import USG as DummyUSG
    importlib.reload(cli)
    monkeypatch.setattr(cli, "USG", DummyUSG)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "acquire_lock", lambda: None)

    # no args switches initializes to "latest", which is "v2.0.0" in test benchmarks
    sys.argv = ["usg", "audit", "cis_level1_server"]
    cli.cli()
    assert load_benchmark_version_state("cis_level1_server") == "v2.0.0"

    # re-set to v1.0.1
    sys.argv = ["usg", "audit", "cis_level1_server", "-b", "v1.0.1"]
    cli.cli()
    assert load_benchmark_version_state("cis_level1_server") == "v1.0.1"

    # no args reuses v1.0.1
    sys.argv = ["usg", "audit", "cis_level1_server"]
    cli.cli()
    assert load_benchmark_version_state("cis_level1_server") == "v1.0.1"

    # confirm with fix
    sys.argv = ["usg", "fix", "cis_level1_server"]
    cli.cli()
    assert load_benchmark_version_state("cis_level1_server") == "v1.0.1"

    # confirm with generate-fix
    sys.argv = ["usg", "generate-fix", "cis_level1_server"]
    cli.cli()
    assert load_benchmark_version_state("cis_level1_server") == "v1.0.1"

    # re-set to latest
    sys.argv = ["usg", "generate-fix", "cis_level1_server", "--benchmark-version", "latest"]
    cli.cli()
    assert load_benchmark_version_state("cis_level1_server") == "v2.0.0"


def test_init_logging(capsys, tmp_path):
    # test that info logs are written to file and that warning+ go to stderr
    logfile = tmp_path / "logfile"
    init_logging(logfile, False)
    logger.debug("TEST DEBUG")
    logger.info("TEST INFO")
    logger.warning("TEST WARNING")

    logs = logfile.read_text()
    assert "TEST DEBUG" not in logs
    assert "TEST INFO" in logs
    assert "TEST WARNING" in logs
    captured = capsys.readouterr()
    assert "TEST DEBUG" not in captured.err
    assert "TEST INFO" not in captured.err
    assert "TEST WARNING" in captured.err


def test_init_logging_debug(capsys, tmp_path):
    # test that debug logs are written to file
    logfile = tmp_path / "logfile"
    init_logging(logfile, True)
    logger.debug("TEST DEBUG")
    logger.info("TEST INFO")

    logs = logfile.read_text()
    assert "TEST DEBUG" in logs
    assert "TEST INFO" in logs
    captured = capsys.readouterr()
    assert "TEST DEBUG" not in captured.err

 
def test_init_logging_error_writing_to_file(capsys):
    # test that logs go to stderr if logfile cannot be written
    init_logging(Path("/dev/null/nonwritable/logfile"), False)
    captured = capsys.readouterr()
    assert not Path("/dev/null/nonwritable/logfile").exists()
    assert "Writing logs to stderr" in captured.err
    assert "Initialized logging" in captured.err

def test_main_error_kbd_interrupt(monkeypatch, capsys, tmp_path):
    def fake_cli():
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "cli", fake_cli)
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 1
    captured = capsys.readouterr()
    assert "Caught keyboard interrupt" in captured.err

def test_main_error_runtime(monkeypatch, capsys, caplog):
    def fake_cli():
        raise ValueError("testing error")
    
    monkeypatch.setattr(cli, "cli", fake_cli)
    with pytest.raises(SystemExit) as e:
        cli.main()
    assert e.value.code == 1
    captured = capsys.readouterr()
    assert "USG encountered an unknown error" in captured.err
    assert "ValueError: testing error" in caplog.text
