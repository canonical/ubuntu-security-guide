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
from usg.cli import init_logging
from usg.exceptions import LockError, USGError
from usg.usg import USG
from usg.results import AuditResults, BackendArtifacts

logger = logging.getLogger(__name__)

@pytest.fixture
def patch_usg_and_cli(tmp_path_factory, test_metadata):
    # patch the usg module:
    # - set benchmarks to dummy benchmarks fixture
    # - set state_dir to a tmp path
    # - set default product to match dummy_benchmarks
    # - set check_perms, verify_integrity, and acquire_lock to no-ops
    # - patch USG with a dummy USG class overriding audit, generate_fix, fix
    # - change working directory to a tmp dir and create tailoring file in it
    #   and set save_state to noop
    mp = MonkeyPatch()

    tmp_state_dir = tmp_path_factory.mktemp("var_dir")

    dummy_cfg = tmp_state_dir / "usg.conf"
    dummy_cfg.write_text("")
    mp.setattr(constants, "BENCHMARK_METADATA_PATH", test_metadata)
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
                f"Audit called with profile_id={profile.id},"
                f"tailoring_file={profile.tailoring_file},"
                f"extended_profile_id={profile.extends_id},"
                f"debug={debug},"
                f"oval_results={oval_results},"
                f"benchmark={profile.benchmark.id}"
            )
            output_files = BackendArtifacts()
            output_files.add_artifact("audit_results", "test_results_contents")
            output_files.add_artifact("audit_report", "test_report_contents")
            return AuditResults(), output_files

        def generate_fix(self, profile) -> BackendArtifacts:
            print(
                f"Generate fix called with profile_id={profile.id},"
                f"tailoring_file={profile.tailoring_file},"
                f"extended_profile_id={profile.extends_id},"
                f"benchmark={profile.benchmark.id}"
            )
            output_files = BackendArtifacts()
            output_files.add_artifact("fix_script", "test_fix_contents")
            return output_files

        def fix(self, profile, audit_results_file=None) -> BackendArtifacts:
            fn = audit_results_file.name if audit_results_file else "None"
            print(
                f"Fix called with profile_id={profile.id},"
                f"tailoring_file={profile.tailoring_file},"
                f"extended_profile_id={profile.extends_id},"
                f"benchmark={profile.benchmark.id},"
                f"audit_results_file={fn}"
            )
            output_files = BackendArtifacts()
            output_files.add_artifact("fix_script", "test_fix_contents")
            return output_files

    mp.setattr(cli, "USG", DummyUSG)
    mp.setattr(os, "geteuid", lambda: 0)


    # cd into a tmp dir and create a tailoring file in it
    # (hack to use hardcoded tailoring name in parametrized tests)
    test_dir = tmp_path_factory.mktemp("test_dir")
    os.chdir(test_dir)
    tailoring_file = test_dir / "tailoring.xml"
    tailoring_xml = """<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark href="/usr/share/usg-benchmarks/ubuntu2404_CIS_2"/>
  <Profile id="tailored_profile" extends="cis_level1_server">
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
        (["list"], "Listing latest profiles", None, None),
        (["list", "asd"], None, "unrecognized arguments: asd", 2),
        (["list", "--all"], "v1.0.0", None, None),
        (["list", "-a"], "v1.0.0", None, None),
        (["list", "--machine-readable"], "cis_level1_server:CIS:ubuntu2404:v2.0.0", None, None),
        (["list", "-m"], "cis_level1_server:CIS:ubuntu2404:v2.0.0", None, None),
        (["list"], "v2.0.0", None, None),
        # successful commands with new profile id
        (["info", "cis_level1_server-v2.0.0"], "ubuntu2404_CIS_3", None, None),
        (["audit", "cis_level1_server-v2.0.0"], "ubuntu2404_CIS_3", None, None),
        (["fix", "cis_level1_server-v2.0.0"], "ubuntu2404_CIS_3", None, None),
        (["generate-fix", "cis_level1_server-v2.0.0"], "ubuntu2404_CIS_3", None, None),
        (["generate-fix", "cis_level1_server-v2.0.0", "-o", "fix.sh"], "ubuntu2404_CIS_3", None, None),
        (["generate-fix", "cis_level1_server-v2.0.0", "--output", "fix.sh"], "ubuntu2404_CIS_3", None, None),
        # successful commands with legacy fallback profile id
        (["info", "cis_level1_server"], "ubuntu2404_CIS_1", None, None),
        (["info", "stig"], "ubuntu2404_STIG_1", None, None),
        (["info", "disa_stig"], "ubuntu2404_STIG_1", None, None),
        (["audit", "cis_level1_server"], "ubuntu2404_CIS_1", None, None),
        (["fix", "cis_level1_server"], "ubuntu2404_CIS_1", None, None),
        (["generate-fix", "cis_level1_server"], "ubuntu2404_CIS_1", None, None),
        # successful commands with tailoring file
        (["info", "-t", "tailoring.xml"], "ubuntu2404_CIS_2", None, None),
        (["audit", "-t", "tailoring.xml"], "ubuntu2404_CIS_2", None, None),
        (["fix", "-t", "tailoring.xml"], "ubuntu2404_CIS_2", None, None),
        (["generate-fix", "--tailoring-file", "tailoring.xml"], "ubuntu2404_CIS_2", None, None),
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
        # failed commands with both a profile and a tailoring file
        (["info", "cis_level1_server", "-t", "tailoring.xml"], None, "You cannot provide both a tailoring file and a profile!", 2),
        (["audit", "cis_level1_server", "-t", "tailoring.xml"], None, "You cannot provide both a tailoring file and a profile!", 2),
        (["fix", "cis_level1_server", "-t", "tailoring.xml"], None, "You cannot provide both a tailoring file and a profile!", 2),
        (["generate-fix", "cis_level1_server", "--tailoring-file", "tailoring.xml"], None, "You cannot provide both a tailoring file and a profile!", 2),
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
            ["generate-tailoring", "cis_level1_server-v2.0.0", "gen-tail-out.xml"],
            "ubuntu2404_CIS_3",
        ),
        (
            ["generate-tailoring", "cis_level1_server", "gen-tail-out.xml"],
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
    assert "generate-tailoring command completed" in captured.err


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
  <Profile id="tailored_profile" extends="cis_level1_server">
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
    assert f"Using the default tailoring file at {default_tailoring_file}" in captured.err
    assert "tailored_profile" in captured.out


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

def test_list_machine_readable(
    patch_usg_and_cli,
    capsys,
):
    # Test machine readable output
    sys.argv = ["usg", "list", "--all", "--machine-readable"]
    cli.cli()
    captured = capsys.readouterr()
    match_line = (
        "cis_level1_workstation-v1.0.1:cis_level1_workstation:CIS:ubuntu2404:v1.0.1:ubuntu2404_CIS_2-v1.0.1:Maintenance:ubuntu2404_CIS_2:2::::::"
    )
    assert match_line in captured.out
    match_line = (
        "cis_level1_workstation-v2.0.0:cis_level1_workstation:CIS:ubuntu2404:v2.0.0:ubuntu2404_CIS_3-v2.0.0:Latest stable:ubuntu2404_CIS_3:3::::::"
    )
    assert match_line in captured.out
    