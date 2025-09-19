import json
import os
import sys
from pathlib import Path

import pytest
from pytest import MonkeyPatch

from usg import __version__
from usg.results import AuditResults, BackendArtifacts


@pytest.fixture
def patch_usg_and_cli(tmp_path_factory, dummy_benchmarks):
    # patch the usg module:
    # - set benchmarks to dummy benchmarks fixture
    # - set state_dir to a tmp path
    # - set validate_perms and verify_integrity to no-ops
    # - patch USG with a dummy USG class overriding audit, generate_fix, fix
    # - change working directory to a tmp dir and create tailoring file in it
    # - patch load state functions to always return "latest" (always clean slate and no state file)
    #   and set save_state to noop
    mp = MonkeyPatch()

    tmp_state_dir = tmp_path_factory.mktemp("var_dir")
    from usg import constants as constants_module

    mp.setattr(constants_module, "BENCHMARK_METADATA_PATH", dummy_benchmarks)
    mp.setattr(constants_module, "STATE_DIR", tmp_state_dir)
    mp.setattr(constants_module, "CLI_STATE_FILE", tmp_state_dir / "state.json")
    mp.setattr(constants_module, "LOCK_PATH", tmp_state_dir / "usg.lock")

    from usg import usg as usg_module

    mp.setattr(usg_module, "validate_perms", lambda *a, **k: None)
    mp.setattr(usg_module, "verify_integrity", lambda *a, **k: None)

    from usg.usg import USG

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
            output_files.add_artifact("results", "test_results_contents")
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

        def fix(self, profile, only_failed=False) -> BackendArtifacts:
            print(
                f"Fix called with profile_id={profile.profile_id},"
                f"tailoring_file={profile.tailoring_file}."
                f"Benchmark={profile.benchmark_id}"
                f"only_failed={only_failed}"
            )
            output_files = BackendArtifacts()
            output_files.add_artifact("fix_script", "test_fix_contents")
            return output_files

    from usg import cli as cli_module

    mp.setattr(cli_module, "USG", DummyUSG)
    mp.setattr(cli_module.os, "geteuid", lambda: 0)
    mp.setattr(cli_module, "load_benchmark_version_state", lambda *a: "latest")
    mp.setattr(cli_module, "save_benchmark_version_state", lambda *a: None)


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


def test_cli_non_root_user(monkeypatch, capsys):
    from usg import cli as cli_module

    monkeypatch.setattr(cli_module.os, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit) as e:
        cli_module.cli()
    assert e.value.code == 1
    captured = capsys.readouterr()
    assert (
        captured.err.strip()
        == "Error: this script must be run with super-user privileges."
    )


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
        (["list", "--names-only"], "cis_level1_server", None, None),        
        (["list"], "v2.0.0", None, None),
        # successfulcommands with profile argument
        (["info", "cis_level1_server"], "ubuntu2404_CIS_3", None, None),
        (["audit", "cis_level1_server"], "ubuntu2404_CIS_3", None, None),
        (["fix", "cis_level1_server"], "ubuntu2404_CIS_3", None, None),
        (["generate-fix", "cis_level1_server"], "ubuntu2404_CIS_3", None, None),
        # successfulcommands with profile and version
        (["info", "cis_level1_server", "-b", "v1.0.0"], "ubuntu2404_CIS_1", None, None),
        (["audit", "cis_level1_server", "-b", "v1.0.0"], "ubuntu2404_CIS_1", None, None),
        (["fix", "cis_level1_server", "-b", "v1.0.0"], "ubuntu2404_CIS_1", None, None),
        (["generate-fix", "cis_level1_server", "-b", "v1.0.0"], "ubuntu2404_CIS_1", None, None),
        # successfulommands with tailoring file
        (["info", "-t", "tailoring.xml"], "ubuntu2404_CIS_1", None, None),
        (["audit", "-t", "tailoring.xml"], "ubuntu2404_CIS_1", None, None),
        (["fix", "-t", "tailoring.xml"], "ubuntu2404_CIS_1", None, None),
        (["generate-fix", "-t", "tailoring.xml"], "ubuntu2404_CIS_1", None, None),
        # failed commands without a profile or a tailoring file
        (["info"], None, "Error: a profile or a tailoring file must be provided.", 2),
        (["audit"], None, "Error: a profile or a tailoring file must be provided.", 2),
        (["fix"], None, "Error: a profile or a tailoring file must be provided.", 2),
        (["generate-fix"], None, "Error: a profile or a tailoring file must be provided.", 2),
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
        (["fix", "cis_level1_server"], "only_failed=False", None, None),
        (["fix", "cis_level1_server", "--only-failed"], "only_failed=True", None, None),
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
    from usg import cli

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

    # Create a dummy tailoring file template in the datastream directory
    from usg.constants import BENCHMARK_METADATA_PATH

    tailoring_file = (
        BENCHMARK_METADATA_PATH.parent
        / benchmark_id
        / "tailoring"
        / "cis_level1_server-tailoring.xml"
    )
    tailoring_file.parent.mkdir(parents=True, exist_ok=True)
    tailoring_file.write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<Tailoring xmlns="http://checklists.nist.gov/xccdf/1.2">
  <benchmark id="{benchmark_id}"/>
  <Profile id="tailored_profile">
    <select idref="xccdf_org.ssgproject.content_rule_test_rule" selected="true"/>
    </Profile>
</Tailoring>""")
    
    sys.argv = ["usg", *cli_args]

    from usg import cli
    cli.cli()
    captured = capsys.readouterr()
    assert Path("gen-tail-out.xml").exists()
    assert "generate-tailoring command completed" in captured.out
    os.remove(tailoring_file)
    os.remove("gen-tail-out.xml")


def test_load_benchmark_version_state(tmp_path, monkeypatch):
    # Test that the benchmark version is correctly loaded from the state file
    from usg import constants as constants_module
    from usg.cli import load_benchmark_version_state

    state_file = tmp_path / "state.json"
    monkeypatch.setattr(constants_module, "CLI_STATE_FILE", state_file)

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
    from usg import constants as constants_module
    from usg.cli import load_benchmark_version_state, StateFileError

    state_file = tmp_path / "state.json"
    monkeypatch.setattr(constants_module, "CLI_STATE_FILE", state_file)

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
    from usg import constants as constants_module
    from usg.cli import save_benchmark_version_state, load_benchmark_version_state

    state_file = tmp_path / "state.json"
    monkeypatch.setattr(constants_module, "CLI_STATE_FILE", state_file)

    # non-existing file should be created
    Path(state_file).unlink(missing_ok=True)
    save_benchmark_version_state("cis_level1_server", "test_version")
    assert load_benchmark_version_state("cis_level1_server") == "test_version"

    # existing file should be updated
    save_benchmark_version_state("cis_level1_server", "test_version2")
    assert load_benchmark_version_state("cis_level1_server") == "test_version2"


def test_save_benchmark_version_state_error(tmp_path, monkeypatch):
    # Test that benchmark version state is stored correctly to state file
    from usg import constants as constants_module
    from usg.cli import save_benchmark_version_state, load_benchmark_version_state, StateFileError

    state_file = tmp_path / "state.json"
    monkeypatch.setattr(constants_module, "CLI_STATE_FILE", state_file)

    # corrupt state data
    Path(state_file).write_text("asd")
    with pytest.raises(StateFileError, match="Corrupted"):
        save_benchmark_version_state("cis_level1_server", "test_version")
    
    # permission error should result in statefileerror
    Path(state_file).write_text(json.dumps({
        "benchmark_versions": {
            "cis_level1_server": "test_version"
        }
    }))
    tmp_path.chmod(0o500) # prevent moving the state tmpfile to final dest
    with pytest.raises(StateFileError, match="Failed to write to state file"):
        save_benchmark_version_state("cis_level1_server", "test_version2")


def test_benchmark_version_state_integration(patch_usg_and_cli, capsys, monkeypatch, tmp_path):
    # test that cli commands retain benchmark version across runs
     
     # hack to undo monkepatches to state functions done in patch_usg_and_cli
    from usg import cli
    from usg.cli import USG as DummyUSG
    import importlib
    importlib.reload(cli)
    monkeypatch.setattr(cli, "USG", DummyUSG)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "acquire_lock", lambda: None)

    from usg.cli import load_benchmark_version_state

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
