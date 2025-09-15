import configparser
import os

import pytest

from usg import backends
from usg.results import AuditResults, BackendArtifacts

TEST_DS_NAME = "ssg-testproduct-ds.xml"
TEST_PROFILE_ID = "test_profile"


@pytest.fixture
def dummy_datastream(tmp_path):
    # Create a dummy datastream file
    ds_path = tmp_path / TEST_DS_NAME
    ds_path.write_text("<Benchmark></Benchmark>")
    os.chmod(ds_path, 0o600)
    return ds_path


@pytest.fixture
def dummy_openscap_bin(tmp_path):
    # Create a dummy executable file
    # - Echo args to args
    # - Create dummy results file if eval is passed
    # - Create dummy oval results files if eval is passed
    # - Exit with status 0
    bin_path = tmp_path / "test_oscap.sh"
    bin_path.write_text(f"""\
#!/bin/bash

# echo args to file
echo -n $@ > test_oscap.args
echo -n "$PWD" > test_oscap.cwd

if grep -qw -- "eval" <<< "$@"; then
    # create results file with dummy results
    while [[ $# -gt 0 ]]; do
        if [[ "$1" == "--results" ]]; then
            echo "<Benchmark><TestResult><rule-result idref='xccdf_org.ssgproject.content_rule_test_rule_name'><result>pass</result></rule-result></TestResult></Benchmark>" > $2
            shift
        elif [[ "$1" == "--report" ]]; then
            echo "test_report_contents" > $2
            shift
        elif [[ "$1" == "--verbose-log-file" ]]; then
            echo "test_log_contents" > $2
            shift
        fi
        shift
    done

    # dummy oval results files (hardcoded names)
    echo "test_oval_results" > {TEST_DS_NAME.replace("-ds.xml", "-oval.xml.result.xml")}
    echo "test_oval_cpe_results" > {TEST_DS_NAME.replace("-ds.xml", "-cpe-oval.xml.result.xml")}

elif grep -qw -- "generate" <<< "$@"; then
    if grep -qw -- "--result-id" <<< "$@"; then
        output_str="#TEST FIX OUTPUT USING AUDIT RESULTS"
    else
        output_str="#TEST FIX OUTPUT WITHOUT AUDIT RESULTS"
    fi
    # create dummy fix file
    while [[ $# -gt 0 ]]; do
        if [[ "$1" == "--output" ]]; then
            echo -n "$output_str" > $2
        fi
        shift
    done

elif grep -qw -- "--version" <<< "$@"; then
    echo "OpenSCAP command line tool (oscap) 1.3.9"
fi

exit 0
""")
    os.chmod(bin_path, 0o755)
    return bin_path


@pytest.fixture
def oscap_backend(
    monkeypatch, tmp_path, dummy_datastream, dummy_openscap_bin
):
    # Fixture to create a dummy backends.OpenscapBackend
    # - Patch validate_perms to always pass
    # - Patch os.access to always True
    # - Patch version function to always return (1,3,9)
    # - Return a dummy backends.OpenscapBackend

    monkeypatch.setattr(backends, "validate_perms", lambda path, *a, **kw: None)
    monkeypatch.setattr(backends.os, "access", lambda path, mode: True)
    monkeypatch.setattr(backends.OpenscapBackend, "_get_oscap_version",
                        lambda *a: (1, 3, 9))

    return backends.OpenscapBackend(
        datastream_file=dummy_datastream,
        openscap_bin_path=dummy_openscap_bin,
        work_dir=tmp_path,
    )


# ---- OpenscapBackend initialization ----
def test_oscap_backend_initialization(
    monkeypatch, tmp_path, dummy_datastream, dummy_openscap_bin
):
    monkeypatch.setattr(backends, "validate_perms", lambda path, *a, **kw: None)
    monkeypatch.setattr(backends.os, "access", lambda path, mode: True)

    oscap = backends.OpenscapBackend(
        datastream_file=dummy_datastream,
        openscap_bin_path=dummy_openscap_bin,
        work_dir=tmp_path,
    )


# ---- OpenscapBackend initialization error tests ----


def test_oscap_backend_error_on_non_executable_oscap(
    monkeypatch, tmp_path, dummy_datastream, dummy_openscap_bin
):
    # Test that a non-executable oscap fails
    os.chmod(dummy_openscap_bin, 0o644)
    monkeypatch.setattr(backends, "validate_perms", lambda path, *a, **kw: None)
    with pytest.raises(backends.BackendError):
        backends.OpenscapBackend(
            datastream_file=dummy_datastream,
            openscap_bin_path=dummy_openscap_bin,
            work_dir=tmp_path,
        )


def test_oscap_backend_error_on_bad_oscap_permissions(
    monkeypatch, tmp_path, dummy_datastream, dummy_openscap_bin
):
    # Test that a bad permissions oscap fails
    os.chmod(dummy_openscap_bin, 0o777)
    os.chmod(tmp_path, 0o700)
    with pytest.raises(backends.BackendError):
        backends.OpenscapBackend(
            datastream_file=dummy_datastream,
            openscap_bin_path=dummy_openscap_bin,
            work_dir=tmp_path,
        )


def test_oscap_backend_error_on_bad_tmp_work_dir_permissions(
    monkeypatch, tmp_path, dummy_datastream, dummy_openscap_bin
):
    # Test that a bad permissions tmp_work_dir fails
    os.chmod(dummy_openscap_bin, 0o700)
    os.chmod(tmp_path, 0o777)
    with pytest.raises(backends.BackendError):
        backends.OpenscapBackend(
            datastream_file=dummy_datastream,
            openscap_bin_path=dummy_openscap_bin,
            work_dir=tmp_path,
        )


# ---- OpenscapBackend audit tests ----


def test_audit_runs_and_parses_results(oscap_backend, tmp_path):
    # Test that audit runs and parses dummy results
    results, artifacts = oscap_backend.audit(
        cac_profile=TEST_PROFILE_ID, tailoring_file=None, debug=True
    )
    assert isinstance(results, AuditResults)
    # Should contain the test rule
    assert len(results) == 1
    assert results[0].rule_name == "test_rule_name"
    assert results[0].state == "pass"
    assert results[0].message == ""
    # Should contain some output files
    assert isinstance(artifacts, BackendArtifacts)
    assert len(artifacts) == 5
    assert (
        artifacts.get_by_type("audit_report").path.read_text()
        == "test_report_contents\n"
    )
    assert artifacts.get_by_type("audit_results").path.exists()
    assert artifacts.get_by_type("audit_oval_results").path.exists()
    assert artifacts.get_by_type("audit_oval_cpe_results").path.exists()
    assert artifacts.get_by_type("audit_log").path.exists()


def test_audit_command_line_options(
    monkeypatch, oscap_backend, tmp_path, dummy_datastream
):
    # Test that command line options are correct
    monkeypatch.setattr(oscap_backend, "_parse_audit_results", lambda x: None)
    results, artifacts = oscap_backend.audit(
        cac_profile=TEST_PROFILE_ID,
        tailoring_file=None,
    )
    args = (tmp_path / "test_oscap.args").read_text()
    log_file = (
        oscap_backend._work_dir / oscap_backend.ARTIFACT_FILENAMES["audit_log"]
    )
    results_file = (
        oscap_backend._work_dir / oscap_backend.ARTIFACT_FILENAMES["audit_results"]
    )
    report_file = (
        oscap_backend._work_dir / oscap_backend.ARTIFACT_FILENAMES["audit_report"]
    )

    assert args == (
        f"xccdf --verbose WARNING --verbose-log-file {log_file} eval "
        f"--results {results_file} "
        f"--report {report_file} "
        f"--profile {TEST_PROFILE_ID} "
        f"{dummy_datastream}"
    )


def test_audit_command_line_options_old_oscap_version(
    monkeypatch, oscap_backend, tmp_path, dummy_datastream
):
    # Test that command line options are correct on oscap < 1.3.0
    monkeypatch.setattr(oscap_backend, "_parse_audit_results", lambda x: None)
    oscap_backend._oscap_version = (1, 2, 17)
    results, artifacts = oscap_backend.audit(
        cac_profile=TEST_PROFILE_ID,
        tailoring_file=None,
    )
    args = (tmp_path / "test_oscap.args").read_text()
    log_file = (
        oscap_backend._work_dir / oscap_backend.ARTIFACT_FILENAMES["audit_log"]
    )
    results_file = (
        oscap_backend._work_dir / oscap_backend.ARTIFACT_FILENAMES["audit_results"]
    )
    report_file = (
        oscap_backend._work_dir / oscap_backend.ARTIFACT_FILENAMES["audit_report"]
    )

    assert args == (
        f"xccdf eval "
        f"--results {results_file} "
        f"--report {report_file} "
        f"--profile {TEST_PROFILE_ID} "
        f"--verbose WARNING --verbose-log-file {log_file} "
        f"{dummy_datastream}"
    )



def test_audit_command_line_options_with_tailoring(
    monkeypatch, oscap_backend, tmp_path
):
    # Test that command line options are correct
    monkeypatch.setattr(oscap_backend, "_parse_audit_results", lambda x: None)
    tailoring_file = tmp_path / "dummy_tailoring_file.xml"
    results, artifacts = oscap_backend.audit(
        cac_profile=TEST_PROFILE_ID,
        tailoring_file=tailoring_file,
        debug=False,
        oval_results=False,
    )
    args = (tmp_path / "test_oscap.args").read_text()  # type: ignore
    assert f"--tailoring-file {tailoring_file}" in args


def test_audit_command_line_options_with_debug(monkeypatch, oscap_backend, tmp_path):
    # Test that command line options are correct
    monkeypatch.setattr(oscap_backend, "_parse_audit_results", lambda x: None)
    results, artifacts = oscap_backend.audit(
        cac_profile=TEST_PROFILE_ID, tailoring_file=None, debug=True, oval_results=False
    )
    args = (tmp_path / "test_oscap.args").read_text()  # type: ignore
    assert "--verbose INFO" in args
    assert "--oval-results" in args


def test_audit_command_line_options_with_oval_results(
    monkeypatch, oscap_backend, tmp_path
):
    # Test that command line options are correct
    monkeypatch.setattr(oscap_backend, "_parse_audit_results", lambda x: None)
    results, artifacts = oscap_backend.audit(
        cac_profile=TEST_PROFILE_ID, tailoring_file=None, debug=False, oval_results=True
    )
    args = (tmp_path / "test_oscap.args").read_text()  # type: ignore
    assert "--oval-results" in args


# ---- _parse_audit_results tests ----


def test_parse_audit_results_invalid_xml(oscap_backend, tmp_path):
    # Test that invalid xml fails
    xml = tmp_path / "bad_results_file.xml"
    xml.write_text("<notxml>")
    with pytest.raises(backends.BackendError):
        oscap_backend._parse_audit_results(xml)


def test_parse_audit_results_unknown_root_element(oscap_backend, tmp_path):
    # Test that unknown root element fails
    xml = tmp_path / "unknown_root_element.xml"
    xml.write_text(
        "<BadRoot><TestResult><rule-result idref='xccdf_org.ssgproject.content_rule_test'><result>pass</result></rule-result></TestResult></BadRoot>"
    )
    with pytest.raises(backends.BackendError):
        oscap_backend._parse_audit_results(xml)


def test_parse_audit_results_missing_testresult(oscap_backend, tmp_path):
    # Test that missing testresult fails
    xml = tmp_path / "no_testresult.xml"
    xml.write_text("<Benchmark></Benchmark>")
    with pytest.raises(backends.BackendError):
        oscap_backend._parse_audit_results(xml)


def test_parse_audit_results_missing_rule_id(oscap_backend, tmp_path):
    # Test that missing rule id fails
    xml = tmp_path / "no_rule_id.xml"
    xml.write_text(
        "<Benchmark><TestResult><rule-result><result>pass</result></rule-result></TestResult></Benchmark>"
    )
    with pytest.raises(backends.BackendError):
        oscap_backend._parse_audit_results(xml)


def test_parse_audit_results_missing_result(oscap_backend, tmp_path):
    # Test that missing result fails
    xml = tmp_path / "no_result.xml"
    xml.write_text(
        "<Benchmark><TestResult><rule-result idref='xccdf_org.ssgproject.content_rule_test'></rule-result></TestResult></Benchmark>"
    )
    with pytest.raises(backends.BackendError):
        oscap_backend._parse_audit_results(xml)


def test_parse_audit_results_notselected_rule(oscap_backend, tmp_path):
    # Test that notselected rule is ignored
    xml = tmp_path / "notselected_rule.xml"
    xml.write_text(
        "<Benchmark><TestResult><rule-result idref='xccdf_org.ssgproject.content_rule_test'><result>notselected</result></rule-result></TestResult></Benchmark>"
    )
    results = oscap_backend._parse_audit_results(xml)
    assert len(results) == 0


# ---- OpenscapBackend fix tests ----


def test_fix_runs_and_creates_script(oscap_backend, tmp_path):
    # Test that fix runs and creates fix file
    artifacts = oscap_backend.fix(cac_profile=TEST_PROFILE_ID, tailoring_file=None)
    # The copy of the fix file should exist with correct content
    fix_file = artifacts.get_by_type("fix_script").path
    print(fix_file)
    print((tmp_path / "test_oscap.args").read_text())

    assert fix_file.read_text() == "#TEST FIX OUTPUT WITHOUT AUDIT RESULTS"


def test_fix_runs_and_creates_script_with_audit_results(tmp_path, oscap_backend):
    # Test that fix runs and creates fix file when passing in audit_results
    audit_results_file = tmp_path / "test_audit_results.xml"
    artifacts = oscap_backend.fix(
        cac_profile=TEST_PROFILE_ID,
        tailoring_file=None,
        audit_results_file=audit_results_file,
    )
    # The fix file should exist with the correct content
    fix_file = artifacts.get_by_type("fix_script").path
    assert fix_file.read_text() == "#TEST FIX OUTPUT USING AUDIT RESULTS"



# ---- OpenscapBackend generate_fix tests ----


def test_generate_fix_runs_and_creates_fix_file(oscap_backend):
    # Test that generate_fix runs and creates fix file
    artifacts = oscap_backend.generate_fix(cac_profile=TEST_PROFILE_ID, tailoring_file=None)
    # The copy of the fix file should exist with correct content
    fix_file = artifacts.get_by_type("fix_script").path
    assert fix_file.read_text() == "#TEST FIX OUTPUT WITHOUT AUDIT RESULTS"


def test_generate_fix_command_line_options(oscap_backend, tmp_path, dummy_datastream):
    # Test that command line options are correct
    tailoring_file = tmp_path / "dummy_tailoring_file.xml"
    artifacts = oscap_backend.generate_fix(
        cac_profile=TEST_PROFILE_ID, tailoring_file=tailoring_file
    )
    args = (tmp_path / "test_oscap.args").read_text()
    fix_file = artifacts.get_by_type("fix_script").path
    assert args == (
        f"xccdf generate fix "
        f"--fix-type bash "
        f"--output {fix_file} "
        f"--tailoring-file {tailoring_file} "
        f"--profile {TEST_PROFILE_ID} "
        f"{dummy_datastream}"
    )

def test_generate_fix_command_line_options_with_audit_results(oscap_backend, tmp_path):
    # Test that command line options are correct
    audit_results_file = tmp_path / "test_audit_results.xml"
    artifacts = oscap_backend.generate_fix(
        cac_profile=TEST_PROFILE_ID,
        tailoring_file=None,
        audit_results_file=audit_results_file,
    )
    args = (tmp_path / "test_oscap.args").read_text()
    fix_file = artifacts.get_by_type("fix_script").path
    assert args == (
        f"xccdf generate fix "
        f"--fix-type bash "
        f"--output {fix_file} "
        f"--result-id {TEST_PROFILE_ID} "
        f"{audit_results_file}"
    )

# ---- OpenscapBackend get_oscap_version() tests ----

def test_get_oscap_version(dummy_openscap_bin, tmp_path):
    # Test that command line options and version are correct
    version = backends.OpenscapBackend._get_oscap_version(
        dummy_openscap_bin, tmp_path
        )
    args = (tmp_path / "test_oscap.args").read_text()
    assert args == "--version"
    assert version == (1, 3, 9)

def test_get_oscap_version_no_dummy_oscap(monkeypatch):
    # Test oscap version with mocked run_cmd
    class DummyProcessResult():
        def __init__(self, version):
            self.stdout = f"OpenSCAP command line tool (oscap) {version}"
    monkeypatch.setattr(backends, "run_cmd", lambda *a, **kw: DummyProcessResult("1.3.9"))
    version = backends.OpenscapBackend._get_oscap_version(None, None)
    assert version == (1, 3, 9)

def test_get_oscap_version_fail_match(tmp_path, monkeypatch):
    # Test that garbled oscap version raises error
    class DummyProcessResult():
        def __init__(self, version):
            self.stdout = f"OpenSCAP command line tool (oscap) {version}"
    monkeypatch.setattr(backends, "run_cmd", lambda *a, **kw: DummyProcessResult("1.3.garbled"))
    with pytest.raises(backends.BackendError,
                       match="Failed to determine oscap version"):
        version = backends.OpenscapBackend._get_oscap_version(None, None)

def test_get_oscap_version_fail_runcmd(tmp_path, monkeypatch):
    # Test that failure to run oscap results 
    class DummyProcessResult():
        def __init__(self, version):
            raise backends.BackendCommandError()
    monkeypatch.setattr(backends, "run_cmd", lambda *a, **kw: DummyProcessResult("1.3.9"))
    with pytest.raises(backends.BackendError,
                       match="Failed to determine oscap version"):
        version = backends.OpenscapBackend._get_oscap_version(None, None)


 # ---- run_cmd() tests ----

def test_run_cmd_args_and_cwd(tmp_path, dummy_openscap_bin):
    # test that correct args and cwd are used
    cwd = tmp_path / "ASD"
    cwd.mkdir()
    cmd = [str(dummy_openscap_bin), "arg1", "--arg2"]
    backends.run_cmd(cmd, cwd)
    args = (cwd / "test_oscap.args").read_text()
    assert args == "arg1 --arg2"
    assert str(cwd) == (cwd / "test_oscap.cwd").read_text()


def test_run_cmd_capture_stdout(tmp_path):
    # test that stdout is correctly captured
    p = backends.run_cmd(["/usr/bin/echo", "-n", "test_string"], tmp_path, capture_output=True)
    assert p.stdout == "test_string"
    assert p.stderr == ""
    assert p.returncode == 0


def test_run_cmd_allowed_error(tmp_path):
    # test that stderr is correct captured and allowed_return_codes is respected
    p = backends.run_cmd(["/usr/bin/cat", "nofilehere"], tmp_path, capture_output=True, allowed_return_codes=[1])
    assert p.stdout == ""
    assert "No such file or directory" in p.stderr
    assert p.returncode == 1


def test_run_cmd_fail(tmp_path):
    # test that cmd failure raises backendcommanderror
    with pytest.raises(backends.BackendCommandError,
                       match="Backend command.*exited with return code 1"):
        backends.run_cmd(["/usr/bin/cat", "nofilehere"], tmp_path)


def test_run_cmd_fail_timeout(tmp_path):
    # test that timeout raises backendcommanderror
    with pytest.raises(backends.BackendCommandError,
                       match="timed out"):
        backends.run_cmd(["/usr/bin/sleep", "0.1"], tmp_path, timeout=0.0001)

    
def test_run_cmd_fail_oserror(tmp_path):
    # test that non-executable raises backendcommanderror
    bin = tmp_path / "abin"
    bin.touch()
    with pytest.raises(backends.BackendCommandError,
                       match="Failed to execute command.*Permission denied"):
        backends.run_cmd([str(bin)], tmp_path)

    

