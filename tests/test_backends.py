import configparser
import os

import pytest

from usg.backends import BackendError, OpenscapBackend
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
    # - Echo args to stdout
    # - Create dummy results file if eval is passed
    # - Create dummy oval results files if eval is passed
    # - Exit with status 0
    bin_path = tmp_path / "test_oscap_echo_args.sh"
    bin_path.write_text(f"""\
#!/bin/bash

# echo args to stdout
echo -n $@ > test_oscap_echo_args.stdout

if grep -qw "eval" <<< "$@"; then
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

elif grep -qw "generate" <<< "$@"; then
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
fi

exit 0
""")
    os.chmod(bin_path, 0o755)
    return bin_path


@pytest.fixture
def oscap_backend(
    monkeypatch, tmp_path, dummy_datastream, dummy_openscap_bin
):
    # Fixture to create a dummy OpenscapBackend
    # - Patch validate_perms to always pass
    # - Patch os.access to always True
    # - Return a dummy OpenscapBackend

    from usg import utils

    monkeypatch.setattr(utils, "validate_perms", lambda path, *_: None)
    monkeypatch.setattr(os, "access", lambda path, mode: True)

    return OpenscapBackend(
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
    from usg import utils

    monkeypatch.setattr(utils, "validate_perms", lambda path, *_: None)
    with pytest.raises(BackendError):
        OpenscapBackend(
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
    with pytest.raises(BackendError):
        OpenscapBackend(
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
    with pytest.raises(BackendError):
        OpenscapBackend(
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
    stdout = (tmp_path / "test_oscap_echo_args.stdout").read_text()
    log_file = (
        oscap_backend._work_dir / oscap_backend.ARTIFACT_FILENAMES["audit_log"]
    )
    results_file = (
        oscap_backend._work_dir / oscap_backend.ARTIFACT_FILENAMES["audit_results"]
    )
    report_file = (
        oscap_backend._work_dir / oscap_backend.ARTIFACT_FILENAMES["audit_report"]
    )

    assert stdout == (
        f"xccdf --verbose WARNING --verbose-log-file {log_file} eval "
        f"--results {results_file} "
        f"--report {report_file} "
        f"--profile {TEST_PROFILE_ID} "
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
    stdout = (tmp_path / "test_oscap_echo_args.stdout").read_text()  # type: ignore
    assert f"--tailoring-file {tailoring_file}" in stdout


def test_audit_command_line_options_with_debug(monkeypatch, oscap_backend, tmp_path):
    # Test that command line options are correct
    monkeypatch.setattr(oscap_backend, "_parse_audit_results", lambda x: None)
    results, artifacts = oscap_backend.audit(
        cac_profile=TEST_PROFILE_ID, tailoring_file=None, debug=True, oval_results=False
    )
    stdout = (tmp_path / "test_oscap_echo_args.stdout").read_text()  # type: ignore
    assert "--verbose INFO" in stdout
    assert "--oval-results" in stdout


def test_audit_command_line_options_with_oval_results(
    monkeypatch, oscap_backend, tmp_path
):
    # Test that command line options are correct
    monkeypatch.setattr(oscap_backend, "_parse_audit_results", lambda x: None)
    results, artifacts = oscap_backend.audit(
        cac_profile=TEST_PROFILE_ID, tailoring_file=None, debug=False, oval_results=True
    )
    stdout = (tmp_path / "test_oscap_echo_args.stdout").read_text()  # type: ignore
    assert "--oval-results" in stdout


# ---- _parse_audit_results tests ----


def test_parse_audit_results_invalid_xml(oscap_backend, tmp_path):
    # Test that invalid xml fails
    xml = tmp_path / "bad_results_file.xml"
    xml.write_text("<notxml>")
    with pytest.raises(BackendError):
        oscap_backend._parse_audit_results(xml)


def test_parse_audit_results_unknown_root_element(oscap_backend, tmp_path):
    # Test that unknown root element fails
    xml = tmp_path / "unknown_root_element.xml"
    xml.write_text(
        "<BadRoot><TestResult><rule-result idref='xccdf_org.ssgproject.content_rule_test'><result>pass</result></rule-result></TestResult></BadRoot>"
    )
    with pytest.raises(BackendError):
        oscap_backend._parse_audit_results(xml)


def test_parse_audit_results_missing_testresult(oscap_backend, tmp_path):
    # Test that missing testresult fails
    xml = tmp_path / "no_testresult.xml"
    xml.write_text("<Benchmark></Benchmark>")
    with pytest.raises(BackendError):
        oscap_backend._parse_audit_results(xml)


def test_parse_audit_results_missing_rule_id(oscap_backend, tmp_path):
    # Test that missing rule id fails
    xml = tmp_path / "no_rule_id.xml"
    xml.write_text(
        "<Benchmark><TestResult><rule-result><result>pass</result></rule-result></TestResult></Benchmark>"
    )
    with pytest.raises(BackendError):
        oscap_backend._parse_audit_results(xml)


def test_parse_audit_results_missing_result(oscap_backend, tmp_path):
    # Test that missing result fails
    xml = tmp_path / "no_result.xml"
    xml.write_text(
        "<Benchmark><TestResult><rule-result idref='xccdf_org.ssgproject.content_rule_test'></rule-result></TestResult></Benchmark>"
    )
    with pytest.raises(BackendError):
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
    print((tmp_path / "test_oscap_echo_args.stdout").read_text())

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
    stdout = (tmp_path / "test_oscap_echo_args.stdout").read_text()
    fix_file = artifacts.get_by_type("fix_script").path
    assert stdout == (
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
    stdout = (tmp_path / "test_oscap_echo_args.stdout").read_text()
    fix_file = artifacts.get_by_type("fix_script").path
    assert stdout == (
        f"xccdf generate fix "
        f"--fix-type bash "
        f"--output {fix_file} "
        f"--result-id {TEST_PROFILE_ID} "
        f"{audit_results_file}"
    )
