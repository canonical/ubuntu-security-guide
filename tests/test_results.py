from pathlib import Path

import pytest

from usg.results import AuditResult, AuditResults, BackendArtifacts, FileMoveError


def test_usgauditresults_add_and_summary():
    results = AuditResults()
    results.add_result("rule1", "pass", "")
    results.add_result("rule2", "fail", "something failed")
    results.add_result("rule3", "notapplicable", "")
    results.add_result("rule4", "error", "error msg")
    results.add_result("rule5", "notchecked", "")
    results.add_result("rule6", "unknown", "")
    results.add_result("rule7", "customstate", "should count as unknown")

    # Check that results are stored as AuditResult
    assert isinstance(results[0], AuditResult)
    assert results[0].rule_name == "rule1"
    assert results[1].state == "fail"
    assert results[3].message == "error msg"

    # Check summary output
    summary = results.get_summary()
    assert (
        summary
        == """\
Pass:  1
Fail:  1
Error: 1
NotChecked: 1
Unknown: 2
N/A:   1
"""
    )


def test_backend_artifact_paths(tmp_path):
    # test that the file paths are correct
    output_files = BackendArtifacts()
    output_files.add_artifact("test_type1", "test_file1")
    output_files.add_artifact("test_type2", tmp_path / "test_file2")
    assert output_files.get_by_type("test_type1").path == Path("test_file1").resolve()
    assert (
        output_files.get_by_type("test_type2").path
        == (tmp_path / "test_file2").resolve()
    )


def test_backend_artifact_move(tmp_path):
    # test that the files are moved to the correct location
    output_files = BackendArtifacts()
    test_file = tmp_path / "test_file"
    test_file.write_text("test_file_contents")
    output_files.add_artifact("test_type", test_file)
    assert output_files.get_by_type("test_type").path == test_file.resolve()

    new_dir = tmp_path / "new_dir"
    for file in output_files:
        file.move(new_dir / file.path.name)

    assert output_files.get_by_type("test_type").path == new_dir / "test_file"
    assert (new_dir / "test_file").read_text() == "test_file_contents"


def test_backend_artifact_move_to_dir(tmp_path):
    # test that all artifacts are moved to the correct location
    output_files = BackendArtifacts()
    test_files = ["test1", "test2", "test3"]
    for t in test_files:
        (tmp_path / t).write_text(t)
        output_files.add_artifact(t, tmp_path / t)

    new_dir = tmp_path / "new_dir"
    output_files.move_to_dir(new_dir, parent_dir_filter="/")
    for t in test_files:
        assert output_files.get_by_type(t).path == new_dir / t
        assert (new_dir / t).read_text() == t


def test_backend_artifact_move_to_dir_bad_filter(tmp_path):
    # test that files are not moved if parent dir filter doesn't match
    output_files = BackendArtifacts()
    test_files = ["test1", "test2", "test3"]
    for t in test_files:
        (tmp_path / t).write_text(t)
        output_files.add_artifact(t, tmp_path / t)

    new_dir = tmp_path / "new_dir"
    output_files.move_to_dir(new_dir, parent_dir_filter="/notaparentdir")
    for t in test_files:
        assert output_files.get_by_type(t).path == tmp_path / t

def test_backend_artifact_missing(tmp_path):
    # test that it fails to move non-existent files
    output_files = BackendArtifacts()
    test_file = tmp_path / "test_file"
    output_files.add_artifact("test_type", test_file)
    with pytest.raises(FileMoveError):
        output_files[0].move(tmp_path / "missing_dir/test_file")

def test_backend_artifact_kind_exists(tmp_path):
    # test that error is raised if kind already exists
    output_files = BackendArtifacts()
    output_files.add_artifact("test_type", "/test_file")
    with pytest.raises(ValueError, match="already exists"):
        output_files.add_artifact("test_type", "/test_file")

def test_backend_artifact_no_such_kind(tmp_path):
    # test that error is raised if artifact kind doesn't exist
    output_files = BackendArtifacts()
    output_files.add_artifact("test_type", "/test_file")
    output_files.get_by_type("test_type")
    with pytest.raises(ValueError, match="No file found with kind"):
        output_files.get_by_type("test_type2")

