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

import datetime
import configparser
from pathlib import Path

import pytest
from pytest import MonkeyPatch

from usg import usg as usg_module
from usg import constants, config
from usg.exceptions import BackendError, ProfileNotFoundError, USGError
from usg.models import Benchmark, Benchmarks, Profile, TailoringFile
from usg.results import AuditResults, BackendArtifacts
from usg.usg import USG


TEST_DATE = "20250715.1200"
TEST_DATETIME = datetime.datetime(2025, 7, 15, 12, 0)

@pytest.fixture
def dummy_config(tmp_path):
    config = configparser.ConfigParser()
    config.read_dict({
        "cli": {
            "log_file": tmp_path / "test.usg.log",
            "product": "ubuntu2404",
            "fix_only_failed": False,
        },
        "openscap_backend": {
            "audit_report": "test-report-{PROFILE_ID}-{DATE}.html",
            "audit_results": "test-results-{PROFILE_ID}-{DATE}.xml",
            "audit_log": "test-log-{PROFILE_ID}-{DATE}.txt",
            "fix_script": "test-fix-{PROFILE_ID}-{DATE}.sh",
            "audit_oval_results": "test-oval-results.xml",
            "audit_oval_cpe_results": "test-oval-cpe-results.xml",
            "save_oval_results": True
        }
    })
    return config


@pytest.fixture
def patch_usg(tmp_path_factory, dummy_benchmarks):
    # patch the usg module:
    # - set benchmarks to our dummy benchmarks
    # - set var_dir to our tmp path
    # - set OpenscapBackend to our dummy backend
    # - set check_perms, verify_integrity to no-ops
    # - set gunzip_file to no-op since anyhow using dummy backend
    #   which doesn't use the datastream
    # - set datetime to a fixed date
    mp = MonkeyPatch()

    class DummyBackend:
        def __init__(self, *args, **kwargs):
            pass

        def audit(
            self, profile_id, tailoring_file=None, debug=False, oval_results=False
        ) -> tuple[AuditResults, BackendArtifacts]:
            # echo arguments to check correct pass through to backend
            print(
                f"audit called with profile_id={profile_id}, "
                f"tailoring_file={tailoring_file}, debug={debug}, "
                f"oval_results={oval_results}"
            )

            # mock results file... should be moved to the correct path by usg.audit()
            artifacts = BackendArtifacts()
            test_name = "test_backend_results_file.xml"
            results_file = tmp_path_factory.mktemp("audit_results") / test_name
            results_file.write_text("test_results_contents")
            artifacts.add_artifact("audit_results", results_file)
            return AuditResults(), artifacts

        def generate_fix(
            self, profile_id, tailoring_file=None, fix_path=None
        ) -> BackendArtifacts:
            # echo arguments to check correct pass through to backend
            print(
                f"generate_fix called with profile_id={profile_id}, "
                f"tailoring_file={tailoring_file}, fix_path={fix_path}"
            )

            # mock fix script file, it should be moved to the
            # correct path by usg.generate_fix()
            artifacts = BackendArtifacts()
            test_name = "test_backend_fix_script.sh"
            fix_script_file = tmp_path_factory.mktemp("fix_script") / test_name
            fix_script_file.write_text("test_fix_script_contents")
            artifacts.add_artifact("fix_script", fix_script_file)
            return artifacts

        def fix(
            self, profile_id, tailoring_file=None, audit_results_file=None
        ) -> BackendArtifacts:
            # echo arguments to check correct pass through to backend
            # check only the filename of audit_results_filename since
            # the full path includes the tmp path
            ar_fname = audit_results_file.name if audit_results_file else "None"
            print(
                f"fix called with profile_id={profile_id}, "
                f"tailoring_file={tailoring_file}, "
                f"audit_results_file={ar_fname}"
            )

            # mock fix script file, should be moved to the correct path by usg.fix()
            artifacts = BackendArtifacts()
            test_name = "test_backend_fix_script.sh"
            fix_script_file = tmp_path_factory.mktemp("script_fix") / test_name
            fix_script_file.write_text("test_fix_script_contents")
            artifacts.add_artifact("fix_script", fix_script_file)
            return artifacts

    mp.setattr(constants, "BENCHMARK_METADATA_PATH", dummy_benchmarks)
    mp.setattr(constants, "STATE_DIR", tmp_path_factory.mktemp("var_dir"))
    mp.setattr(usg_module, "OpenscapBackend", DummyBackend)
    mp.setattr(usg_module, "check_perms", lambda *a, **k: None)
    mp.setattr(usg_module, "verify_integrity", lambda *a, **k: None)
    mp.setattr(usg_module, "gunzip_file", lambda *a, **k: None)

    class DummyDatetime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            return TEST_DATETIME

    mp.setattr(datetime, "datetime", DummyDatetime)

    yield

    mp.undo()


def test_usg_init_and_benchmarks(patch_usg, monkeypatch, dummy_benchmarks):
    usg = USG()
    assert isinstance(usg.benchmarks, Benchmarks)
    assert isinstance(usg.get_benchmark_by_id("ubuntu2404_CIS_1"), Benchmark)
    with pytest.raises(KeyError, match="Benchmark 'badbenchmark' not found"):
        usg.get_benchmark_by_id("badbenchmark")


@pytest.mark.parametrize(
    "profile_arg, product, version, expected_benchmark_id,expected_profile_id",
    [
        # by default, get latest version
        (
            "cis_level1_server",
            "ubuntu2404",
            None,
            "ubuntu2404_CIS_3",
            "cis_level1_server",
        ),
        # by latest version
        (
            "cis_level1_server",
            "ubuntu2404",
            "latest",
            "ubuntu2404_CIS_3",
            "cis_level1_server",
        ),
        # by explicit version
        (
            "cis_level1_server",
            "ubuntu2404",
            "v1.0.0",
            "ubuntu2404_CIS_1",
            "cis_level1_server",
        ),
        # by compatible version
        (
            "cis_level1_server",
            "ubuntu2404",
            "v1.0.0.usg1",
            "ubuntu2404_CIS_2",
            "cis_level1_server",
        ),
        # by legacy id
        ("disa_stig", "ubuntu2404", "V1R1", "ubuntu2404_STIG_1", "stig"),
        # by most recently released (profile not in latest benchmark)
        (
            "cis_level1_server_special",
            "ubuntu2404",
            None,
            "ubuntu2404_CIS_2",
            "cis_level1_server_special"
        )
    ],
)
def test_get_profile_success(
    patch_usg, profile_arg, product, version, expected_benchmark_id, expected_profile_id
):
    usg = USG()
    if version is not None:
        profile = usg.get_profile(profile_arg, product, benchmark_version=version)
    else:
        profile = usg.get_profile(profile_arg, product)
    assert isinstance(profile, Profile)
    assert profile.profile_id == expected_profile_id
    assert profile.benchmark_id == expected_benchmark_id


@pytest.mark.parametrize(
    "profile,product,version,error_string",
    [
        ("bad_profile", "ubuntu2404", "v1.0.0", "Could not find benchmark profile"),
        ("cis_level1_server", "bad_product", "v1.0.0", "Could not find benchmark product"),
        ("cis_level1_server", "ubuntu2404", "bad_version", "Could not find profile.*with benchmark version"),
    ],
)
def test_get_profile_not_found(patch_usg, profile, product, version, error_string)  :
    usg = USG()
    with pytest.raises(ProfileNotFoundError, match=error_string):
        usg.get_profile(profile, product, benchmark_version=version)


def test_load_tailoring_returns_tailoring_object(patch_usg, tmp_path, monkeypatch):
    # test that the load_tailoring function returns a tailoring file
    usg = USG()
    tailoring_path = (
        tmp_path / "ubuntu2404_CIS_1/tailoring/cis_level1_server-tailoring.xml"
    )
    tailoring_path.parent.mkdir(parents=True, exist_ok=True)
    tailoring_path.write_text("")

    # Patch TailoringFile.from_file to return a dummy object
    class DummyTailoring:
        def __init__(self):
            self.benchmark_id = "ubuntu2404_CIS_1"
            self.tailoring_file = tailoring_path
            self.profile = Profile(
                profile_id="cis_level1_server",
                profile_legacy_id="cis_level1_server_legacy_id",
                benchmark_id="ubuntu2404_CIS_1",
                tailoring_file=tailoring_path,
            )

    monkeypatch.setattr(TailoringFile, "from_file", lambda path: DummyTailoring())
    result = usg.load_tailoring(tailoring_path)
    assert isinstance(result, DummyTailoring)


def test_load_tailoring_benchmark_not_found(patch_usg, monkeypatch, tmp_path):
    # test that the tailoring file contains an invalid benchmark
    # (not in list of benchmarks)
    usg = USG()
    tailoring_path = (
        tmp_path / "ubuntu2404_CIS_1/tailoring/cis_level1_server-tailoring.xml"
    )
    tailoring_path.parent.mkdir(parents=True, exist_ok=True)
    tailoring_path.write_text("")

    # Patch TailoringFile.from_file to return a dummy object
    class DummyTailoring:
        benchmark_id = "badbenchmark"
        profile = Profile(
            profile_id="cis_level1_server",
            profile_legacy_id="cis_level1_server_legacy_id",
            benchmark_id="badbenchmark",
            tailoring_file=tailoring_path,
        )


    monkeypatch.setattr(TailoringFile, "from_file", lambda path: DummyTailoring)
    with pytest.raises(
        USGError,
        match="Could not find benchmark referenced in tailoring file: badbenchmark",
    ):
        usg.load_tailoring(tailoring_path)


def test_generate_fix(patch_usg, dummy_benchmarks, capsys):
    # test that generate fix runs and passess the correct arguments to the backend
    usg = USG()
    profile = usg.get_profile("cis_level1_server", "ubuntu2404")
    _ = usg.generate_fix(profile)
    stdout, _ = capsys.readouterr()
    assert stdout == (
        "generate_fix called with profile_id=cis_level1_server, "
        "tailoring_file=None, fix_path=None\n"
    )


def test_generate_fix_correct_artifact_names(patch_usg, dummy_config, dummy_benchmarks, capsys):
    # test that generate-fix creates the correct artifact name and moves it to the correct path
    usg = USG(dummy_config)
    profile = usg.get_profile("cis_level1_server", "ubuntu2404")
    artifacts = usg.generate_fix(profile)
    expected_name = "test-fix-cis_level1_server-20250715.1200.sh"
    assert artifacts.get_by_type("fix_script").path.name == expected_name



def test_fix(patch_usg, dummy_benchmarks, capsys):
    # test that fix runs and passess the correct arguments to the backend
    usg = USG()
    profile = usg.get_profile("cis_level1_server", "ubuntu2404")
    _ = usg.fix(profile)
    stdout, _ = capsys.readouterr()
    assert stdout.strip() == (
        "fix called with profile_id=cis_level1_server, "
        "tailoring_file=None, audit_results_file=None"
    )


def test_fix_audit_results_file(patch_usg, dummy_benchmarks, capsys):
    # test that fix only remediates failed rules
    usg = USG()
    profile = usg.get_profile("cis_level1_server", "ubuntu2404")
    _ = usg.fix(profile, audit_results_file=Path("/path/to/test_audit_results_file.xml"))
    stdout, stderr = capsys.readouterr()
    assert stdout.strip() == (
        "fix called with profile_id=cis_level1_server, "
        "tailoring_file=None, audit_results_file=test_audit_results_file.xml"
    )


def test_fix_correct_artifact_names(patch_usg, dummy_config, dummy_benchmarks, capsys):
    # test that fix creates the correct artifact name and moves it to the correct path
    usg = USG(dummy_config)
    profile = usg.get_profile("cis_level1_server", "ubuntu2404")
    artifacts = usg.fix(profile)
    expected_name = "test-fix-cis_level1_server-20250715.1200.sh"
    assert artifacts.get_by_type("fix_script").path.name == expected_name



def test_audit_correct_arguments(patch_usg, dummy_benchmarks, capsys):
    # test that audit runs and passess the correct arguments to the backend
    usg = USG()
    profile = usg.get_profile("cis_level1_server", "ubuntu2404")
    results, artifacts = usg.audit(profile)
    stdout, stderr = capsys.readouterr()
    assert stdout == (
        "audit called with profile_id=cis_level1_server, "
        "tailoring_file=None, debug=False, oval_results=False\n"
    )


def test_audit_correct_artifact_names(patch_usg, dummy_benchmarks, capsys):
    # test that audit creates the correct artifact name and moves it to the correct path
    usg = USG()
    profile = usg.get_profile("cis_level1_server", "ubuntu2404")
    results, artifacts = usg.audit(profile)
    expected_name = "usg-results-20250715.1200.xml"
    assert artifacts.get_by_type("audit_results").path.name == expected_name


def test_missing_benchmarks_file(monkeypatch, tmp_path):
    # test that the missing benchmark file raises the correct errror
    monkeypatch.setattr(constants, "BENCHMARK_METADATA_PATH", tmp_path / "nonexistant")
    with pytest.raises(USGError, match="Could not find benchmark data"):
        USG()


def test_move_artifacts_error_handling(patch_usg, monkeypatch):
    # test that moving the file raises USGError
    monkeypatch.setattr(
        config, "get_artifact_destination_path", lambda *a: "/dev/null/nonwritable/path"
        )
    usg = USG()
    artifacts = BackendArtifacts()
    artifacts.add_artifact("test", "test")
    
    with pytest.raises(USGError, match="Error moving files"):
        usg._move_artifacts(artifacts, "test_profile", "test_product")


@pytest.mark.parametrize("function_name,backend_error_type,reraised_error_type,error_text", [
    ["audit", BackendError, USGError, "Failed to run backend operation"],
    ["fix", BackendError, USGError, "Failed to run backend operation"],
    ["generate_fix", BackendError, USGError, "Failed to run backend operation"],
    ["audit", KeyboardInterrupt, KeyboardInterrupt, ""],
    ["fix", KeyboardInterrupt, KeyboardInterrupt, ""],
    ["generate_fix", KeyboardInterrupt, KeyboardInterrupt, ""],
    ["audit", RuntimeError, RuntimeError, ""],
    ["fix", RuntimeError, RuntimeError, ""],
    ["generate_fix", RuntimeError, RuntimeError, ""],
])
def test_error_handling_in_backend_operations(patch_usg, monkeypatch, caplog, function_name,
                                              backend_error_type, reraised_error_type, error_text):
    # test that errors returned by backend are properly handled
    def backend_function(*a, **kw):
        raise backend_error_type

    monkeypatch.setattr(usg_module.OpenscapBackend, function_name, backend_function)
    usg = USG()
    profile = usg.get_profile("cis_level1_server", "ubuntu2404")
    with pytest.raises(reraised_error_type, match=error_text):
        with caplog.at_level("ERROR"):
            getattr(usg, function_name)(profile)
    assert "Storing partial outputs in " in caplog.text
