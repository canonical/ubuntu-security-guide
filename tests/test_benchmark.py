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

import json
from pathlib import Path

import pytest

from usg.exceptions import BenchmarkError, ProfileNotFoundError
from usg.models import Benchmark, Benchmarks, OldProfile


def test_usgbenchmarks(dummy_benchmarks):
    # Test that the two benchmarks from a file are correctly loaded
    benchmarks = Benchmarks.from_json(dummy_benchmarks)
    assert benchmarks.version == 1
    assert len(benchmarks) == 5
    assert isinstance(benchmarks, Benchmarks)
    assert isinstance(benchmarks["ubuntu2404_CIS_1"], Benchmark)
    assert isinstance(benchmarks["ubuntu2404_STIG_1"], Benchmark)

def test_usgbenchmarks_error_loading_and_parsing(tmp_path):
    # test that failure to load or parse json file results in BenchmarkError
    with pytest.raises(BenchmarkError, match="Failed to parse"):
        Benchmarks.from_json("/dev/null/nonexistent")

    bad_json = tmp_path / "benchmarks.json"
    bad_json.write_text("this won't parse")
    with pytest.raises(BenchmarkError, match="Failed to parse"):
        Benchmarks.from_json(bad_json)

def test_usgbenchmarks_error_from_missing_benchmarks(tmp_path, dummy_benchmarks):
    # Test that an error is raised if the benchmarks key is missing
    b = json.loads(dummy_benchmarks.read_text())
    b.pop("benchmarks")
    json_file = tmp_path / "benchmarks.json"
    json_file.write_text(json.dumps(b))
    with pytest.raises(
        BenchmarkError, match="Invalid '.*' contents. Could not find key 'benchmarks'"
    ):
        Benchmarks.from_json(json_file)


def test_usgbenchmarks_error_from_missing_version(tmp_path, dummy_benchmarks):
    # Test that an error is raised if the version key is missing
    b = json.loads(dummy_benchmarks.read_text())
    b.pop("version")
    json_file = tmp_path / "benchmarks.json"
    json_file.write_text(json.dumps(b))
    with pytest.raises(
        BenchmarkError, match="Invalid '.*' contents. Could not find key 'version'"
    ):
        Benchmarks.from_json(json_file)


def test_usgbenchmarks_error_from_duplicate_benchmark_id(tmp_path, dummy_benchmarks):
    # Test that an error is raised if the version key is missing
    b = json.loads(dummy_benchmarks.read_text())
    b["benchmarks"].append(b["benchmarks"][0])
    json_file = tmp_path / "benchmarks.json"
    json_file.write_text(json.dumps(b))
    with pytest.raises(
        BenchmarkError,
        match="Malformed dataset - duplicate benchmark ID: ubuntu2404_CIS_1",
    ):
        Benchmarks.from_json(json_file)


def test_usgbenchmark(dummy_benchmarks):
    # Test that the single benchmark from a file is correctly parsed
    benchmarks = Benchmarks.from_json(dummy_benchmarks)
    benchmark = benchmarks["ubuntu2404_CIS_2"]
    assert benchmark.id == "ubuntu2404_CIS_2"
    assert benchmark.benchmark_type == "CIS"
    assert benchmark.product == "ubuntu2404"
    assert benchmark.product_long == "Ubuntu 24.04 LTS (Noble Numbat)"
    assert benchmark.version == "v1.0.1"
    assert benchmark.tailoring_version == 2
    assert (
        benchmark.description
        == "ComplianceAsCode implementation of CIS Ubuntu 24.04 LTS v1.0.1 benchmark.\n"
    )
    assert benchmark.compatible_versions == ["v1.0.0.usg1"]
    assert benchmark.breaking_upgrade_path == ["v2.0.0"]
    assert (
        benchmark.release_notes_url
        == "https://github.com/canonical/ubuntu-security-guide/"
    )
    assert benchmark.release_timestamp == 1002
    assert (
        benchmark.reference_url == "https://www.cisecurity.org/benchmark/ubuntu_linux/"
    )
    assert benchmark.is_latest == False
    assert len(benchmark.profiles) == 5
    assert benchmark.tailoring_files["cis_level2_server"] == {
        "path": "ubuntu2404_CIS_2/tailoring/cis_level2_server-tailoring.xml",
        "sha256": "b1c953719606572f8ab507e9bfbbd570724127e8c87055aca90ebff85817e6f5",
    }
    t_rel_path = benchmark.get_tailoring_file_relative_path("cis_level2_server")
    assert t_rel_path == Path(
        "ubuntu2404_CIS_2/tailoring/cis_level2_server-tailoring.xml"
    )

    ds_file = benchmark.data_files["datastream_gz"]
    assert ds_file.type == "datastream_gz"
    assert ds_file.rel_path == Path("ubuntu2404_CIS_2/ssg-ubuntu2404-ds.xml.gz")
    assert (
        ds_file.sha256
        == "5ef3b9feb87381e7cca99f50cfaae6d5789ba66e512e97bd82e027f2005a8366"
    )


@pytest.mark.parametrize("missing_key", ["profiles", "data_files", "tailoring_files"])
def test_usgbenchmark_bad_data(dummy_benchmarks, missing_key):
    # Test that an error is raised if the data is malformed
    raw_data = json.loads(dummy_benchmarks.read_text())
    raw_data["benchmarks"][0].pop(missing_key)
    with pytest.raises(
        BenchmarkError,
        match=f"Failed to create Benchmark object from.*: '{missing_key}",
    ):
        Benchmark.from_dict(raw_data["benchmarks"][0])


def test_usgbenchmark_tailoring_bad_profile(dummy_benchmarks):
    benchmarks = Benchmarks.from_json(dummy_benchmarks)
    benchmark = benchmarks["ubuntu2404_CIS_1"]
    with pytest.raises(ProfileNotFoundError):
        benchmark.get_tailoring_file_relative_path("cis_level3_server")


def test_usgbenchmark_tailoring_file(dummy_benchmarks):
    benchmarks = Benchmarks.from_json(dummy_benchmarks)
    benchmark = benchmarks["ubuntu2404_CIS_1"]
    assert benchmark.get_tailoring_file_relative_path("cis_level1_server") == Path(
        "ubuntu2404_CIS_1/tailoring/cis_level1_server-tailoring.xml"
    )
    assert benchmark.get_tailoring_file_relative_path("cis_level2_server") == Path(
        "ubuntu2404_CIS_1/tailoring/cis_level2_server-tailoring.xml"
    )


def test_usgbenchmark_profiles(dummy_benchmarks):
    benchmarks = Benchmarks.from_json(dummy_benchmarks)
    benchmark = benchmarks["ubuntu2404_CIS_1"]
    # Test that profiles contain correct data
    for profile_id, profile in benchmarks["ubuntu2404_CIS_1"].profiles.items():
        assert isinstance(profile, OldProfile)
        assert profile.benchmark_channel == "ubuntu2404_CIS_1"
        assert profile.profile_id == profile_id
        assert (
            profile.profile_legacy_id
            == benchmark.profiles[profile_id].profile_legacy_id
        )
        assert profile.tailoring_file is None


def test_usgprofile():
    # Test Profile initialization and properties
    profile = OldProfile(
        profile_id="test_profile",
        profile_legacy_id="test_profile_legacy_id",
        benchmark_channel="test_benchmark_id",
        tailoring_file=Path("test_tailoring.xml"),
    )
    assert profile.profile_id == "test_profile"
    assert profile.profile_legacy_id == "test_profile_legacy_id"
    assert profile.benchmark_channel == "test_benchmark_id"
    assert profile.tailoring_file == Path("test_tailoring.xml")
