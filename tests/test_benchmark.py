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

from usg.exceptions import MetadataError, ProfileNotFoundError
from usg.models import Benchmark, Metadata, Profile, ReleaseChannel


def test_metadata_loading(test_metadata):
    # Test that the two benchmarks from a file are correctly loaded
    metadata = Metadata.from_json(test_metadata)
    assert isinstance(metadata, Metadata)
    assert metadata.version == 1
    assert len(metadata.profiles) == 18
    profile = list(metadata.profiles.values())[0]
    assert isinstance(profile, Profile)
    assert isinstance(profile.benchmark, Benchmark)
    assert isinstance(profile.benchmark.channel, ReleaseChannel)
    assert profile.benchmark.id in metadata.benchmarks
    assert profile.benchmark.channel.id in metadata.channels


def test_metadata_error_loading_and_parsing(tmp_path):
    # test that failure to load or parse json file results in MetadataError
    with pytest.raises(MetadataError, match="Failed to parse"):
        Metadata.from_json("/dev/null/nonexistent")

    bad_json = tmp_path / "benchmarks.json"
    bad_json.write_text("this won't parse")
    with pytest.raises(MetadataError, match="Failed to parse"):
        Metadata.from_json(bad_json)

def test_metadata_error_from_missing_benchmarks(tmp_path, test_metadata):
    # Test that an error is raised if the benchmarks key is missing
    metadata_json = json.loads(test_metadata.read_text())
    metadata_json.pop("benchmarks")
    json_file = tmp_path / "benchmarks.json"
    json_file.write_text(json.dumps(metadata_json))
    with pytest.raises(
        MetadataError, match="Invalid '.*' contents. Could not find key 'benchmarks'"
    ):
        Metadata.from_json(json_file)


def test_metadata_error_from_missing_version(tmp_path, test_metadata):
    # Test that an error is raised if the version key is missing
    metadata_json = json.loads(test_metadata.read_text())
    metadata_json.pop("version")
    json_file = tmp_path / "benchmarks.json"
    json_file.write_text(json.dumps(metadata_json))
    with pytest.raises(
        MetadataError, match="Invalid '.*' contents. Could not find key 'version'"
    ):
        Metadata.from_json(json_file)


@pytest.mark.parametrize("data_type",["profiles", "benchmarks", "release_channels"])
def test_metadata_error_from_duplicate_benchmark_id(tmp_path, test_metadata, data_type):
    # Test that an error is raised if there's a duplicate ID
    metadata_json = json.loads(test_metadata.read_text())
    metadata_json[data_type].append(metadata_json[data_type][0])
    json_file = tmp_path / "benchmarks.json"
    json_file.write_text(json.dumps(metadata_json))
    data_id = metadata_json[data_type][0]["id"]
    with pytest.raises(
        MetadataError,
        match=f"Malformed dataset - duplicate .* ID: {data_id}",
    ):
        Metadata.from_json(json_file)


def test_benchmark_data(test_metadata):
    # Test benchmark metadata is correctly parsed
    metadata = Metadata.from_json(test_metadata)
    benchmark = metadata.benchmarks["ubuntu2404_CIS_2-v1.0.0.usg1"]
    assert benchmark.id == "ubuntu2404_CIS_2-v1.0.0.usg1"
    assert benchmark.benchmark_type == "CIS"
    assert benchmark.product == "ubuntu2404"
    assert benchmark.product_long == "Ubuntu 24.04 LTS (Noble Numbat)"
    assert benchmark.version == "v1.0.0.usg1"
    assert benchmark.tailoring_version == 2
    assert (
        benchmark.description
        == "ComplianceAsCode implementation of CIS Ubuntu 24.04 LTS v1.0.0 benchmark.\n"
    )
    assert benchmark.latest_compatible_id == "ubuntu2404_CIS_2-v1.0.1"
    assert benchmark.latest_breaking_id == "ubuntu2404_CIS_3-v2.0.0"
    assert benchmark.channel.id == "ubuntu2404_CIS_2"
    assert (
        benchmark.reference_url == "https://www.cisecurity.org/benchmark/ubuntu_linux/"
    )
    assert len(benchmark.profiles) == 4


def test_channel_data(test_metadata):
    # Test release channel metadata is correctly parsed
    metadata = Metadata.from_json(test_metadata)
    channel = metadata.channels["ubuntu2404_CIS_2"]
    assert channel.benchmark_ids == ["ubuntu2404_CIS_2-v1.0.0.usg1", "ubuntu2404_CIS_2-v1.0.1"]
    assert channel.tailoring_version == 2
    assert channel.is_latest == False
    assert metadata.channels["ubuntu2404_CIS_3"].is_latest == True
    assert (
        channel.release_notes_url
        == "https://github.com/canonical/ubuntu-security-guide/"
    )
    assert channel.release_timestamp == 2
    assert channel.tailoring_files["cis_level2_server"] == {
        "path": "ubuntu2404_CIS_2/tailoring/cis_level2_server-tailoring.xml",
        "sha256": "b1c953719606572f8ab507e9bfbbd570724127e8c87055aca90ebff85817e6f5",
    }
    t_rel_path = channel.get_tailoring_file_relative_path("cis_level2_server")
    assert t_rel_path == Path(
        "ubuntu2404_CIS_2/tailoring/cis_level2_server-tailoring.xml"
    )

    ds_file = channel.data_files["datastream_gz"]
    assert ds_file.type == "datastream_gz"
    assert ds_file.rel_path == Path("ubuntu2404_CIS_2/ssg-ubuntu2404-ds.xml.gz")
    assert (
        ds_file.sha256
        == "5ef3b9feb87381e7cca99f50cfaae6d5789ba66e512e97bd82e027f2005a8366"
    )


@pytest.mark.parametrize("missing_key", ["profiles", "data_files", "tailoring_files"])
def test_benchmark_bad_data(test_metadata, missing_key):
    # Test that an error is raised if the data is malformed
    raw_data = json.loads(test_metadata.read_text())
    raw_data["benchmarks"][0].pop(missing_key)
    with pytest.raises(
        MetadataError,
        match=f"Failed to create Benchmark object from.*: '{missing_key}",
    ):
        Benchmark.from_dict(raw_data["benchmarks"][0])


def test_benchmark_tailoring_bad_profile(test_metadata):
    metadata = Metadata.from_json(test_metadata)
    benchmark = metadata["ubuntu2404_CIS_1"]
    with pytest.raises(ProfileNotFoundError):
        benchmark.get_tailoring_file_relative_path("cis_level3_server")


def test_benchmark_tailoring_file(test_metadata):
    metadata = Metadata.from_json(test_metadata)
    benchmark = metadata["ubuntu2404_CIS_1"]
    assert benchmark.get_tailoring_file_relative_path("cis_level1_server") == Path(
        "ubuntu2404_CIS_1/tailoring/cis_level1_server-tailoring.xml"
    )
    assert benchmark.get_tailoring_file_relative_path("cis_level2_server") == Path(
        "ubuntu2404_CIS_1/tailoring/cis_level2_server-tailoring.xml"
    )


def test_benchmark_profiles(test_metadata):
    metadata = Metadata.from_json(test_metadata)
    benchmark = metadata["ubuntu2404_CIS_1"]
    # Test that profiles contain correct data
    for profile_id, profile in metadata["ubuntu2404_CIS_1"].profiles.items():
        assert isinstance(profile, OldProfile)
        assert profile.benchmark_channel == "ubuntu2404_CIS_1"
        assert profile.profile_id == profile_id
        assert (
            profile.profile_legacy_id
            == benchmark.profiles[profile_id].profile_legacy_id
        )
        assert profile.tailoring_file is None

