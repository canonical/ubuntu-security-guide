#!/usr/bin/env python3
#
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

"""Functions and CLI for processing USG benchmark releases."""
from dataclasses import dataclass
import sys

if sys.version_info < (3,12):
    sys.exit("Build tools require Python>=3.12")

import argparse
import gzip
import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml
from generate_tailoring_file import (
    GenerateTailoringError,
    generate_tailoring_file,
    validate_tailoring_file,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
OUTPUT_JSON_NAME = "benchmarks.json"
CAC_RELEASE_NAME = "ssg-{}-ds.xml"
CAC_TAILORING_NAME = "{}-tailoring.xml"


class BenchmarkProcessingError(Exception):
    """Error processing benchmark data."""


def _get_release_succession(r: dict[str, Any], releases: list[Any]) -> Iterator[dict[str, Any]]:
    """Search recursively for release succession from latest release backwards."""
    for r_parent in releases:
        if r_parent["cac_tag"] == r["parent_tag"]:
            yield from _get_release_succession(r_parent, releases)
    yield r

def _get_release_channel_successions(
        all_releases: list[dict[str, Any]]
        ) -> dict[int, list[dict[str, Any]]]:
    """Bin releases into corresponding channels and sort from oldest to newest.

    Args:
        all_releases: list of dictionaries representation of CaC releases

    Returns:
        dictionary {channel1: list(release1, release2, ...), channel2: ...}

    """
    logger.debug("Entered get_release_successions()")

    # sanity check tailoring versions (channels) (should be all from 1 to max())
    channels = sorted({r["tailoring_version"] for r in all_releases})
    channels_good = list(range(1, max(channels) + 1))
    if channels != channels_good:
        raise BenchmarkProcessingError(
            f"Corrupt release file. Found tailoring versions {channels}. "
            f"Should be {channels_good}"
        )

    # bin by channel_id
    releases_by_channels = {channel: [] for channel in channels}
    for release in all_releases:
        channel = release["tailoring_version"]
        releases_by_channels[channel].append(release)

    # sort by release (first to latest) and sanity checks
    for channel, releases_in_channel in releases_by_channels.items():

        # get the latest in the group (not anyone's parent)
        parent_tags = [r["parent_tag"] for r in releases_in_channel]
        not_a_parent_release = [r for r in releases_in_channel if r["cac_tag"] not in parent_tags]
        if len(not_a_parent_release) != 1:
            raise BenchmarkProcessingError(
                f"There should be exactly 1 release without children in channel {channel}. "
                f"Found: {not_a_parent_release}."
            )

        # get succession and ensure all releases are included
        sorted_releases = list(_get_release_succession(
            not_a_parent_release[0], releases_in_channel)
            )
        orphaned = {r["cac_tag"] for r in releases_in_channel} - {r["cac_tag"] for r in sorted_releases}
        if orphaned:
            raise BenchmarkProcessingError(
                f"Releases in channel {channel} do not have a valid succession. "
                f"These releases are orphaned: {','.join(r['cac_tag'] for r in orphaned)}."
            )
        releases_by_channels[channel] = sorted_releases

    # sanity check that same benchmark version doesn't appear in multiple channels
    for channel1, releases_in_channel1 in releases_by_channels.items():
        unique_versions1 = {r["benchmark_data"]["version"] for r in releases_in_channel1}
        for channel2, releases_in_channel2 in releases_by_channels.items():
            if channel1 != channel2:
                unique_versions2 = {r["benchmark_data"]["version"] for r in releases_in_channel2}
                if unique_versions1 & unique_versions2:
                    raise BenchmarkProcessingError(
                        f"Same benchmark version cannot appear in different release channels. "
                        f"Offending versions: {unique_versions1 & unique_versions2}"
                    )

    # Debug print
    logger.debug("--- Listing all releases")
    for channel, releases_in_channel in releases_by_channels.items():
        logger.debug(f"Channel: {channel}")
        for release in releases_in_channel:
            logger.debug(f" - Release tag: {release['cac_tag']}")
    logger.debug("---")

    return releases_by_channels




def _process_yaml(yaml_data: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    # Process CaC release yaml configuration file

    # Iterate over release list and:
    # - generate channel and benchmark IDs used in USG
    # - map compatibility with older releases (same channel)
    #   - generate complete breaking upgrade path
    # - return list of all releases

    # Initial iteration over the releases:
    # - initialize several empty fields and generate benchmark_id
    logger.debug("Entered process_yaml()")

    all_releases = sorted(
        yaml_data["benchmark_releases"], key=lambda x: x["usg_version"] + x["cac_tag"]
    )

    # Bin releases to channels and sort the channels and releases in channels from oldest to newest
    releases_by_channels = _get_release_channel_successions(all_releases)

    # Populate base data structures
    profiles = {}       # cac_profile_id, latest_breaking_id, latest_compatible_id, ...
    benchmarks = {}     # channel_id, tailoring_version, product, cac_profiles, latest_breaking_id, latest_compatible_id, state, ...
    channel_releases = {}   # latest release info, data files

    all_channels = list(releases_by_channels)
    product = yaml_data["general"]["product"]
    benchmark_type = yaml_data["general"]["benchmark_type"]

    # add info from latest releases in each channel to 'channel_data'
    for tailoring_version, releases_in_channel in releases_by_channels.items():

        latest_release = releases_in_channel[-1]
        channel_id = f"{product}_{benchmark_type}_{tailoring_version}"
        assert channel_id not in channel_releases
        channel_releases[channel_id] = {
            "id": channel_id,
            "cac_profiles": list(latest_release["benchmark_data"]["profiles"]), # all benchmarks in one channel should have same profiles
            "product": product,
            "benchmark_type": benchmark_type,
            "tailoring_version": tailoring_version,
            "release_tag": latest_release["cac_tag"],
            "release_commit": latest_release["cac_commit"],
            "release_notes_url": latest_release["benchmark_data"]["release_notes_url"],
            "release_timestamp": None, # added at build time
            "data_files": None, # added at build time
            "tailoring_files": None, # added at build time
        }

    # find all benchmarks with unique IDs (versions) and add info to 'benchmarks' and 'profiles'
    for tailoring_version, releases_in_channel in releases_by_channels.items():
        channel_id = f"{product}_{benchmark_type}_{tailoring_version}"

        for release in reversed(releases_in_channel):
            benchmark_version = release["benchmark_data"]["version"]
            benchmark_id = f"{channel_id}-{benchmark_version}"

            if benchmark_id not in benchmarks:
                b_data = {
                    "id": benchmark_id,
                    "channel_id": channel_id,
                    "product": product,
                    "benchmark_type": benchmark_type,
                    "tailoring_version": tailoring_version,
                    "latest_breaking_id": None,
                    "latest_compatible_id": None,
                    "state": None,
                }
                b_data.update(release["benchmark_data"])
                assert list(b_data["profiles"]) == channel_releases[channel_id]["cac_profiles"]

                benchmarks[benchmark_id] = b_data

                # get profiles and store them in 'profiles'
                for cac_profile_id in b_data["profiles"]:
                    profile_id = f"{benchmark_id}_{cac_profile_id}"
                    assert profile_id not in profiles
                    profile = {
                        "id": profile_id,
                        "cac_id": cac_profile_id,
                        "benchmark_id": benchmark_id,
                        "latest_breaking_id": None,
                        "latest_compatible_id": None,
                    }
                    profiles[profile_id] = profile


    # Get relationships and states (latest_compatible_id, latest_breaking_id, maintenance/superseded/latest)
    latest_release = list(releases_by_channels.values())[-1][-1]
    latest_version = latest_release["benchmark_data"]["version"]
    latest_tailoring = latest_release["tailoring_version"]
    latest_channel_id = f"{product}_{benchmark_type}_{latest_tailoring}"
    latest_benchmark_id = f"{latest_channel_id}-{latest_version}"

    for benchmark_id, b_data in benchmarks.items():

        tailoring_version = b_data["tailoring_version"]
        channel_id = f"{product}_{benchmark_type}_{tailoring_version}"
        latest_release_in_channel = releases_by_channels[tailoring_version][-1]
        latest_version_in_channel = latest_release_in_channel["benchmark_data"]["version"]
        latest_benchmark_id_in_channel = f"{channel_id}-{latest_version_in_channel}"

        # Benchmark is not in latest channel (maintenance mode)
        if tailoring_version != latest_tailoring:
            b_data["latest_breaking_id"] = latest_benchmark_id
            b_data["latest_compatible_id"] = None
            b_data["state"] = "Maintenance"

        # Latest channel but not latest in channel (superseded by latest)
        elif benchmark_id != latest_benchmark_id_in_channel:
            b_data["latest_breaking_id"] = None
            b_data["latest_compatible_id"] = latest_benchmark_id_in_channel
            b_data["state"] = "Superseded"

        # Latest
        else:
            b_data["latest_breaking_id"] = None
            b_data["latest_compatible_id"] = None
            b_data["state"] = "Latest"


    for profile_id, profile in profiles.items():
        benchmark_id = profile["benchmark_id"]
        b_data = benchmarks[benchmark_id]
        cac_profile_id = profile["cac_id"]

        # Superseded benchmark. Profile is superseded by same superseding benchmark.
        if b_data["latest_compatible_id"]:
            superseding_benchmark_id = benchmarks[b_data["latest_compatible_id"]]["id"]
            superseding_profile_id = f"{superseding_benchmark_id}_{cac_profile_id}"
            assert superseding_profile_id in profiles
            profile["latest_compatible_id"] = superseding_profile_id

        # Latest channel (corresponding benchmark has no latest_breaking_id candidate)
        if b_data["latest_breaking_id"] is None:
            profile["latest_breaking_id"] = None

        # Older channel (and the latest benchmark contains the profile id)
        elif cac_profile_id in benchmarks[b_data["latest_breaking_id"]]["profiles"]:
            profile["latest_breaking_id"] = b_data["latest_breaking_id"]

        # Older channel (and the latest benchmark doesn't contain the profile id)
        # Find the latest benchmark which contains this profile
        else:
            benchmarks_sorted_by_channels = sorted(
                benchmarks.values(), key=lambda b: b["tailoring_version"]
                )
            for b in reversed(benchmarks_sorted_by_channels):
                if b["tailoring_version"] > b_data["tailoring_version"] and \
                    cac_profile_id in b["profiles"]:
                    b_data["latest_breaking_id"] = b["id"]
                    break
    
    for s in ["profiles", "benchmarks", "channel_releases"]:
        logger.debug(f"---{s}---")
        for k, v in locals()[s].items():
            logger.debug(k,v)

    return profiles, benchmarks, channel_releases


def _build_cac_release(cac_repo_dir: Path, commit: str, cac_product: str) -> int:
    # Reset CaC repo to commit and build product cac_product
    # Return timestamp of commit
    # Raises BenchmarkProcessingError on failure to build

    logger.debug("Building repo {cac_repo_dir}, commit {commit}, product {cac_product}")

    # cleanup repo and checkout commit
    for cmd in (
        ["/usr/bin/git", "reset", "--hard"],
        ["/usr/bin/git", "clean", "-fxd"],
        ["/usr/bin/git", "checkout", commit],
    ):
        logger.debug(f"Calling cmd: {cmd}")
        try:
            p = subprocess.run(
                    cmd,
                    cwd=cac_repo_dir,
                    check=True,
                    text=True,
                    capture_output=True
                    )  # noqa: S603
            logger.debug(f"STDOUT: {p.stdout}")
            logger.debug(f"STDERR: {p.stderr}")
        except subprocess.CalledProcessError as e:
            logger.error(p.stderr)
            raise BenchmarkProcessingError(
                f"Failed to checkout commit {commit} in repo {cac_repo_dir}: {e}"
                ) from e


    # get timestamp of last commit
    env = os.environ.copy()
    env["TZ"] = "UTC0"
    cmd = ["/usr/bin/git", "log", "-1", "--format=tformat:%cd", "--date=format:%s"]

    try:
        logger.debug(f"Calling cmd: {cmd}")
        out = subprocess.check_output(
            cmd, cwd=cac_repo_dir, env=env, text=True
            )
        commit_timestamp = int(out.strip())
    except (subprocess.CalledProcessError, ValueError) as e:
        raise BenchmarkProcessingError(
            f"Failed to get timestamp for commit {commit}: {e}"
        ) from e

    logger.debug(f"Commit timestamp: {commit_timestamp}")
    # build CaC product
    env["SOURCE_DATE_EPOCH"] = str(commit_timestamp)
    env["ADDITIONAL_CMAKE_OPTIONS"] = "-DSSG_SCE_ENABLED:BOOL=ON -DSSG_OVAL_SCHEMATRON_VALIDATION_ENABLED=OFF"
    cmd = [cac_repo_dir/"build_product", "-j4", cac_product]

    try:
        logger.debug(f"Calling cmd: {cmd}")
        p = subprocess.run(
                cmd,
                cwd=cac_repo_dir,
                env=env,
                check=True,
                text=True,
                capture_output=True
                )  # noqa: S603
    except subprocess.CalledProcessError as e:
        logger.error(p.stderr)
        raise BenchmarkProcessingError(
            f"Failed to build repo {cac_repo_dir}: {e}"
            ) from e

    logger.debug(f"STDOUT: {p.stdout}")
    logger.debug(f"STDERR: {p.stderr}")
    logger.debug("Successfully built CaC release")
    return commit_timestamp


def _save_compressed_datastream(src: Path, dst_gz: Path) -> None:
    # gzip compress datastream src to dst
    logger.debug(f"Compressing datastream to {dst_gz}")
    try:
        with src.open("rb") as ds:  # noqa: SIM117
            with gzip.GzipFile(dst_gz, mode="wb", mtime=0) as ds_gz:
                shutil.copyfileobj(ds, ds_gz)
    except Exception as e:
        raise BenchmarkProcessingError(
            f"Failed to compress datastream {src} "
            f"to {dst_gz}: {e}"
        ) from e


def _create_tailoring_file(
        profile_path: Path,
        datastream_build_path: Path,
        tailoring_template_path: Path,
        benchmark_id: str,
        output_tailoring_path: Path
) -> None:
    # Generate and validate tailoring file
    if not profile_path.exists():
        raise BenchmarkProcessingError(
            f"Profile {profile_path} not found in ComplianceAsCode repo."
        )
    if not tailoring_template_path.exists():
        raise BenchmarkProcessingError(
            f"Tailoring template {tailoring_template_path} not found in template dir."
        )

    try:
        generate_tailoring_file(
            profile_path,
            datastream_build_path,
            tailoring_template_path,
            benchmark_id,
            output_tailoring_path
        )
        validate_tailoring_file(output_tailoring_path)
    except GenerateTailoringError as e:
        raise BenchmarkProcessingError(
            f"Failed to generate tailoring file {output_tailoring_path}: {e}"
        ) from e


def _calc_sha256(path: Path) -> str:
    # return sha256 for file
    with path.open("rb") as f:
        digest = hashlib.file_digest(f, "sha256").hexdigest()
    logger.debug(f"sha256 for {path}: {digest}")
    return digest


def _build_active_releases(
    channel_releases: list[dict[str, Any]],
    cac_repo_dir: Path,
    tailoring_templates_dir: Path,
    dst_dir: Path,
    pre_built_data_dir: Path | None,
) -> None:
    # For each active release:
    # - build datastream (or use pre-built data)
    # - generate tailoring files
    # - generate checksums

    logger.info(f"Building {len(channel_releases)} active releases...")

    for i, channel_data in enumerate(channel_releases):
        cac_tag = channel_data["release_tag"]
        channel_id = channel_data["id"]
        logger.info(f"Building CaC release {cac_tag} (channel ID = {channel_id})")

        # Create output directory based on benchmark id (dst_dir/benchmark_id)
        output_benchmark_dir = dst_dir / channel_id
        output_benchmark_dir.mkdir(parents=True, exist_ok=True)

        # Create new tmp build dir for each release
        with tempfile.TemporaryDirectory(prefix=f"cac_{cac_tag}_") as tmp_build_dir_x:
            # Build the CaC tag in tmp_build_dir or copy pre-built data
            logger.debug(f"Building in temporary directory: {tmp_build_dir_x}")
            tmp_build_dir = Path(tmp_build_dir_x)
            if pre_built_data_dir:
                release_dir = pre_built_data_dir / cac_tag
                if not release_dir.exists():
                    raise BenchmarkProcessingError(
                        f"Data directory {cac_tag} does not exist in "
                        f"{pre_built_data_dir}. "
                        f"Check the pre-built-data-dir argument. "
                        f"Ensure the directory structure matches the one used in "
                        f"tools/tests/data/input/"
                    )
                logger.debug(f"Copying test data from {release_dir} to {tmp_build_dir}")
                shutil.copytree(release_dir, tmp_build_dir, dirs_exist_ok=True)
                release_timestamp = i+1 # dummy timestamp
            else:
                logger.debug(
                    f"Copying the CaC repo {cac_repo_dir} to tmp dir {tmp_build_dir}"
                    )
                shutil.copytree(
                    cac_repo_dir,
                    tmp_build_dir,
                    dirs_exist_ok=True,
                    ignore_dangling_symlinks=True
                    )
                release_timestamp = _build_cac_release(
                    tmp_build_dir,
                    channel_data["release_commit"],
                    channel_data["product"]
                )
                logger.info("Successfully built CaC content.")


            channel_data["release_timestamp"] = release_timestamp

            # Compress datastream and save to destination dir
            # (e.g. dst dir/ubuntu2404_CIS_2/...)
            datastream_filename = CAC_RELEASE_NAME.format(channel_data["product"])
            datastream_build_path = tmp_build_dir / "build" / datastream_filename
            datastream_dst_gz_path = (
                    output_benchmark_dir / datastream_filename
                    ).with_suffix(".xml.gz")
            _save_compressed_datastream(datastream_build_path, datastream_dst_gz_path)

            # Calc hashes and set metadata for datastream
            channel_data["data_files"] = {
                "datastream_gz": {
                    "path": str(datastream_dst_gz_path.relative_to(dst_dir)),
                    "sha256": _calc_sha256(datastream_dst_gz_path),
                    "sha256_orig": _calc_sha256(datastream_build_path)
                }
            }

            # Generate tailoring files
            logger.debug("Generating tailoring files for benchmark {benchmark_id}...")
            output_tailoring_files_dir = output_benchmark_dir / "tailoring"
            output_tailoring_files_dir.mkdir()
            channel_data["tailoring_files"] = {}

            cac_profiles_dir = (
                tmp_build_dir / "products" / channel_data["product"] / "profiles"
            )
            for profile_id in channel_data["cac_profiles"]:
                logger.info(f"Generating tailoring file for profile {profile_id}")

                profile_path = cac_profiles_dir / f"{profile_id}.profile"
                tailoring_template_path = (
                        tailoring_templates_dir / f"{profile_id}-tailoring.xml"
                        )
                output_tailoring_path = (
                        output_tailoring_files_dir / f"{profile_id}-tailoring.xml"
                        )

                _create_tailoring_file(
                    profile_path,
                    datastream_build_path,
                    tailoring_template_path,
                    channel_id,
                    output_tailoring_path
                )

                # Calc hashes and set metadata
                channel_data["tailoring_files"][profile_id] = {
                    "path": str(output_tailoring_path.relative_to(dst_dir)),
                    "sha256": _calc_sha256(output_tailoring_path)
                }
                logger.info(
                    f"Successfully generated tailoring file {output_tailoring_path}"
                )

            # Copy licence files
            license_build_path = tmp_build_dir / "LICENSE"
            license_dst = output_benchmark_dir / "LICENSE"
            logger.debug("Copying license file to {license_dst}")
            shutil.copy(license_build_path, license_dst)


def _log_upgrade_paths(active_releases: list[dict[str, Any]]) -> None:
    # print out clean upgrade paths
    logger.info("--- Benchmark upgrade paths ---")
    for _, release in enumerate(sorted(active_releases,
                                 key=lambda x: x["benchmark_data"]["benchmark_id"])):
        b = release["benchmark_data"]
        compatible_versions = [
            x for x in b["compatible_versions"] if x != b["benchmark_id"]
        ] or []
        compatible_versions = ", ".join(compatible_versions)

        logger.info(f"Benchmark id/version: {b['benchmark_id']}/{b['version']}")
        if compatible_versions:
            logger.info(
                f"Automatically replaces deprecated versions: {compatible_versions}"
            )

        logger.info("Upgrade path:")
        upgrade_path = b["breaking_upgrade_path"]
        if upgrade_path:
            for j, benchmark_id in enumerate(upgrade_path):
                logger.info(f"{j + 1}: {benchmark_id}")
        else:
            logger.info("None, this is the latest release!")

    logger.info("----------------------------")


def process_benchmarks(
    benchmark_yaml_files: list[Path],
    cac_repo_dir: Path,
    tailoring_templates_dir: Path,
    pre_built_data_dir: Path,
    out_dir: Path,
) -> None:
    """Process benchmark releases defined in benchmark_yaml_files.

    - Parse yaml files and get profile,benchmark,and channel data on CaC releases (_process_yaml)
    - Build active ComplianceAsCode releases (latest in each channel)
    - Write data to benchmark metadata json
    """
    if out_dir.exists() and list(out_dir.rglob("*.xml")):
        raise BenchmarkProcessingError(
            f"Benchmark directory {out_dir} is not empty. "
            f"Remove the old data and re-run the script."
        )

    if cac_repo_dir is not None and not (cac_repo_dir / ".git").is_dir():
        raise BenchmarkProcessingError(
            f"ComplianceAsCode directory {cac_repo_dir} doesn't exist "
            f"or is not a git repository."
        )

    logger.info(f"Schema version is: {SCHEMA_VERSION}")
    benchmarks_json_data = {
        "version": SCHEMA_VERSION,
        "benchmarks": [],
    }

    # parse and process benchmark yaml files
    data = {
        "profiles": [],
        "benchmarks": [],
        "channel_releases": [],
    }
    for benchmark_yaml in sorted(benchmark_yaml_files):
        logger.info(f"Processing yaml - {benchmark_yaml}")
        with Path(benchmark_yaml).open() as f:
            yaml_data = yaml.safe_load(f.read())

        # sanity checks
        for k in ["general", "benchmark_releases"]:
            if not yaml_data.get(k):
                raise BenchmarkProcessingError(
                    f"Error: Key {k} not found in {benchmark_yaml}."
                )

        for k in ["benchmark_type", "product"]:
            if not yaml_data["general"].get(k):
                raise BenchmarkProcessingError(
                    f"Error: Key general.{k} not found in {benchmark_yaml}."
                )

        # get available profiles,benchmarks,channels
        profiles, benchmarks, channel_releases = _process_yaml(yaml_data)
        data["profiles"].extend(profiles.values())
        data["benchmarks"].extend(benchmarks.values())
        data["channel_releases"].extend(channel_releases.values())
#        _log_upgrade_paths(active_releases)

    # build data for active releases
    with tempfile.TemporaryDirectory() as tmp_dst_dir:
        logger.info(f"Building benchmark data in {tmp_dst_dir}")
        _build_active_releases(
            data["channel_releases"],
            cac_repo_dir,
            tailoring_templates_dir,
            Path(tmp_dst_dir),
            pre_built_data_dir
            )
        logger.info(f"Copying benchmark files and folders to {out_dir}")
        shutil.copytree(tmp_dst_dir, out_dir, dirs_exist_ok=True)

    # update benchmark metadata and store in json
    benchmarks_json_data.update(data)
    json_output = out_dir / OUTPUT_JSON_NAME
    json_output.write_text(
        json.dumps(benchmarks_json_data, indent=2) + "\n"
        )
    logger.info(f"Wrote benchmark metadata to {json_output}")

    # calc hash of json
    with (out_dir / OUTPUT_JSON_NAME).open("rb") as f:
        digest = hashlib.file_digest(f, "sha256")
    logger.info(f"sha256({OUTPUT_JSON_NAME}): {digest.hexdigest()}")






def main() -> None:
    """Command line entry point."""
    parser = argparse.ArgumentParser()
    mutex_group = parser.add_mutually_exclusive_group(required=True)
    mutex_group.add_argument(
        "-c", "--complianceascode-repo-dir",
        type=Path,
        help="Path to up-to-date ComplianceAsCode repo."
        )
    mutex_group.add_argument(
        "--pre-built-data-dir",
        type=Path,
        help="Dir containing pre-built data (mainly used for testing)",
    )
    parser.add_argument(
        "-b", "--benchmark-yaml-files", type=Path, required=True, nargs="+"
    )
    parser.add_argument("-t", "--tailoring-templates-dir", type=Path, required=True)
    parser.add_argument("-o", "--output-dir", type=Path, required=True)
    parser.add_argument("-d", "--debug", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    if args.debug:
        logger.setLevel(logging.DEBUG)

    if args.pre_built_data_dir is not None:
        logger.warning(f"Using pre-built data from {args.pre_built_data_dir}")

    try:
        process_benchmarks(
            args.benchmark_yaml_files,
            args.complianceascode_repo_dir,
            args.tailoring_templates_dir,
            args.pre_built_data_dir,
            args.output_dir,
        )
    except BenchmarkProcessingError as e:
        logger.error(f"Error processing benchmarks: {e}")
        sys.exit(1)
    except Exception as e:
        logger.exception(e)
        sys.exit(1)

    logger.info("Done!")


if __name__ == "__main__":
    main()
