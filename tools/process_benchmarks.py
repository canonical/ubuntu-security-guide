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
        ) -> dict[str, Any]:
    """Bin releases into corresponding channels and sort from oldest to newest.

    Args:
        all_releases: list of dictionaries representation of CaC releases

    Returns:
        dictionary {channel1: list(release1, release2, ...), channel2: ...}

    """
    logger.debug("Entered get_release_successions()")

    # sanity check tailoring versions (channels) (should be all from 1 to max())
    channels = sorted([r["tailoring_version"] for r in all_releases])
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
            )[::-1]
        orphaned = set(releases_in_channel) - set(sorted_releases)
        if orphaned:
            raise BenchmarkProcessingError(
                f"Releases in channel {channel} do not have a valid succession. "
                f"These releases are orphaned: {','.join(r['cac_tag'] for r in orphaned)}."
            )
        releases_by_channels[channel] = sorted_releases

    # Debug print
    logger.debug("--- Listing all releases")
    for channel, releases_in_channel in releases_by_channels.items():
        logger.debug(f"Channel ID: {channel}")
        for release in releases_in_channel:
            logger.debug(f" - Release: {release['cac_tag']}")
    logger.debug("---")

    return releases_by_channels



def _process_yaml(yaml_data: dict[str, Any]) -> list[dict[str, Any]]:
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

    # how would I like to see this?
    # should there really be backreferencing? Does b_data need information about channels?
    # Or should there be channels which reference the benchmark?

    # The profile needs to be the main structure:
    #  - id, benchmark reference, 
    # The benchmark needs to have:
    #  - title, version, release info
    # There can be another structure which has compatibility information (Relations, Compatibility)
    #  - 

    # Populate fields
    profiles = 
    all_channels = list(releases_by_channels)
    for i, (tailoring_version, releases_in_channel) in enumerate(releases_by_channels.items()):
        for release in releases_in_channel:
            b_data = {}
            b_data.update(yaml_data["general"])
            b_data.update(release["benchmark_data"])
            assert release["tailoring_version"] == tailoring_version, "Should not happen"
            b_data["tailoring_version"] = release["tailoring_version"]
            channel_id = "{}_{}_{}".format(
                b_data["product"], b_data["benchmark_type"], b_data["tailoring_version"]
            )
            benchmark_id = f"{channel_id}-{b_data['version']}"
            b_data.update(
                {
                    "benchmark_id": benchmark_id,
                    "channel_id": channel_id,
                }
            )
            release["benchmark_data"] = b_data        # last 
            if i == len(releases_by_channels) - 1:
                    "benchmarks_in_channel": [],
                    "is_latest_in_channel": False,
                    "is_latest_channel": False,
                    "breaking_upgrade_path": [],


    logger.debug("--- Listing benchmarks")
    for r in all_releases:
        logger.debug(f"Benchmark: {r['benchmark_data']['benchmark_id']}")

    logger.debug("Exiting process_yaml()")

    return all_releases


def _get_superseded_compatible(
    release: dict[str, Any],
) -> list[str]:
    # Return the list of releases which are superseded by the given release and
    # which are compatible with it (non-breaking)
    logger.debug(f"From _get_superseded_compatible({release['cac_tag']})")

    compatible_versions = set()
    for r in release["upgrade_paths"]["compatible"]:
        if r != release:
            benchmark_version = r["benchmark_data"]["version"]
            logger.debug(
                f"Found superseded release with benchmark version: "
                f"{benchmark_version} (cac_tag: {r['cac_tag']})."
            )
            if benchmark_version == release["benchmark_data"]["version"]:
                logger.debug(
                    "benchmark version is the same as active release. "
                    "Not adding it to list of compatible_versions"
                )
            else:
                logger.debug(
                    f"Adding the release with benchmark version {benchmark_version} to "
                    f"list of compatible_versions in benchmark in release "
                    f"{release['cac_tag']}"
                )
                compatible_versions.add(benchmark_version)
    return sorted(compatible_versions)


def _get_breaking_upgrade_path(
    release: dict[str, Any], all_releases: list[dict[str, Any]]
) -> list[str]:
    # return the list of all breaking releases superseding given releases

    logger.debug(f"From _get_breaking_upgrade_path({release['cac_tag']})")

    def _get_breaking_list(r: dict[str, Any]) -> Iterator[dict[str, Any]]:
        # recursive search for successive breaking releases
        # returns succession in reverse order (from newest to oldest release)
        if r["upgrade_paths"]["next_breaking"]:
            for r_next in all_releases:
                if r_next == r["upgrade_paths"]["next_breaking"]:
                    yield from _get_breaking_list(r_next)
        yield r

    next_breaking = release["upgrade_paths"]["next_breaking"]
    next_breaking_latest_compatible = next_breaking["upgrade_paths"][
        "latest_compatible"
    ]

    logger.debug(
        f"Release can be upgraded to the next breaking release with version: "
        f"{next_breaking_latest_compatible['benchmark_data']['version']} "
        f"({next_breaking_latest_compatible['cac_tag']})"
    )

    breaking_succession = list(_get_breaking_list(next_breaking))[::-1]

    logger.debug(f"Printing full upgrade path for release {release['cac_tag']}:")
    breaking_upgrade_path = []
    for i, breaking_release in enumerate(breaking_succession):
        breaking_latest_compatible = breaking_release["upgrade_paths"][
            "latest_compatible"
        ]
        breaking_cac_tag = breaking_latest_compatible["cac_tag"]
        breaking_benchmark_version = breaking_latest_compatible["benchmark_data"][
            "version"
        ]
        breaking_upgrade_path.append(breaking_benchmark_version)
        logger.debug(f"  {i + 1}: {breaking_benchmark_version} ({breaking_cac_tag})")
    return breaking_upgrade_path


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
    all_active_releases: list[dict[str, Any]],
    cac_repo_dir: Path,
    tailoring_templates_dir: Path,
    dst_dir: Path,
    pre_built_data_dir: Path | None,
) -> None:
    # For each active release:
    # - build datastream (or use pre-built data)
    # - generate tailoring files
    # - generate checksums

    logger.info(f"Building {len(all_active_releases)} active releases...")

    for i, release in enumerate(all_active_releases):
        cac_tag = release["cac_tag"]
        b_data = release["benchmark_data"]
        benchmark_id = b_data["benchmark_id"]
        logger.info(f"Building CaC release {cac_tag} (benchmark ID = {benchmark_id})")

        # Create output directory based on benchmark id (dst_dir/benchmark_id)
        output_benchmark_dir = dst_dir / benchmark_id
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
                    release["cac_commit"],
                    b_data["product"]
                )
                logger.info("Successfully built CaC content.")


            b_data["release_timestamp"] = release_timestamp

            # Compress datastream and save to destination dir
            # (e.g. dst dir/ubuntu2404_CIS_2/...)
            datastream_filename = CAC_RELEASE_NAME.format(b_data["product"])
            datastream_build_path = tmp_build_dir / "build" / datastream_filename
            datastream_dst_gz_path = (
                    output_benchmark_dir / datastream_filename
                    ).with_suffix(".xml.gz")
            _save_compressed_datastream(datastream_build_path, datastream_dst_gz_path)

            # Calc hashes and set metadata for datastream
            b_data["data_files"] = {
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
            b_data["tailoring_files"] = {}

            cac_profiles_dir = (
                tmp_build_dir / "products" / b_data["product"] / "profiles"
            )
            for profile_id in b_data["profiles"]:
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
                    benchmark_id,
                    output_tailoring_path
                )

                # Calc hashes and set metadata
                b_data["tailoring_files"][profile_id] = {
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

    - Parse yaml files and get list of active CaC releases (_process_yaml)
    - Build active ComplianceAsCode releases
    - Write benchmark metadata json
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
    all_active_releases = []
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

        # process yaml and store active releases
        releases = _process_yaml(yaml_data)

        latest_in_channels = [releases_in_channel[-1] for releases_in_channel in releases]
        # find also 

        all_active_releases.extend(active_releases)
        _log_upgrade_paths(active_releases)


    # build data for active releases
    with tempfile.TemporaryDirectory() as tmp_dst_dir:
        logger.info(f"Building benchmark data in {tmp_dst_dir}")
        _build_active_releases(
            all_active_releases,
            cac_repo_dir,
            tailoring_templates_dir,
            Path(tmp_dst_dir),
            pre_built_data_dir
            )
        logger.info(f"Copying benchmark files and folders to {out_dir}")
        shutil.copytree(tmp_dst_dir, out_dir, dirs_exist_ok=True)

        # build CaC datastreams and
        # Get the actual benchmark data and files
      #   - download release datastream
    #   - generate tailoring files and whatever else is needed

    # extract benchmark metadata and store in json
    benchmarks_metadata = [r["benchmark_data"] for r in all_active_releases]
    benchmarks_json_data["benchmarks"].extend(benchmarks_metadata)

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
