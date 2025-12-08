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
        ) -> dict[int, list[dict[str, Any]]]:
    """Bin releases into corresponding channels and sort from oldest to newest.

    Args:
        all_releases: list of dictionaries representation of CaC releases

    Returns:
        dictionary {channel1: list(release1, release2, ...), channel2: ...}

    """
    logger.debug("Entered get_release_successions()")

    # sanity check tailoring versions (channels) (should be all from 1 to max())
    channels = sorted({r["release_channel"] for r in all_releases})
    channels_good = list(range(1, max(channels) + 1))
    if channels != channels_good:
        raise BenchmarkProcessingError(
            f"Corrupt release file. Found tailoring versions {channels}. "
            f"Should be {channels_good}"
        )

    # bin by channel_id
    releases_by_channels = {channel: [] for channel in channels}
    for release in all_releases:
        channel = release["release_channel"]
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
    benchmarks = {}     # channel_id, channel_number, product, cac_profiles, latest_breaking_id, latest_compatible_id, state, ...
    release_channels = {}   # benchmark release channel information, latest release tag/commit/timestamp, data files, tailoring files

    # Preset common values
    product = yaml_data["general"]["product"]
    product_long = yaml_data["general"]["product_long"]
    benchmark_type = yaml_data["general"]["benchmark_type"]
    latest_release = list(releases_by_channels.values())[-1][-1]
    latest_version = latest_release["benchmark_data"]["version"]
    latest_channel_number = latest_release["release_channel"]
    latest_channel_id = f"{product}_{benchmark_type}_{latest_channel_number}"
    latest_benchmark_id = f"{latest_channel_id}-{latest_version}"

    # Add info from latest releases in each channel to 'channel_data'
    for channel_number, releases_in_channel in releases_by_channels.items():

        latest_release = releases_in_channel[-1]
        channel_id = f"{product}_{benchmark_type}_{channel_number}"
        assert channel_id not in release_channels
        release_channels[channel_id] = {
            "id": channel_id,
            "benchmark_ids": [], # populated below
            "channel_number": channel_number,
            "is_latest": channel_number == latest_channel_number,
            "cac_product": product,
            "cac_profiles": list(latest_release["benchmark_data"]["profiles"]), # store profiles here to ensure all benchmarks in one channel have same profiles
            "release_tag": latest_release["cac_tag"],
            "release_commit": latest_release["cac_commit"],
            "release_notes_url": latest_release["benchmark_data"]["release_notes_url"],
            "release_timestamp": None, # added at build time
            "data_files": None, # added at build time
            "tailoring_files": None, # added at build time
        }

    # find all benchmarks with unique IDs (versions) and add info to 'benchmarks' and 'profiles'
    for channel_number, releases_in_channel in releases_by_channels.items():
        channel_id = f"{product}_{benchmark_type}_{channel_number}"

        for i, release in enumerate(releases_in_channel):

            benchmark_version = release["benchmark_data"]["version"]
            benchmark_id = f"{channel_id}-{benchmark_version}"

            # Latest release in channel or latest release with specific version
            if release == releases_in_channel[-1] or \
                benchmark_version != releases_in_channel[i+1]["benchmark_data"]["version"]:

                benchmark = {
                    "id": benchmark_id,
                    "channel_id": channel_id,
                    "benchmark_type": benchmark_type,
                    "product": product,
                    "product_long": product_long,
                    "channel_number": channel_number,
                    "latest_breaking_id": None,
                    "latest_compatible_id": None,
                    "state": None,
                }
                benchmark.update(release["benchmark_data"])
                assert list(benchmark["profiles"]) == release_channels[channel_id]["cac_profiles"]
                assert benchmark_id not in benchmarks

                benchmarks[benchmark_id] = benchmark

                # add backreference to channel object
                release_channels[channel_id]["benchmark_ids"].append(benchmark_id)

                # get profiles and store them in 'profiles'
                for cac_profile_id in benchmark["profiles"]:
                    profile_id = f"{cac_profile_id}-{benchmark_version.lower()}"
                    if "ubuntu" not in product:
                        profile_id = f"{product}_{profile_id}"

                    assert profile_id not in profiles

                    # add original profile id-s to alias ids if initial version of benchmark
                    # to keep beackwards compatibility
                    alias_ids = []
                    if benchmark["channel_number"] == 1:
                        alias_ids.append(cac_profile_id)
                        # also add 'disa_stig' which is legacy name for stig
                        if cac_profile_id == "stig":
                            alias_ids.append("disa_stig")

                    profile = {
                        "id": profile_id,
                        "cac_id": cac_profile_id,
                        "alias_ids": alias_ids,
                        "benchmark_id": benchmark_id,
                        "latest_breaking_id": None,
                        "latest_compatible_id": None,
                    }
                    profiles[profile_id] = profile

                    # add backreference to benchmark
                    benchmarks[benchmark_id]["profiles"][cac_profile_id] = profile_id


    # Get latest compatible and breaking versions of benchmarks
    for benchmark_id, benchmark in benchmarks.items():

        channel_id = benchmark["channel_id"]
        channel_number = release_channels[channel_id]["channel_number"]
        latest_release_in_channel = releases_by_channels[channel_number][-1]
        latest_version_in_channel = latest_release_in_channel["benchmark_data"]["version"]
        latest_benchmark_id_in_channel = f"{channel_id}-{latest_version_in_channel}"

        benchmark["state"] = "Latest stable"
        # Benchmark is superseded by a newer release in same channel
        if benchmark_id != latest_benchmark_id_in_channel:
            benchmark["latest_compatible_id"] = latest_benchmark_id_in_channel
            benchmark["state"] = f"Superseded by {latest_version_in_channel}"

        # Benchmark is not in latest channel (maintenance mode)
        if channel_number != latest_channel_number:
            benchmark["latest_breaking_id"] = latest_benchmark_id
            benchmark["state"] = "Maintenance"  # overrides superseded

    # Get latest compatible and breaking versions of profiles
    for profile_id, profile in profiles.items():
        benchmark_id = profile["benchmark_id"]
        benchmark = benchmarks[benchmark_id]
        cac_profile_id = profile["cac_id"]

        # Superseded benchmark. Profile is superseded by same superseding benchmark.
        if benchmark["latest_compatible_id"]:
            superseding_benchmark = benchmarks[benchmark["latest_compatible_id"]]
            superseding_profile_id = superseding_benchmark["profiles"][cac_profile_id]
            assert superseding_profile_id in profiles
            profile["latest_compatible_id"] = superseding_profile_id

        # Find latest breaking profile via the most latest benchmark which contains the profile
        latest_breaking_benchmark = None
        # Latest channel (corresponding benchmark has no latest_breaking_id candidate)
        if benchmark["latest_breaking_id"] is None:
            latest_breaking_benchmark = None
        # Older channel (and the latest benchmark contains the profile id)
        elif cac_profile_id in benchmarks[benchmark["latest_breaking_id"]]["profiles"]:
            latest_breaking_benchmark = benchmarks[benchmark["latest_breaking_id"]]
        # Older channel (and the latest benchmark doesn't contain the profile id)
        # Find the latest benchmark which contains this profile
        else:
            channel_number = benchmark["channel_number"]
            for benchmark2 in benchmarks.values():
                channel_number2 = benchmark2["channel_number"]

                if channel_number2 > channel_number and \
                      benchmark2["latest_compatible_id"] is None and \
                      cac_profile_id in benchmark2["profiles"]:
                    channel_number = channel_number2
                    latest_breaking_benchmark = benchmark2

        if latest_breaking_benchmark:
            latest_breaking_id = latest_breaking_benchmark["profiles"][cac_profile_id]
            assert latest_breaking_id in profiles
        else:
            latest_breaking_id = None
        profile["latest_breaking_id"] = latest_breaking_id


    for s in ["profiles", "benchmarks", "release_channels"]:
        logger.debug(f"---{s}---")
        for k, v in locals()[s].items():
            logger.debug(f"{k}: {v}")

    return profiles, benchmarks, release_channels


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
        output_tailoring_path: Path,
        release_timestamp: int
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
            output_tailoring_path,
            release_timestamp
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
    release_channels: list[dict[str, Any]],
    cac_repo_dir: Path,
    tailoring_templates_dir: Path,
    dst_dir: Path,
    pre_built_data_dir: Path | None,
) -> None:
    # For each active release:
    # - build datastream (or use pre-built data)
    # - generate tailoring files
    # - generate checksums

    logger.info(f"Building {len(release_channels)} active releases...")

    for i, channel_data in enumerate(release_channels):
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
                        f"tests/data/input/"
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
                    channel_data["cac_product"]
                )
                logger.info("Successfully built CaC content.")


            channel_data["release_timestamp"] = release_timestamp
            cac_product = channel_data["cac_product"]
            
            # Compress datastream and save to destination dir
            # (e.g. dst dir/ubuntu2404_CIS_2/...)
            datastream_filename = CAC_RELEASE_NAME.format(cac_product)
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

            # Copy other SCAP files to destination dir
            scap_files = {
                "xccdf": f"ssg-{cac_product}-xccdf.xml",
                "oval": f"ssg-{cac_product}-oval.xml",
                "cpe-dict": f"ssg-{cac_product}-cpe-dictionary.xml",
                "cpe-oval": f"ssg-{cac_product}-cpe-oval.xml",
                "ocil": f"ssg-{cac_product}-ocil.xml",
            }
            for file_key, file_name in scap_files.items():
                src_path = tmp_build_dir / "build" / file_name
                dst_path = output_benchmark_dir / file_name
                logger.debug(f"Copying {file_key} file from {src_path} to {dst_path}")
                shutil.copy(src_path, dst_path)
                channel_data["data_files"][file_key] = {
                    "path": str(dst_path.relative_to(dst_dir)),
                    "sha256": _calc_sha256(dst_path)
                }

            # Copy SCE scripts
            logger.debug("Copying SCE scripts...")
            sce_scripts = (
                tmp_build_dir / "build" / cac_product / "checks/sce"
                ).glob("*")
            
            sce_dst_dir = output_benchmark_dir / cac_product / "checks/sce"
            sce_dst_dir.mkdir(parents=True)
            for sce_script in sce_scripts:
                logger.debug(f"Copying SCE script {sce_script}...")
                sce_dst_path = sce_dst_dir / Path(sce_script).name
                shutil.copy(sce_script, sce_dst_path)
                sce_dst_path.chmod(0o755)  # SCEs must be executable

            # Generate tailoring files
            logger.debug("Generating tailoring files for benchmark {benchmark_id}...")
            output_tailoring_files_dir = output_benchmark_dir / "tailoring"
            output_tailoring_files_dir.mkdir()
            channel_data["tailoring_files"] = {}

            cac_profiles_dir = (
                tmp_build_dir / "products" / channel_data["cac_product"] / "profiles"
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
                    output_tailoring_path,
                    release_timestamp
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
        "profiles": [],
        "benchmarks": [],
        "release_channels": [],
    }

    # parse and process benchmark yaml files
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
        profiles, benchmarks, release_channels = _process_yaml(yaml_data)
        logger.info(f"Found {len(benchmarks)} benchmark versions containing a total of {len(profiles)} profiles.")
        for b in benchmarks.values():
            logger.info(
                    f"Benchmark: {b['id']}, Release channel: {b['channel_id']}, "
                    f"Latest tag: {release_channels[b['channel_id']]['release_tag']}."
                    )
        benchmarks_json_data["profiles"].extend(profiles.values())
        benchmarks_json_data["benchmarks"].extend(benchmarks.values())
        benchmarks_json_data["release_channels"].extend(release_channels.values())

    # build data for active releases
    with tempfile.TemporaryDirectory() as tmp_dst_dir:
        logger.info(f"Building benchmark data in {tmp_dst_dir}")
        _build_active_releases(
            benchmarks_json_data["release_channels"],
            cac_repo_dir,
            tailoring_templates_dir,
            Path(tmp_dst_dir),
            pre_built_data_dir
            )
        logger.info(f"Copying benchmark files and folders to {out_dir}")
        shutil.copytree(tmp_dst_dir, out_dir, dirs_exist_ok=True)

    # update benchmark metadata and store in json
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
