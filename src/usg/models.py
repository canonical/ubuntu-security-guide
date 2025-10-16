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

"""Data classes."""

import json
import logging
import re
import xml.etree.ElementTree as ET
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from usg.exceptions import BenchmarkError, ProfileNotFoundError, TailoringFileError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DataFile:
    """Immutable representation of a Benchmark data file."""

    type: str
    rel_path: Path
    sha256: str
    sha256_orig: str


class BenchmarkType(str, Enum):
    """Benchmark type."""

    CIS = "CIS"
    STIG = "STIG"


@dataclass(frozen=True)
class Benchmark:
    """Immutable representation of a benchmark entry in benchmarks.json."""

    id: str
    channel_id: str
    benchmark_type: BenchmarkType
    product: str
    product_long: str
    version: str
    tailoring_version: int
    description: str
    release_notes_url: str
    release_timestamp: int
    reference_url: str
    compatible_versions: tuple[str, ...]
    breaking_upgrade_path: tuple[str, ...]
    is_latest: bool
    tailoring_files: dict[str, dict[str, str]]
    profiles: dict[str, dict]
    data_files: dict[str, DataFile]

    @classmethod
    def from_dict(cls, raw_data: dict[str, Any]) -> "Benchmark":
        """Create Benchmark object from a dictionary."""
        logger.debug(f"Creating Benchmark object from {raw_data}")
        try:
            # TODO this needs to be replaced, making profiles first order structures
            profiles = {
                profile_id: raw_data["profiles"][profile_id].get("legacy_id", None)
                for profile_id in raw_data["profiles"]
            }
            data_files = {
                data_file_type: DataFile(
                    data_file_type,
                    Path(raw_data["data_files"][data_file_type]["path"]),
                    raw_data["data_files"][data_file_type]["sha256"],
                    raw_data["data_files"][data_file_type]["sha256_orig"]
                )
                for data_file_type in raw_data["data_files"]
            }
            return cls(
                id=raw_data["benchmark_id"],
                channel_id=raw_data["channel_id"],
                benchmark_type=raw_data["benchmark_type"],
                product=raw_data["product"],
                product_long=raw_data["product_long"],
                version=raw_data["version"],
                tailoring_version=raw_data["tailoring_version"],
                description=raw_data["description"],
                release_notes_url=raw_data["release_notes_url"],
                release_timestamp=raw_data["release_timestamp"],
                reference_url=raw_data["reference_url"],
                compatible_versions=raw_data["compatible_versions"],
                breaking_upgrade_path=raw_data["breaking_upgrade_path"],
                is_latest=raw_data["is_latest"],
                tailoring_files=raw_data["tailoring_files"],
                profiles=profiles,
                data_files=data_files,
            )
        except (KeyError, ValueError, TypeError) as e:
            raise BenchmarkError(
                f"Failed to create Benchmark object from {raw_data}: {e}"
            ) from e

    def get_tailoring_file_relative_path(self, profile_id: str) -> Path:
        """Return relative tailoring file path by profile id.

        Args:
            profile_id: profile id (e.g. cis_level1_server)

        Returns:
            relative path to tailoring file

        Raises:
            ProfileNotFoundError: if the profile id is not found in the benchmark

        """
        logger.debug(f"Getting tailoring file relative path for profile {profile_id}")
        try:
            path = Path(self.tailoring_files[profile_id]["path"])
            logger.debug(f"Tailoring file relative path: {path}")
            return path
        except KeyError as e:
            raise ProfileNotFoundError(
                f"Profile {profile_id} not found in benchmark {self.id}"
            ) from e


@dataclass
class Profile:
    """Representation of a Benchmark profile."""

    id: str
    legacy_ids: list[str]
    cac_id: str
    benchmark: Benchmark
    latest_compatible_id: str | None
    tailoring_file: Path | str | None
    latest_breaking_id: str | None
    extends_id: str | None



class Benchmarks(dict[str, Benchmark]):
    """Collection of benchmarks in form of a dictionary.

    Keys are benchmark IDs and values are Benchmark objects.
    """

    version: int

    @classmethod
    def from_json(cls, json_path: str | Path) -> "Benchmarks":
        """Create a Benchmarks object from a JSON file.

        Args:
            json_path: path to JSON file containing benchmark metadata

        Returns:
            Benchmarks

        Raises:
            BenchmarkError: if the JSON file is invalid or the contents are invalid

        """
        logger.debug(f"Loading benchmark metadata file{json_path}")
        try:
            with Path(json_path).open() as f:
                json_data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            raise BenchmarkError(f"Failed to parse '{json_path}':{e}") from e

        for key in ["benchmarks", "version"]:
            if key not in json_data:
                raise BenchmarkError(
                    f"Invalid '{json_path}' contents. Could not find key '{key}'"
                )

        # load benchmark and profile data
        benchmarks = {}
        for benchmark_data in json_data["benchmarks"]:
            benchmark_id = benchmark_data["channel_id"]
            if benchmark_id in benchmarks:
                raise BenchmarkError(
                    f"Malformed dataset - duplicate benchmark ID: {benchmark_id}"
                )
            benchmark = Benchmark.from_dict(benchmark_data)
            benchmarks[benchmark_id] = Benchmark.from_dict(benchmark_data)
            # TODO: these should exist in benchmarks.json, with a field "superseded"
            for compatible_version in benchmark.compatible_versions:
                comp_id = f"{benchmark.channel_id}-{compatible_version}"
                comp_data = deepcopy(benchmark_data)
                comp_data.update({
                    "benchmark_id": comp_id,
                    "version": compatible_version
                })
                benchmarks[comp_id] = Benchmark.from_dict(comp_data)


        obj = cls(benchmarks)
        obj.version = json_data["version"]
        logger.debug(f"Loaded {len(obj)} benchmarks. Version={obj.version}")
        return obj


@dataclass(frozen=True)
class TailoringFile:
    """Immutable representation of a tailoring file."""

    tailoring_file: Path
    profile: Profile

    @classmethod
    def from_file(
        cls, usg: Any, tailoring_file: Path | str
        ) -> "TailoringFile":
        """Create a TailoringFile object from a tailoring file.

        Args:
            usg: usg object containing profiles
            tailoring_file: path to tailoring file

        Returns:
            TailoringFile

        Raises:
            TailoringFileError: parsing issues

        """
        tailoring_file = Path(tailoring_file).resolve()
        logger.debug(f"Parsing tailoring file {tailoring_file}")

        if not tailoring_file.is_file():
            raise TailoringFileError(
                f"Tailoring file '{tailoring_file}' must exist and be a regular file"
            )

        tailoring_file_contents = tailoring_file.read_text()

        if re.search(r"<Tailoring\s", tailoring_file_contents):
            logger.debug("Found SCAP tailoring file.")
            channel_id, tailoring_profile_id, base_profile_cac_id = cls._parse_tailoring_scap(
                tailoring_file_contents
            )
        else:
            raise TailoringFileError("Unknown type of tailoring file.")

        logger.debug(
            f"Parsed tailoring file: {channel_id}, "
            f"{tailoring_profile_id}, {base_profile_cac_id}"
            )

        try:
            benchmark = usg.get_benchmark_by_id(channel_id)
        except KeyError:
            raise TailoringFileError(
                f"Invalid tailoring file. Tailoring '{channel_id}' "
                f"which doesn't exist in available benchmark data."
            ) from None

        # map channel_id and profile_id to internal usg profile
        profiles_in_channel = [
            p for p in usg.profiles.values()  \
                if (p.benchmark.channel_id == channel_id and p.latest_compatible_id is None)
            ]
        if not profiles_in_channel:
            raise TailoringFileError(
                f"Invalid tailoring file. Benchmark channel ID '{channel_id}' "
                f"does not exist in available benchmark data."
            ) from None

        profiles_matching_base_cac_id = [
            p for p in profiles_in_channel \
                if p.cac_id == base_profile_cac_id
        ]
        try:
            base_profile_id = profiles_matching_base_cac_id[0]
        except IndexError:
            raise TailoringFileError(
                f"Invalid tailoring file. Extended profile '{base_profile_cac_id}' "
                f"doesn't exist in benchmark channel '{channel_id}'."
            ) from None

        return cls(
            tailoring_file,
            Profile(
                id=tailoring_profile_id,
                cac_id=base_profile_cac_id,
                legacy_ids=[],
                benchmark=benchmark,
                latest_compatible_id=None,
                latest_breaking_id=None,
                tailoring_file=tailoring_file,
                extends_id=base_profile_id
                )
            )

    @classmethod
    def _map_benchmark_id_from_legacy(cls, benchmark_href: str, profile_id: str) -> str:
        """Map benchmark id from legacy href attribute and profile id.

        Maps the legacy href to the new ID scheme (e.g. ubuntu2404_CIS_1)
        by extracting the tailoring_file version and the
        product name from the href itself.
        The benchmark type can be inferred from the profile.

        Args:
            benchmark_href: legacy href attribute from tailoring file
            (/usr/share/ubuntu-scap-security-guide/N/benchmarks/ssg-ubuntuXXXX.xccdf.xml)
            profile_id: profile id attribute from tailoring file

        Returns:
            (benchmark_id, profile_id)

        Raises:
            TailoringFileError: parsing issues

        """
        logger.debug(
                f"Extracting benchmark_id from legacy href "
                f"{benchmark_href} and profile {profile_id}"
                )
        # example match: (1, 'ubuntu2404')
        legacy_fields = re.search(
            r"/(\d)/benchmarks/ssg-(\w+)-xccdf.xml", benchmark_href
        )
        if legacy_fields is None:
            raise TailoringFileError(
                "Could not find a valid benchmark reference in tailoring file"
            )

        tailoring_version = legacy_fields.group(1)
        product = legacy_fields.group(2)

        if "profile_cis_" in profile_id:
            benchmark_type = "CIS"
        elif "profile_stig_" in profile_id:
            benchmark_type = "STIG"
        else:
            raise TailoringFileError(
                f"Cannot infer benchmark type from profile {profile_id}"
            )

        benchmark_id = f"{product}_{benchmark_type}_{tailoring_version}"
        logger.debug(
            f"Extracted benchmark id from legacy tailoring file: {benchmark_id}"
        )
        return benchmark_id

    @classmethod
    def _parse_tailoring_scap(cls, tailoring_file_contents: str) -> tuple[str, str, str]:
        """Parse scap tailoring file contents and returns benchmark and profile IDs.

        Args:
            tailoring_file_contents: string contents of tailoring file

        Returns:
            (benchmark_id, tailoring_profile_id, base_profile_name)

        Raises:
            TailoringFileError: parsing issues

        """
        logger.debug("Parsing SCAP tailoring file")
        try:
            xml_root = ET.fromstring(tailoring_file_contents)  # noqa: S314
        except ET.ParseError as e:
            raise TailoringFileError(
                "XML parser failed to parse the tailoring file"
            ) from e
        if not xml_root.tag.endswith("Tailoring"):
            raise TailoringFileError(
                "Root element of tailoring file is not 'Tailoring'"
            )

        # get profile id
        profiles = xml_root.findall("{*}Profile")
        if not profiles:
            raise TailoringFileError("Tailoring file doesn't contain a profile")
        if len(profiles) > 1:
            raise TailoringFileError(
                "Multiple profiles in tailoring file are not supported."
            )
        profile_id = profiles[0].get("id")
        if profile_id is None:
            raise TailoringFileError("Malformed tailoring file - no profile id")
        logger.debug(f"Found profile {profile_id}")

        base_profile_id = profiles[0].get("extends")
        if base_profile_id is None:
            raise TailoringFileError(
                "Malformed tailoring file - profile does not extend a base profile."
                )
        logger.debug(f"Found base profile name {base_profile_id}")

        # get benchmark id
        benchmark = xml_root.find("{*}benchmark")
        if benchmark is None:
            raise TailoringFileError(
                "Tailoring file is missing the 'benchmark' element"
            )

        benchmark_href = benchmark.get("href")
        if benchmark_href is None:
            raise TailoringFileError(
                "Missing benchmark.href attribute in tailoring file"
            )
        logger.debug(f"Found benchmark element with href={benchmark_href}.")

        if "/usr/share/usg-benchmarks" in benchmark_href:
            # new href (e.g. /usr/share/usg-benchmarks/ubuntu2404_CIS_1,
            # benchmark_id is equal to ubuntu2404_CIS_1)
            benchmark_id = Path(benchmark_href).name
        elif "/usr/share/ubuntu-scap-security-guide" in benchmark_href:
            # legacy href (e.v. /usr/share/ubuntu-scap-security-guide/...)
            logger.warning("Using legacy tailoring file.")
            benchmark_id = cls._map_benchmark_id_from_legacy(
                    benchmark_href, profile_id
                    )
        else:
            raise TailoringFileError(
                f"Unrecognized benchmark.href in tailoring file: '{benchmark_href}'"
            )

        # remove xccdf prefixes
        profile_id = profile_id.replace("xccdf_org.ssgproject.content_profile_", "")
        base_profile_id = base_profile_id.replace("xccdf_org.ssgproject.content_profile_", "")
        return benchmark_id, profile_id, base_profile_id
