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

from usg.exceptions import MetadataError, ProfileNotFoundError, TailoringFileError

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
class ReleaseChannel:
    """Immutable representation of a benchmark release channel."""

    id: str
    benchmark_ids: list[str]
    channel_number: int
    is_latest: bool
    release_tag: str
    release_commit: str
    release_notes_url: str
    release_timestamp: int
    data_files: dict[str, DataFile]
    tailoring_files: dict[str, dict[str, str]]

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> "ReleaseChannel":
        """Create ReleaseChannel object from dictionary data."""
        logger.debug(f"Creating ReleaseChannel object from {data}")
        try:
            data_files = {
                data_file_type: DataFile(
                    data_file_type,
                    Path(data["data_files"][data_file_type]["path"]),
                    data["data_files"][data_file_type]["sha256"],
                    data["data_files"][data_file_type]["sha256_orig"]
                )
                for data_file_type in data["data_files"]
            }
            return cls(
                id=data["id"],
                benchmark_ids=data["benchmark_ids"],
                channel_number=data["channel_number"],
                is_latest=data["is_latest"],
                release_tag=data["release_tag"],
                release_commit=data["release_commit"],
                release_notes_url=data["release_notes_url"],
                release_timestamp=data["release_timestamp"],
                data_files=data_files,
                tailoring_files=data["tailoring_files"],
            )
        except (KeyError, ValueError, TypeError) as e:
            raise MetadataError(
                f"Failed to create ReleaseChannel object: {e}"
            ) from e


    def get_tailoring_file_relative_path(self, cac_profile_id: str) -> Path:
        """Return relative tailoring file path by profile id.

        Args:
            cac_profile_id: CaC profile id (e.g. cis_level1_server)

        Returns:
            relative path to tailoring file

        Raises:
            ProfileNotFoundError: if the profile id is not found in the benchmark
                                  release channel

        """
        logger.debug(f"Getting tailoring file relative path for profile {cac_profile_id}")
        try:
            path = Path(self.tailoring_files[cac_profile_id]["path"])
            logger.debug(f"Tailoring file relative path: {path}")
            return path
        except KeyError as e:
            raise ProfileNotFoundError(
                f"Profile {cac_profile_id} not found in channel {self.id}"
            ) from e


@dataclass(frozen=True)
class Benchmark:
    """Immutable representation of a benchmark entry in benchmarks.json."""

    id: str
    benchmark_type: BenchmarkType
    product: str
    product_long: str
    channel: ReleaseChannel
    channel_number: int
    version: str
    profiles: dict[str, dict]
    description: str
    reference_url: str
    latest_compatible_id: str | None
    latest_breaking_id: str | None
    state: str

    @classmethod
    def from_dict(cls, channel: ReleaseChannel, data: dict[str, Any]) -> "Benchmark":
        """Create Benchmark object from dictionary data and channel object."""
        logger.debug(f"Creating Benchmark object from {data} and {channel}")
        try:
            return cls(
                id=data["id"],
                benchmark_type=data["benchmark_type"],
                product=data["product"],
                product_long=data["product_long"],
                channel=channel,
                channel_number=data["channel_number"],
                version=data["version"],
                profiles=data["profiles"],
                description=data["description"],
                reference_url=data["reference_url"],
                latest_compatible_id=data["latest_compatible_id"],
                latest_breaking_id=data["latest_breaking_id"],
                state=data["state"],
            )
        except (KeyError, ValueError, TypeError) as e:
            raise MetadataError(
                f"Failed to create Benchmark object: {e}"
            ) from e


@dataclass
class Profile:
    """Representation of a Benchmark profile."""

    id: str
    cac_id: str
    alias_ids: list[str]
    benchmark: Benchmark
    latest_compatible_id: str | None
    tailoring_file: Path | str | None
    latest_breaking_id: str | None
    extends_id: str | None

    @classmethod
    def from_data(cls, benchmark: Benchmark, data: dict[str, Any]) -> "Profile":
        """Create Profile object from dictionary data and benchmark object."""
        logger.debug(f"Creating Profile object from {data} and {benchmark}")
        try:
            return cls(
                id = data["id"],
                cac_id = data["cac_id"],
                alias_ids = data["alias_ids"],
                benchmark = benchmark,
                latest_compatible_id = data["latest_compatible_id"],
                latest_breaking_id = data["latest_breaking_id"],
                tailoring_file = None,
                extends_id = None,
            )
        except (KeyError, ValueError, TypeError) as e:
            raise MetadataError(
                f"Failed to create profile object: {e}"
            ) from e


@dataclass
class Metadata:
    """Benchmark metadata (profiles, benchmarks, channels)."""

    version: int
    profiles: dict[str, Any]
    benchmarks: dict[str, Any]
    channels: dict[str, Any]

    @classmethod
    def from_json(cls, json_path: str | Path) -> "Metadata":
        """Parse JSON metadata file and create Metadata object.

        Args:
            json_path: path to JSON file containing profile and benchmark metadata

        Returns:
            Metadata

        Raises:
            MetadataError: if the JSON file is invalid or the contents are invalid

        """
        logger.debug(f"Loading metadata file {json_path}")
        try:
            with Path(json_path).open() as f:
                json_data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            raise MetadataError(f"Failed to parse '{json_path}':{e}") from e

        for key in ["profiles", "benchmarks", "release_channels", "version"]:
            if key not in json_data:
                raise MetadataError(
                    f"Invalid '{json_path}' contents. Could not find key '{key}'"
                )

        # load release_channels data
        release_channels = {}
        for channel_data in json_data["release_channels"]:
            channel_id = channel_data["id"]
            if channel_id in release_channels:
                raise MetadataError(
                    f"Malformed dataset - duplicate channel ID: {channel_id}"
                )
            channel = ReleaseChannel.from_data(channel_data)
            release_channels[channel_id] = channel


        # load benchmark data
        benchmarks = {}
        for benchmark_data in json_data["benchmarks"]:
            benchmark_id = benchmark_data["id"]
            if benchmark_id in benchmarks:
                raise MetadataError(
                    f"Malformed dataset - duplicate benchmark ID: {benchmark_id}"
                )
            channel = release_channels[benchmark_data["channel_id"]]
            benchmark = Benchmark.from_dict(channel, benchmark_data)
            benchmarks[benchmark_id] = benchmark

        # load profile data
        profiles = {}
        for profile_data in json_data["profiles"]:
            profile_id = profile_data["id"]
            if profile_id in profiles:
                raise MetadataError(
                    f"Malformed dataset - duplicate profile ID: {profile_id}"
                )
            profile_data.update({
                "tailoring_file": None,
                "extends_id": None,
            })
            benchmark = benchmarks[profile_data["benchmark_id"]]
            profile = Profile.from_data(benchmark, profile_data)
            profiles[profile_id] = profile

        metadata = cls(
            version=json_data["version"],
            profiles=profiles,
            benchmarks=benchmarks,
            channels=release_channels
            )

        logger.debug(
            f"Loaded {len(profiles)} profiles from {len(benchmarks)} benchmarks. "
            f"Version={metadata.version}"
            )
        return metadata


@dataclass(frozen=True)
class TailoringFile:
    """Immutable representation of a tailoring file."""

    tailoring_file: Path
    profile: Profile

    @staticmethod
    def parse_tailoring_file(tailoring_file: Path | str) -> tuple[str, str, str]:
        """Create a TailoringFile object from a tailoring file.

        Args:
            usg: usg object containing profiles
            tailoring_file: path to tailoring file

        Returns:
            (channel_id, tailoring_profile_id, base_profile_cac_id)

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
            channel_id, tailoring_profile_id, base_profile_cac_id = TailoringFile._parse_tailoring_scap(
                tailoring_file_contents
            )
        else:
            raise TailoringFileError("Unknown type of tailoring file.")

        logger.debug(
            f"Parsed tailoring file: {channel_id}, "
            f"{tailoring_profile_id}, {base_profile_cac_id}"
            )
        return channel_id, tailoring_profile_id, base_profile_cac_id


    @staticmethod
    def _map_benchmark_id_from_legacy(benchmark_href: str, profile_id: str) -> str:
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

        channel_number = legacy_fields.group(1)
        product = legacy_fields.group(2)

        if "profile_cis_" in profile_id:
            benchmark_type = "CIS"
        elif "profile_stig_" in profile_id:
            benchmark_type = "STIG"
        else:
            raise TailoringFileError(
                f"Cannot infer benchmark type from profile {profile_id}"
            )

        benchmark_id = f"{product}_{benchmark_type}_{channel_number}"
        logger.debug(
            f"Extracted benchmark id from legacy tailoring file: {benchmark_id}"
        )
        return benchmark_id

    @staticmethod
    def _parse_tailoring_scap(tailoring_file_contents: str) -> tuple[str, str, str]:
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
            benchmark_id = TailoringFile._map_benchmark_id_from_legacy(
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
