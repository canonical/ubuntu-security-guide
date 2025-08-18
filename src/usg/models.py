"""
Classes storing metadata
"""

from __future__ import annotations
import json
import os
import logging
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from usg.exceptions import (
    ProfileNotFoundError,
    BenchmarkError,
    TailoringFileError
    )

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Profile(object):
    """
    Immutable representation of a single profile entry in benchmarks.json or in tailoring file
    """
    profile_id: str
    profile_legacy_id: str
    benchmark_id: str
    tailoring_file: Path | str | None


@dataclass(frozen=True)
class DataFile:
    """
    Immutable representation of a single data file entry in benchmarks.json
    """
    type: str
    rel_path: Path
    sha256: str


class Backend(str, Enum):
    OPENSCAP = "openscap"


class BenchmarkType(str, Enum):
    CIS = "CIS"
    STIG = "STIG"


@dataclass(frozen=True)
class Benchmark(object):
    """
    Immutable representation of a single benchmark entry in benchmarks.json
    """
    id: str
    backend: Backend
    benchmark_type: BenchmarkType
    product: str
    product_long: str
    version: str
    description: str
    release_notes_url: str
    reference_url: str
    compatible_versions: tuple[str, ...]
    breaking_upgrade_path: tuple[str, ...]
    is_latest: bool
    tailoring_files: Mapping[str, dict[str, str]]
    profiles: Mapping[str, Profile]
    data_files: Mapping[str, DataFile]


    @classmethod
    def from_dict(cls, raw_data: dict[str, Any]) -> Benchmark:
        """
        Factory method for creating a Benchmark object from a dictionary
        """
        logger.debug(f"Creating Benchmark object from {raw_data}")
        try:
            profiles = {
                profile_id: Profile(
                    profile_id=profile_id,
                    profile_legacy_id=raw_data["profiles"][profile_id].get("legacy_id", profile_id),
                    benchmark_id=raw_data["benchmark_id"],
                    tailoring_file=None)
                for profile_id in raw_data["profiles"]
            }
            data_files = {
                data_file_type: DataFile(
                    data_file_type,
                    Path(raw_data["data_files"][data_file_type]["path"]),
                    raw_data["data_files"][data_file_type]["sha256"]
                    )
                for data_file_type in raw_data["data_files"].keys()
            }
            return cls(
                id=raw_data["benchmark_id"],
                backend=raw_data["backend"],
                benchmark_type=raw_data["benchmark_type"],
                product=raw_data["product"],
                product_long=raw_data["product_long"],
                version=raw_data["version"],
                description=raw_data["description"],
                release_notes_url=raw_data["release_notes_url"],
                reference_url=raw_data["reference_url"],
                compatible_versions=raw_data["compatible_versions"],
                breaking_upgrade_path=raw_data["breaking_upgrade_path"],
                is_latest=raw_data["is_latest"],
                tailoring_files=raw_data["tailoring_files"],
                profiles=profiles,
                data_files=data_files
            )
        except (KeyError, ValueError, TypeError) as e:
            raise BenchmarkError(
                f"Failed to create Benchmark object from {raw_data}: {e}"
                ) from e

    def get_tailoring_file_relative_path(self, profile_id: str) -> Path:
        """
        Returns relative tailoring file path by profile id

        Args:
            profile_id: profile id (e.g. cis_level1_server)

        Returns:
            relative path to tailoring file

        Raises:
            ProfileNotFoundError: if the profile id is not found in the benchmark
        """
        logger.debug(f"Getting tailoring file relative path for profile {profile_id}")
        try:
            path = Path(self.tailoring_files[profile_id]["file"])
            logger.debug(f"Tailoring file relative path: {path}")
            return path
        except KeyError as e:
            raise ProfileNotFoundError(
                f"Profile {profile_id} not found in benchmark {self.id}"
            ) from e


class Benchmarks(dict[str, Benchmark]):
    """
    Immutable representation of a collection of benchmarks
    """
    version: int

    @classmethod
    def from_json(cls, json_path: str | Path) -> Benchmarks:
        """
        Factory method for creating a Benchmarks object from a JSON file

        Args:
            json_path: path to JSON file containing benchmark metadata
        Returns:
            Benchmarks
        Raises:
            BenchmarkError: if the JSON file is invalid or the contents are invalid
        """
        logger.debug(
            f"Loading benchmark metadata file"
            f"{json_path}"
            )
        try:
            with open(json_path, "r") as f:
                json_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise BenchmarkError(
                f"Failed to parse '{json_path}':"
                f"{e}"
            ) from e

        for key in ["benchmarks", "version"]:
            if key not in json_data:
                raise BenchmarkError(
                    f"Invalid '{json_path}' contents. "
                    f"Could not find key '{key}'"
                    )

        # load benchmark and profile data
        benchmarks = {}
        for benchmark_data in json_data["benchmarks"]:
            benchmark_id = benchmark_data["benchmark_id"]
            if benchmark_id in benchmarks:
                raise BenchmarkError(
                        f"Malformed dataset - duplicate benchmark ID: "
                        f"{benchmark_id}"
                        )
            benchmarks[benchmark_id] = Benchmark.from_dict(benchmark_data)
        obj = cls(benchmarks)
        obj.version = json_data["version"]
        logger.debug(f"Loaded {len(obj)} benchmarks. Version={obj.version}")
        return obj


@dataclass(frozen=True)
class TailoringFile(object):
    """
    Class containing tailoring file metadata (path, profile object, ...)
    """
    tailoring_file: Path
    profile: Profile
    benchmark_id: str

    @classmethod
    def from_file(
            cls,
            tailoring_file: Path | str
            ) -> TailoringFile:
        """
        Factory method for creating a TailoringFile object from a tailoring file

        Args:
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
                f"Tailoring file '{tailoring_file}' must "
                f"exist and be a regular file"
            )

        tailoring_file_contents = tailoring_file.read_text()

        if re.search(r"<Tailoring\s", tailoring_file_contents):
            logger.debug("Found SCAP tailoring file.")
            benchmark_id, profile_id = cls._parse_tailoring_scap(
                tailoring_file_contents
            )
        else:
            raise TailoringFileError("Unknown type of tailoring file.")

        logger.debug(f"Parsed tailoring file: {benchmark_id}, {profile_id}")
        return cls(
                tailoring_file,
                Profile(profile_id, profile_id, benchmark_id, tailoring_file),
                benchmark_id,
                )

    @classmethod
    def _parse_tailoring_scap(cls, tailoring_file_contents: str):
        """
        Parses scap tailoring file contents and returns benchmark and profile IDs

        Args:
            tailoring_file: path to tailoring file
        Returns:
            (benchmark_id, profile_id)
        Raises:
            TailoringFileError: parsing issues
        """

        logger.debug("Parsing SCAP tailoring file")
        try:
            xml_root = ET.fromstring(tailoring_file_contents)
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
                    "Mutliple profiles in tailoring file are not supported."
                    )
        profile_id = profiles[0].get("id")
        if profile_id is None:
            raise TailoringFileError("Malformed tailoring file - no profile id")
        logger.debug(f"Found profile {profile_id}")

        # get benchmark id
        benchmark = xml_root.find("{*}benchmark")
        if benchmark is None:
            raise TailoringFileError(
                    "Tailoring file is missing the 'benchmark' element"
                    )

        benchmark_href = benchmark.get("href")
        if benchmark_href is None:
            raise TailoringFileError(
                "Could not find a valid benchmark "
                "reference in tailoring file"
            )
        else:
            logger.debug(f"Found benchmark element with href={benchmark_href}.")



        if "/usr/share/usg-benchmarks" in benchmark_href:
            # new href (e.g. /usr/share/usg-benchmarks/ubuntu2404_CIS_1
            # benchmark_id = ubuntu2404_CIS_1
            benchmark_id = Path(benchmark_href).name
        else:
            # Legacy tailoring files (href contains path
            # to correct folder/datastream)
            #
            # We can map to the new ID scheme (e.g. ubuntu2404_CIS_1)
            # by extracting the tailoring_file version and the
            # product name from the href itself.
            # The benchmark type can be inferred from the profile.

            logger.warning("Using legacy tailoring file.")

            # example match: (1, 'ubuntu2404')
            legacy_fields = re.search(
                    r'/(\d)/benchmarks/ssg-(\w+)-xccdf.xml',
                    benchmark_href
                    )
            if legacy_fields is None:
                raise TailoringFileError(
                    "Could not find a valid benchmark "
                    "reference in tailoring file"
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

            benchmark_id = (
                f"{product}_"
                f"{benchmark_type}_"
                f"{tailoring_version}"
            )
            logger.debug(
                f"Extracted benchmark id from legacy "
                f"tailoring file: {benchmark_id}"
            )

        return benchmark_id, profile_id

    def __repr__(self):
        return (
                f"{self.__class__.__name__}"
                f"(tailoring_file='{self.tailoring_file}')"
                )

