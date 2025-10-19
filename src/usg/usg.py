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

"""Core logic for USG."""

import configparser
import datetime
import logging
import os
import shutil
import tempfile
from pathlib import Path

from usg import config as usg_config
from usg import constants
from usg.backends import BackendError, OpenscapBackend
from usg.exceptions import (
    FileMoveError,
    MissingFileError,
    ProfileNotFoundError,
    USGError,
)
from usg.models import Benchmark, Metadata, Profile, TailoringFile
from usg.results import AuditResults, BackendArtifacts
from usg.utils import check_perms, gunzip_file, verify_integrity

logger = logging.getLogger(__name__)


class USG:
    """Main class implementing the core logic for USG.

    Responsibilities include:
    - Managing the loading, storage, and retrieval of benchmark metadata
    - Performing operations related to tailoring files
    - Initializing backends and handling extraction of required data files
    - Providing methods for auditing, remediation, and tailoring file creation

    Args:
        benchmark_metadata_path: (optional) path to json metadata file. Defaults
                                 to constants.BENCHMARK_METADATA_PATH.
        state_dir: (optional) path to state dir. Defaults to constants.STATE_DIR.
        config: (optional) A ConfigParser instance to override backend settings.
                If not provided, defaults from config.py are used.

    """

    def __init__(
        self,
        benchmark_metadata_path: Path | None = None,
        state_dir: Path | None = None,
        config: configparser.ConfigParser | None = None,
    ) -> None:
        """Initialize USG with optional config."""
        # load default config if none given
        if config is None:
            self._config = usg_config.load_config(constants.CONFIG_PATH)
        else:
            self._config = config

        if benchmark_metadata_path is None:
            self._benchmark_metadata_path = constants.BENCHMARK_METADATA_PATH
        else:
            self._benchmark_metadata_path = Path(benchmark_metadata_path).resolve()

        if state_dir is None:
            self._state_dir = constants.STATE_DIR
        else:
            self._state_dir = Path(state_dir).resolve()

        # ensure new files are created with the correct permissions
        os.umask(0o077)

        # do sanity checks on important files
        try:
            check_perms(self._benchmark_metadata_path)
        except MissingFileError as e:
            msg = (
                f"Could not find benchmark data {self._benchmark_metadata_path}. "
                f"Please ensure the {constants.BENCHMARK_PKG} package is installed."
            )
            raise USGError(msg) from e

        check_perms(self._state_dir, is_dir=True)

        self._metadata = Metadata.from_json(self._benchmark_metadata_path)
        self._timestamp = datetime.datetime.now().strftime("%Y%m%d.%H%M")  # noqa: DTZ005


    @property
    def profiles(self) -> dict[str, Profile]:
        """Getter for benchmarks."""
        return self._metadata.profiles


    def get_profile(self, profile_id: str) -> Profile:
        """Return benchmark profile based on the given criteria.

        Args:
            profile_id: benchmark profile id (e.g. cis_level1_server_v1.0.0) 
                        or alias (e.g. disa_stig)

        Returns:
            Profile object

        Raises:
            ProfileNotFoundError: when profile is not found

        """
        logger.debug(f"Getting profile: {profile_id}.")
        if profile_id in self.profiles:
            return self.profiles[profile_id]

        matching = [p for p in self.profiles.values() if profile_id in p.alias_ids]
        try:
            return matching[0]
        except IndexError:
            raise ProfileNotFoundError(
                f"Could not find benchmark profile '{profile_id}'."
            ) from None


    def load_tailoring(
        self,
        tailoring_file_path: Path,
    ) -> TailoringFile:
        """Parse tailoring file and return tailoring file object.

        Args:
            tailoring_file_path: path to tailoring file

        Raises:
            USGError: permission issues or failure to parse

        Returns:
            TailoringFile

        """
        logger.debug(f"Loading {tailoring_file_path}")
        check_perms(tailoring_file_path)

        # parse tailoring file
        channel_id, tailoring_profile_id, base_profile_id = \
            TailoringFile.parse_tailoring_file(tailoring_file_path)

        # map channel_id and profile_id to internal usg profile
        profiles_in_channel = [
            p for p in list(self.profiles.values())  \
                if (p.benchmark.channel.id == channel_id and p.latest_compatible_id is None)
            ]
        if not profiles_in_channel:
            raise USGError(
                f"Invalid tailoring file. Benchmark channel ID '{channel_id}' "
                f"does not exist in available benchmark data."
            ) from None

        profiles_matching_base_cac_id = [
            p for p in profiles_in_channel \
                if p.cac_id == base_profile_id
        ]
        try:
            base_profile = profiles_matching_base_cac_id[0]
        except IndexError:
            raise USGError(
                f"Invalid tailoring file. Extended profile '{base_profile_id}' "
                f"doesn't exist in benchmark channel '{channel_id}'."
            ) from None

        return TailoringFile(
            tailoring_file=tailoring_file_path,
            profile=Profile(
                id=tailoring_profile_id,
                cac_id=tailoring_profile_id,
                alias_ids=[],
                benchmark=base_profile.benchmark,
                latest_compatible_id=None,
                latest_breaking_id=None,
                tailoring_file=tailoring_file_path,
                extends_id=base_profile.id
                )
            )


    def _init_openscap_backend(
        self,
        benchmark: Benchmark,
        work_dir: Path | str,
    ) -> OpenscapBackend:
        # initializes and returns the backend object
        work_dir = Path(work_dir).resolve()
        logger.debug(f"Initializing Openscap backend for {benchmark.id}")
        logger.debug(f"Working directory: {work_dir}")

        ds_gz_file = benchmark.channel.data_files["datastream_gz"]
        ds_gz_path = self._benchmark_metadata_path.parent / ds_gz_file.rel_path

        check_perms(ds_gz_path)

        verify_integrity(ds_gz_path, ds_gz_file.sha256, "sha256")

        ds_path = work_dir / ds_gz_path.with_suffix("").name
        ds_path.parent.mkdir(parents=True, exist_ok=True)
        gunzip_file(ds_gz_path, ds_path)

        verify_integrity(ds_path, ds_gz_file.sha256_orig, "sha256")

        backend = OpenscapBackend(
            ds_path,
            constants.OPENSCAP_BIN_PATH,
            work_dir,
        )
        logger.debug(f"Initialized OpenscapBackend for {benchmark.id}")

        return backend

    def generate_tailoring(self, profile: Profile) -> str:
        """Generate tailoring file contents.

        Args:
            profile: Profile object

        Returns:
            string representation of tailoring file

        """
        logger.info(f"Generating tailoring file for profile {profile.id}")
        tailoring_rel_path = profile.benchmark.get_tailoring_file_relative_path(
            profile.cac_id
        )
        tailoring_abs_path = (
            self._benchmark_metadata_path.parent / tailoring_rel_path
        )
        logger.info(f"Tailoring file generated at {tailoring_abs_path}")

        return tailoring_abs_path.read_text()


    def _move_artifacts(
        self, artifacts: BackendArtifacts, profile_cac_id: str, product: str
    ) -> None:
        # Move artifacts to the final destination path
        # as resolved by get_artifact_destination_path()

        timestamp = datetime.datetime.now().strftime("%Y%m%d.%H%M")  # noqa: DTZ005
        try:
            for artifact in artifacts:
                artifact_path = usg_config.get_artifact_destination_path(
                    self._config, artifact.kind, timestamp, profile_cac_id, product
                )
                artifact.move(artifact_path)
        except FileMoveError as e:
            raise USGError(f"Error moving files: {e}") from e

    def generate_fix(self, profile: Profile) -> BackendArtifacts:
        """Generate a fix script.

        Args:
            profile: Profile object

        Returns:
            BackendArtifacts: output files from the generate_fix operation

        Raises:
            USGError: if the backend operation fails

        """
        logger.info(f"Generating fix script for profile {profile.id}")

        work_dir = tempfile.mkdtemp(dir=self._state_dir, prefix="generate-fix_")
        backend = self._init_openscap_backend(profile.benchmark, work_dir)
        try:
            artifacts = backend.generate_fix(
                profile.cac_id,
                profile.tailoring_file,
            )
        except BackendError as e:
            logger.error(
                    f"Failed to generate the fix script. "
                    f"Storing partial outputs in {work_dir}."
                    )
            raise USGError(f"Failed to run backend operation: {e}") from e
        except (KeyboardInterrupt, Exception) as e:
            logger.error(
                    f"Failed to generate the fix script. "
                    f"Storing partial outputs in {work_dir}."
                    )
            raise e

        self._move_artifacts(artifacts, profile.cac_id,  profile.benchmark.product)

        logger.debug(f"Removing temporary directory {work_dir}")
        shutil.rmtree(work_dir)

        logger.info("Fix script generated.")
        for file in artifacts:
            logger.info(f"'{file.kind}' file written to {file.path}")

        return artifacts

    def fix(
            self,
            profile: Profile,
            audit_results_file: Path | None = None
            ) -> BackendArtifacts:
        """Prepare environment and backend and remediates profile.

        Args:
            profile: Profile object
            audit_results_file: if given, only remediate failed rules in the audit

        Returns:
            BackendArtifacts: output files from the fix operation

        Raises:
            USGError: if the backend operation fails

        """
        logger.info(f"Remediating profile {profile.id}")

        work_dir = tempfile.mkdtemp(dir=self._state_dir, prefix="fix_")
        backend = self._init_openscap_backend(profile.benchmark, work_dir)
        try:
            # pass audit results to fix operation to only remediated failed rules
            if audit_results_file is not None:
                logger.info(
                    f"Only remediating failed rules from audit results file "
                    f"{audit_results_file.name}"
                )
            else:
                audit_results_file = None
                logger.info("Remediating all rules")

            artifacts = backend.fix(
                profile.cac_id,
                profile.tailoring_file,
                audit_results_file=audit_results_file,
            )
        except BackendError as e:
            logger.error(
                    f"Failed to remediate the system. "
                    f"Storing partial outputs in {work_dir}."
                    )
            raise USGError(f"Failed to run backend operation: {e}") from e
        except (KeyboardInterrupt, Exception) as e:
            logger.error(
                    f"Failed to remediate the system. "
                    f"Storing partial outputs in {work_dir}."
                    )
            raise e

        self._move_artifacts(artifacts, profile.cac_id, profile.benchmark.product)

        logger.debug(f"Removing temporary directory {work_dir}")
        shutil.rmtree(work_dir)

        logger.info("Remediation finished.")
        for file in artifacts:
            logger.info(f"File '{file.kind}' written to {file.path}")
        return artifacts

    def audit(
        self,
        profile: Profile,
        debug: bool = False,
        oval_results: bool = False,
    ) -> tuple[AuditResults, BackendArtifacts]:
        """Prepare environment and backend and audits a profile.

        Args:
            profile: Profile object
            report_filename: filename for report file (defaults to value in config file)
            results_filename: filename for results file (defaults to value in config)
            log_filename: filename for log file (defaults to value in config file)
            debug: if True, run in debug mode
            oval_results: if True, include oval results in the audit

        Returns:
            tuple[AuditResults, BackendArtifacts]: audit results and output files

        Raises:
            USGError: if the backend operation fails

        """
        logger.info(f"Auditing profile {profile.id}")

        work_dir = tempfile.mkdtemp(dir=self._state_dir, prefix="audit_")
        backend = self._init_openscap_backend(profile.benchmark, work_dir)
        try:
            results, artifacts = backend.audit(
                profile.cac_id,
                tailoring_file=profile.tailoring_file,
                debug=debug,
                oval_results=oval_results,
            )
        except BackendError as e:
            logger.error(
                    f"Failed to audit the system. "
                    f"Storing partial outputs in {work_dir}."
                    )
            raise USGError(f"Failed to run backend operation: {e}") from e
        except (KeyboardInterrupt, Exception) as e:
            logger.error(
                    f"Failed to audit the system. "
                    f"Storing partial outputs in {work_dir}."
                    )
            raise e

        self._move_artifacts(artifacts, profile.cac_id, profile.benchmark.product)

        logger.debug(f"Removing temporary directory {work_dir}")
        shutil.rmtree(work_dir)

        logger.info("Audit completed.")
        summary = ", ".join(results.get_summary().split("\n"))
        logger.info(f"Results summary: {summary}")
        for file in artifacts:
            logger.info(f"'{file.kind}' file written to {file.path}")

        return results, artifacts
