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
from usg.models import Benchmark, Benchmarks, Profile, TailoringFile
from usg.results import AuditResults, BackendArtifacts
from usg.utils import gunzip_file, validate_perms, verify_integrity

logger = logging.getLogger(__name__)


class USG:
    """Main class implementing the core logic for USG.

    Responsibilities include:
    - Managing the loading, storage, and retrieval of benchmark metadata
    - Performing operations related to tailoring files
    - Initializing backends and handling extraction of required data files
    - Providing methods for auditing, remediation, and tailoring file creation

    Args:
        config: (optional) A ConfigParser instance to override backend settings.
                If not provided, defaults from config.py are used.

    """

    def __init__(
        self,
        config: configparser.ConfigParser | None = None,
    ) -> None:
        """Initialize USG with optional config."""
        # load default config if none given
        if config is None:
            self._config = usg_config.load_config(constants.CONFIG_PATH)
        else:
            self._config = config

        # ensure new files are created with the correct permissions
        os.umask(0o077)

        # do sanity checks on important files
        try:
            validate_perms(constants.BENCHMARK_METADATA_PATH)
        except MissingFileError as e:
            msg = (
                f"Could not find benchmark data {constants.BENCHMARK_METADATA_PATH}. "
                f"Please ensure the {constants.BENCHMARK_PKG} package is installed."
            )
            raise USGError(msg) from e
        validate_perms(constants.STATE_DIR, is_dir=True)

        self._benchmarks = Benchmarks.from_json(constants.BENCHMARK_METADATA_PATH)
        self._timestamp = datetime.datetime.now().strftime("%Y%m%d.%H%M")  # noqa: DTZ005

    @property
    def benchmarks(self) -> Benchmarks:
        """Getter for benchmarks."""
        return self._benchmarks

    def get_benchmark_by_id(self, benchmark_id: str) -> Benchmark:
        """Return benchmark object by benchmark id.

        Args:
            benchmark_id: ID of the benchmark to return (e.g. ubuntu2404_CIS_1)

        Returns:
            Benchmark

        Raises:
            KeyError: if the benchmark id is not found

        """
        try:
            return self.benchmarks[benchmark_id]
        except KeyError as e:
            msg = f"Benchmark {benchmark_id} not found"
            raise KeyError(msg) from e

    def get_profile(
        self, profile_id: str, product: str, benchmark_version: str = "latest"
    ) -> Profile:
        """Return benchmark profile based on the given criteria.

        Args:
            profile_id: benchmark profile id (e.g. cis_level1_server)
            product: name of product (e.g. ubuntu2404)
            benchmark_version: version of benchmark (e.g. v1.0.0, v1r2),
                               defaults to "latest"

        Returns:
            profile object matching criteria

        Raises:
            ValueError: when no match is found

        """
        logger.debug(f"Getting profile: {profile_id},{product},{benchmark_version}")

        results = []
        for benchmark in self.benchmarks.values():
            for profile in benchmark.profiles.values():
                logger.debug(f"Checking profile {profile}")

                if (
                    profile_id in [profile.profile_id, profile.profile_legacy_id]
                    and product == benchmark.product
                ):
                    # return latest version by default
                    if benchmark_version == "latest" and benchmark.is_latest:
                        logger.debug(
                            f"Found latest version of {profile_id} for {product}"
                        )
                        results.append(profile)

                    # return specific version if exists
                    if benchmark_version == benchmark.version:
                        logger.debug(
                            f"Found version {benchmark_version} of "
                            f"{profile_id} for {product}"
                        )
                        if not benchmark.is_latest:
                            logger.warning(
                                f"Version {benchmark.version} of the benchmark profile "
                                f"{profile_id} is deprecated."
                            )
                        results.append(profile)

                    # return compatible (non-breaking) version if exists
                    compatible_versions = list(benchmark.compatible_versions)

                    if benchmark_version in compatible_versions:
                        logger.debug(
                            f"Found compatible version {benchmark.version} of "
                            f"{profile_id} for {product}"
                        )
                        logger.info(
                            f"Version {benchmark_version} is superseded by "
                            f"{benchmark.version}. "
                            f" Automatically selecting the latter."
                        )
                        results.append(profile)

        if len(results) == 0:
            raise ProfileNotFoundError(
                f"No profile found matching these criteria: "
                f"profile={profile_id}, product={product}, "
                f"version={benchmark_version}"
            )
        if len(results) > 1:
            raise ProfileNotFoundError(
                f"Multiple benchmark profiles found matching these criteria: "
                f"profile={profile_id}, product={product}, "
                f"version={benchmark_version}"
            )

        return results[0]

    def load_tailoring(
        self,
        tailoring_file_path: Path | str,
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

        validate_perms(tailoring_file_path)

        tailoring = TailoringFile.from_file(tailoring_file_path)

        # check if the benchmark id in the tailoring file
        # exists in the dataset
        benchmark_id = tailoring.profile.benchmark_id
        try:
            benchmark = self.benchmarks[benchmark_id]
        except KeyError as e:
            raise USGError(
                f"Could not find benchmark referenced in tailoring file: {benchmark_id}"
            ) from e
        if not benchmark.is_latest:
            logger.warning(
                f"The version of the benchmark profile found in tailoring file "
                f"({benchmark.version}) is deprecated. "
            )
        return tailoring

    def _init_openscap_backend(
        self,
        benchmark: Benchmark,
        work_dir: Path | str,
    ) -> OpenscapBackend:
        # initializes and returns the backend object
        work_dir = Path(work_dir).resolve()
        logger.debug(f"Initializing Openscap backend for {benchmark.id}")
        logger.debug(f"Working directory: {work_dir}")

        ds_gz_file = benchmark.data_files["datastream_gz"]
        ds_gz_path = constants.BENCHMARK_METADATA_PATH.parent / ds_gz_file.rel_path

        validate_perms(ds_gz_path)

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
        logger.info(f"Generating tailoring file for profile {profile.profile_id}")
        benchmark = self.benchmarks[profile.benchmark_id]
        tailoring_rel_path = benchmark.get_tailoring_file_relative_path(
            profile.profile_id
        )
        tailoring_abs_path = (
            constants.BENCHMARK_METADATA_PATH.parent / tailoring_rel_path
        )
        logger.info(f"Tailoring file generated at {tailoring_abs_path}")

        return tailoring_abs_path.read_text()

    def _move_artifacts(
        self, artifacts: BackendArtifacts, profile_id: str, product: str
    ) -> None:
        # Move artifacts to the final destination path
        # as resolved by get_artifact_destination_path()

        timestamp = datetime.datetime.now().strftime("%Y%m%d.%H%M")  # noqa: DTZ005
        try:
            for artifact in artifacts:
                artifact_path = usg_config.get_artifact_destination_path(
                    self._config, artifact.kind, timestamp, profile_id, product
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
        logger.info(f"Generating fix script for profile {profile.profile_id}")

        benchmark = self.benchmarks[profile.benchmark_id]
        work_dir = tempfile.mkdtemp(dir=constants.STATE_DIR, prefix="generate-fix_")
        backend = self._init_openscap_backend(benchmark, work_dir)
        try:
            artifacts = backend.generate_fix(
                profile.profile_id,
                profile.tailoring_file,
            )
        except BackendError as e:
            logger.error(f"Failed to generate the fix script. Storing partial outputs in {work_dir}.")
            raise USGError(f"Failed to run backend operation: {e}") from e
        except (KeyboardInterrupt, Exception) as e:
            logger.error(f"Failed to generate the fix script. Storing partial outputs in {work_dir}.")
            raise e

        self._move_artifacts(artifacts, profile.profile_id, benchmark.product)

        logger.debug(f"Removing temporary directory {work_dir}")
        shutil.rmtree(work_dir)

        logger.info("Fix script generated.")
        for file in artifacts:
            logger.info(f"'{file.kind}' file written to {file.path}")

        return artifacts

    def fix(self, profile: Profile, only_failed: bool = False) -> BackendArtifacts:
        """Prepare environment and backend and remediates profile.

        Args:
            profile: Profile object
            only_failed: if True, only remediate failed rules

        Returns:
            BackendArtifacts: output files from the fix operation

        Raises:
            USGError: if the backend operation fails

        """
        logger.info(f"Remediating profile {profile.profile_id}")

        benchmark = self.benchmarks[profile.benchmark_id]
        work_dir = tempfile.mkdtemp(dir=constants.STATE_DIR, prefix="fix_")
        backend = self._init_openscap_backend(benchmark, work_dir)
        try:
            results, artifacts = backend.audit(
                profile.profile_id, profile.tailoring_file
            )

            # pass audit results to fix operation to only remediated failed rules
            if only_failed:
                audit_results_file = artifacts.get_by_type("audit_results").path
                logger.info(
                    f"Only remediating failed rules from audit results file "
                    f"{audit_results_file.name}"
                )
            else:
                audit_results_file = None
                logger.info("Remediating all rules")

            artifacts = backend.fix(
                profile.profile_id,
                profile.tailoring_file,
                audit_results_file=audit_results_file,
            )
        except BackendError as e:
            logger.error(f"Failed to remediate the system. Storing partial outputs in {work_dir}.")
            raise USGError(f"Failed to run backend operation: {e}") from e
        except (KeyboardInterrupt, Exception) as e:
            logger.error(f"Failed to remediate the system. Storing partial outputs in {work_dir}.")
            raise e

        self._move_artifacts(artifacts, profile.profile_id, benchmark.product)

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
        logger.info(f"Auditing profile {profile.profile_id}")

        benchmark = self.benchmarks[profile.benchmark_id]
        work_dir = tempfile.mkdtemp(dir=constants.STATE_DIR, prefix="audit_")
        backend = self._init_openscap_backend(benchmark, work_dir)
        try:
            results, artifacts = backend.audit(
                profile.profile_id,
                tailoring_file=profile.tailoring_file,
                debug=debug,
                oval_results=oval_results,
            )
        except BackendError as e:
            logger.error(f"Failed to audit the system. Storing partial outputs in {work_dir}.")
            raise USGError(f"Failed to run backend operation: {e}") from e
        except (KeyboardInterrupt, Exception) as e:
            logger.error(f"Failed to audit the system. Storing partial outputs in {work_dir}.")
            raise e

        self._move_artifacts(artifacts, profile.profile_id, benchmark.product)

        logger.debug(f"Removing temporary directory {work_dir}")
        shutil.rmtree(work_dir)

        logger.info("Audit completed.")
        summary = ", ".join(results.get_summary().split("\n"))
        logger.info(f"Results summary: {summary}")
        for file in artifacts:
            logger.info(f"'{file.kind}' file written to {file.path}")

        return results, artifacts
