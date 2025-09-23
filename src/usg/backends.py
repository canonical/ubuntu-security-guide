"""Auditing and remediation backends for USG (e.g. oscap)."""

import logging
import os
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import ClassVar

from usg.exceptions import BackendCommandError, BackendError, PermValidationError
from usg.results import AuditResults, BackendArtifacts
from usg.utils import validate_perms

logger = logging.getLogger(__name__)


def run_cmd(
    cmd: list[str],
    cwd: Path,
    capture_output: bool = True,
    timeout: float | None = None,
    allowed_return_codes: list[int] | None = None,
    ) -> subprocess.CompletedProcess[str]:
    """Call external command cmd and log and return completed process.

    Args:
        cmd: command list
        cwd: cwd to pass to subprocess.run
        capture_output: passed to subprocess.run
                        (True: capture and return output,
                         False: forward to console)
        timeout: timeout to pass to subprocess.run
        allowed_return_codes: raises BackendCommandError if process returns
                               exitcode that is not in this list (defaults to [0])

    Returns:
        process: completed process

    Raises:
        BackendCommandError: if command is not found or if command returns
                        non-zero return code and raise_on_error==True

    """
    allowed_return_codes = allowed_return_codes or [0]

    cmd = list(map(str, cmd))
    cmd_str = " ".join(cmd)
    logger.info(f"Calling command '{cmd_str}'")
    logger.debug(
        f"CWD: {cwd}, timeout: {timeout}, "
        f"capture_output: {capture_output}"
        )
    try:
        process = subprocess.run(  # noqa: S603
            cmd,
            cwd=cwd,
            timeout=timeout,
            capture_output=capture_output,
            check=False,
            encoding="utf-8",
            errors="replace",
            text=True,
            )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise BackendCommandError(
            f"Failed to execute command {cmd_str}: {e}"
            ) from e

    logger.debug(f"Return code: {process.returncode}")
    if capture_output:
        logger.debug(f"Command stdout: {process.stdout}")
        logger.debug(f"Command stderr: {process.stderr}")
    else:
        logger.debug("Command stdout and stderr are streamed to console.")

    if process.returncode not in allowed_return_codes:
        raise BackendCommandError(
            f"Backend command '{cmd_str}' exited with return code "
            f"{process.returncode}"
            )
    logger.info("Command finished successfully.")
    return process


class OpenscapBackend:
    """Wrapper for auditing and remediating a system with the openscap engine."""

    ARTIFACT_FILENAMES: ClassVar[dict[str, str]] = {
        "audit_report": "report.html",
        "audit_results": "results.xml",
        "audit_log": "oscap.log",
        "fix_script": "fix.sh",
    }

    OSCAP_VERSION_PATTERN = re.compile(
        r"^\s*OpenSCAP[\s]+command[\s]+line[\s]+tool[\s]+\(oscap\)[\s]+(\d+)\.(\d+)\.(\d+)\s*$",
        flags=re.MULTILINE
    )

    def __init__(
        self,
        datastream_file: Path | str,
        openscap_bin_path: Path | str,
        work_dir: Path | str,
    ) -> None:
        """Initialize openscap backend.

        Args:
            datastream_file: path to SCAP datastream file
            openscap_bin_path: path to oscap binary
            work_dir: path to work directory for storing artifacts

        Raises:
            BackendError on permission issues with input files/dirs

        """
        self._datastream_path = Path(datastream_file).resolve()
        self._work_dir = Path(work_dir).resolve()
        self._oscap_path = Path(openscap_bin_path).resolve()

        # do sanity checks on oscap binary and work_dir
        try:
            validate_perms(self._oscap_path)
        except PermValidationError as e:
            raise BackendError(
                f"Permission issue with Openscap binary: {e}",
            ) from e
        if not os.access(self._oscap_path, os.X_OK):
            raise BackendError(
                f"Openscap binary '{self._oscap_path}' is not executable.",
            )

        try:
            validate_perms(self._work_dir, is_dir=True)
        except PermValidationError as e:
            raise BackendError(
                f"Permission issue with temporary work directory: {e}",
            ) from e

        self._oscap_version = self._get_oscap_version(
            self._oscap_path, self._work_dir
            )


    @staticmethod
    def _get_oscap_version(oscap_bin_path: Path, cwd: Path) -> tuple:
        # run "oscap --version" and return tuple
        logger.debug("Checking OpenSCAP version")

        cmd = [str(oscap_bin_path), "--version"]
        try:
            process = run_cmd(cmd, cwd=cwd, timeout=60)
        except BackendCommandError as e:
            raise BackendError(
                f"Failed to call 'oscap --version': {e}"
            ) from e

        try:
            match = re.match(
                OpenscapBackend.OSCAP_VERSION_PATTERN, process.stdout
                )
            version_s = match.group(1, 2, 3) # pyright: ignore[reportOptionalMemberAccess]
            return tuple(map(int, version_s))
        except (AttributeError, IndexError, ValueError):
            raise BackendError(
                "Failed to determine oscap version. Check debug logs."
                ) from None


    def audit(
        self,
        cac_profile: str,
        tailoring_file: Path | str | None = None,
        debug: bool = False,
        oval_results: bool = False,
    ) -> tuple[AuditResults, BackendArtifacts]:
        """Run audit using oscap backend.

        Args:
            cac_profile: profile ID
            tailoring_file: path to tailoring file (if None, no tailoring file is used)
            debug: if True, run in debug mode
            oval_results: if True, run with oval results

        Returns:
            AuditResults

        Raises:
            BackendError: if the audit command fails or the results file is invalid

        """
        logger.debug("Running audit using oscap backend")
        logger.debug(f"cac_profile: {cac_profile}")
        logger.debug(f"tailoring_file: {tailoring_file}")
        logger.debug(f"debug: {debug}")
        logger.debug(f"oval_results: {oval_results}")

        cmd = [str(self._oscap_path), "xccdf"]

        report_path = self._work_dir / self.ARTIFACT_FILENAMES["audit_report"]
        results_path = self._work_dir / self.ARTIFACT_FILENAMES["audit_results"]
        log_path = self._work_dir / self.ARTIFACT_FILENAMES["audit_log"]

        verbose_flag = "INFO" if debug else "WARNING"

        verbose_options = [
                "--verbose", verbose_flag,
                "--verbose-log-file", str(log_path),
            ]

        xccdf_options = [
                "eval",
                "--results", str(results_path),
                "--report", str(report_path),
                "--profile", cac_profile,
            ]

        # The cli is not backwards compatible with respect to verbose options.
        # In 1.3.9 (Noble), the options work only on the base command (xccdf).
        # In 1.2.17 (Jammy), the options work only on subcommands (eval),
        # Addressed in https://github.com/OpenSCAP/openscap/pull/2220
        if self._oscap_version < (1, 3, 0):
            cmd.extend(xccdf_options)
            cmd.extend(verbose_options)
        else:
            cmd.extend(verbose_options)
            cmd.extend(xccdf_options)

        if oval_results or debug:
            cmd.extend(["--oval-results"])

        if tailoring_file is not None:
            tailoring_path = Path(tailoring_file).resolve()
            cmd.extend(["--tailoring-file", str(tailoring_path)])

        cmd.append(str(self._datastream_path))

        try:
            _ = run_cmd(
                cmd,
                cwd=self._work_dir,
                capture_output=False,
                allowed_return_codes=[0,2],
                )
        except BackendCommandError as e:
            raise BackendError(
                f"Failed to run backend audit command: {e}",
            ) from e

        if not results_path.exists():
            raise BackendError(
                f"Backend failed to produce audit results file {results_path}. "
                f"Check openscap output for more details.",
            )

        artifacts = BackendArtifacts()
        artifacts.add_artifact("audit_report", report_path)
        artifacts.add_artifact("audit_results", results_path)
        artifacts.add_artifact("audit_log", log_path)

        if oval_results or debug:
            # oval results filenames are hardcoded and based on the DS
            # rename them to include the timestamp for backwards compatibility
            oval_result_files = list(self._work_dir.glob("*-oval.xml.result.xml"))
            try:
                oval_results_path = [  # noqa: RUF015
                    f for f in oval_result_files if "cpe" not in f.name
                ][0]
                artifacts.add_artifact(
                    "audit_oval_results", self._work_dir / oval_results_path
                )
            except IndexError:
                logger.error("Expected OVAL result file not found.")

            try:
                oval_cpe_results_path = [  # noqa: RUF015
                    f for f in oval_result_files if "cpe" in f.name
                ][0]
                artifacts.add_artifact(
                    "audit_oval_cpe_results", self._work_dir / oval_cpe_results_path
                )
            except IndexError:
                logger.error("Expected OVAL CPE result file not found.")

        logger.debug("Audit completed, parsing results")
        try:
            results = self._parse_audit_results(results_path)
        except Exception as e:  # noqa: BLE001
            # Result parsing is not critical and shouldn't break the app.
            # Log error and return empty results on fail.
            logger.error(
                f"Failed to parse audit results: {e}. "
                f"Check the result and report files."
                )
            results = AuditResults()
        return results, artifacts


    def _parse_audit_results(
        self,
        results_path: Path,
    ) -> AuditResults:
        """Parse Openscap results.xml and return results.

        Args:
            results_path: path to results file

        Returns:
            AuditResults

        Raises:
            BackendError: if the results file is invalid

        """
        logger.debug(f"Parsing results file {results_path}")

        try:
            tree = ET.parse(results_path)  # noqa: S314
            xml_root = tree.getroot()
        except ET.ParseError as e:
            raise BackendError(
                "XML parser failed to parse the results file",
            ) from e

        if not xml_root.tag.endswith("Benchmark"):
            raise BackendError(
                "Unknown root element of results file",
            )

        audit_results = AuditResults()
        try:
            test_results = xml_root.find("{*}TestResult")
            if test_results is None:
                raise BackendError(
                    "No TestResult found in results file",
                )
            for rule_result in test_results.findall("{*}rule-result"):
                rule_id = rule_result.get("idref")
                if rule_id is None:
                    raise BackendError(
                        f"No idref attribute found for rule-result {rule_result}",
                    )
                rule_id_short = rule_id.replace(
                    "xccdf_org.ssgproject.content_rule_", ""
                )

                result = rule_result.find("{*}result")
                if result is None:
                    raise BackendError(
                        f"No result found for rule-result {rule_result}",
                    )
                result_text = result.text or ""

                if result_text == "notselected":
                    logger.debug(f"Skipping notselected rule {rule_id_short}")
                else:
                    logger.debug(
                        f"Adding result for rule {rule_id_short}: {result_text}"
                    )
                    audit_results.add_result(rule_id_short, result_text, "")

        except Exception as e:
            raise BackendError(
                f"Failed to parse Openscap results file: {e}",
            ) from e

        logger.debug(f"Found {len(audit_results)} results")
        return audit_results


    def fix(
        self,
        cac_profile: str,
        tailoring_file: Path | str | None = None,
        audit_results_file: Path | str | None = None,
    ) -> BackendArtifacts:
        """Generate temporary fix file using oscap and run it.

        Args:
            cac_profile: profile ID
            tailoring_file: path to tailoring file (if None, no tailoring file is used)
            audit_results_file: path to audit results file. If specified,
                                only remediate failed rules (optional)

        Returns:
            BackendArtifacts

        Raises:
            BackendError: if the fix command fails or the fix file is invalid

        """
        logger.debug("Running remediation using openscap backend")
        logger.debug(f"cac_profile: {cac_profile}")
        logger.debug(f"tailoring_file: {tailoring_file}")
        logger.debug(f"audit_results_file: {audit_results_file}")

        # generate and run the fix script
        artifacts = self.generate_fix(
            cac_profile,
            tailoring_file,
            audit_results_file,
        )
        fix_path = artifacts.get_by_type("fix_script").path

        cmd = ["bash", str(fix_path)]
        try:
            _ = run_cmd(
                cmd,
                cwd=self._work_dir,
                capture_output=False,
                timeout=None,
                allowed_return_codes=list(range(256))
                )
        except BackendCommandError as e:
            raise BackendError(f"Failed to run backend fix command: {e}") from e

        logger.debug("Remediation finished")
        artifacts = BackendArtifacts()
        artifacts.add_artifact("fix_script", fix_path)
        return artifacts


    def generate_fix(
        self,
        cac_profile: str,
        tailoring_file: Path | str | None = None,
        audit_results_file: Path | str | None = None,
    ) -> BackendArtifacts:
        """Generate fix file using oscap and save it.

        Args:
            cac_profile: profile ID
            tailoring_file: path to tailoring file (if None, no tailoring file is used)
            audit_results_file: path to audit results file. If specified,
                                only generate fix for failed rules (optional)

        """
        logger.debug("Generating remeditiation script with openscap")
        logger.debug(f"cac_profile: {cac_profile}")
        logger.debug(f"tailoring_file: {tailoring_file}")
        logger.debug(f"audit_results_file: {audit_results_file}")

        fix_path = self._work_dir / self.ARTIFACT_FILENAMES["fix_script"]
        cmd = [
            str(self._oscap_path),
            "xccdf", "generate", "fix",
            "--fix-type", "bash",
            "--output", str(fix_path),
        ]

        if tailoring_file is not None:
            tailoring_file = Path(tailoring_file).resolve()
            cmd.extend([
                "--tailoring-file",
                str(tailoring_file)
                ])

        if audit_results_file is not None:
            audit_results_file = Path(audit_results_file).resolve()
            cmd.extend([
                "--result-id", cac_profile,
                str(audit_results_file)
                ])
        else:
            cmd.extend([
                "--profile", cac_profile,
                str(self._datastream_path)
                ])

        logger.debug(f"Writing remediation script {fix_path}")
        try:
            _ = run_cmd(cmd, cwd=self._work_dir)
        except BackendCommandError as e:
            raise BackendError(
                f"Failed to run backend generate-fix command: {e}"
            ) from e

        artifacts = BackendArtifacts()
        artifacts.add_artifact("fix_script", fix_path)
        return artifacts
