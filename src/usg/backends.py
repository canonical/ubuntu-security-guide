"""
Auditing and remediation backends for USG (e.g. oscap).
"""

import logging
import os
import subprocess
from pathlib import Path
import xml.etree.ElementTree as ET

from usg.results import AuditResults, BackendArtifacts
from usg.utils import validate_perms
from usg.exceptions import PermValidationError, BackendError

logger = logging.getLogger(__name__)


class OpenscapBackend:

    ARTIFACT_FILENAMES = {
        "audit_report": "report.html",
        "audit_results": "results.xml",
        "audit_log": "oscap.log",
        "fix_script": "fix.sh",
        "fix_log": "fix.log",
    }

    def __init__(
            self,
            datastream_file: Path | str,
            tmp_work_dir: Path | str,
            openscap_bin_path: Path | str,
            ):

        self._datastream_path = Path(datastream_file)
        self._tmp_work_dir = Path(tmp_work_dir)
        self._oscap_path = Path(openscap_bin_path)

        # do sanity checks on oscap binary and tmp_work_dir
        try:
            validate_perms(self._oscap_path)
        except PermValidationError as e:
            raise BackendError(
                    f"Issue with Openscap binary: {e}"
                    )
        if not os.access(self._oscap_path, os.X_OK):
            raise BackendError(
                f"Openscap binary '{self._oscap_path}' is not "
                "executable."
            )

        try:
            validate_perms(self._tmp_work_dir, is_dir=True)
        except PermValidationError as e:
            raise BackendError(
                    f"Issue with temporary work directory: {e}"
                    )
        

    def audit(
            self,
            cac_profile: str,
            tailoring_file: Path | str | None = None,
            debug: bool = False,
            oval_results: bool = False,
            ) -> tuple[AuditResults, BackendArtifacts]:
        """
        Run audit using oscap backend.

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

        report_path = self._tmp_work_dir / self.ARTIFACT_FILENAMES["audit_report"]
        results_path = self._tmp_work_dir / self.ARTIFACT_FILENAMES["audit_results"]
        log_path = self._tmp_work_dir / self.ARTIFACT_FILENAMES["audit_log"]

        if debug:
            verbose_flag = "INFO"
        else:
            verbose_flag = "WARNING"

        cmd.extend([
                "--verbose", verbose_flag,
                "--verbose-log-file", str(log_path),
                "eval",
                "--results", str(results_path),
                "--report", str(report_path),
                "--profile", cac_profile,
            ]
        )

        if oval_results or debug:
            cmd.extend(["--oval-results"])

        if tailoring_file is not None:
            tailoring_path = Path(tailoring_file).resolve()
            cmd.extend(["--tailoring-file", str(tailoring_path)])

        cmd.append(str(self._datastream_path))

        logger.debug(f"Running cmd: {' '.join(cmd)}")
        try:
            subprocess.run(cmd, cwd=self._tmp_work_dir)
        except subprocess.SubprocessError as e:
            raise BackendError(
                    f"Error running backend audit command: {e}"
                    ) from e

        if not results_path.exists():
            raise BackendError(
                    f"'audit' command failed to produce results file {results_path}. "
                    "Check openscap output for more details."
                    )

        artifacts = BackendArtifacts()
        artifacts.add_artifact("audit_report", report_path)
        artifacts.add_artifact("audit_results", results_path)
        artifacts.add_artifact("audit_log", log_path)

        if oval_results or debug:
            # oval results filenames are hardcoded and based on the DS
            # rename them to include the timestamp for backwards compatibility
            oval_result_files = list(self._tmp_work_dir.glob("*-oval.xml.result.xml"))
            try:
                oval_results_path = [f for f in oval_result_files if "cpe" not in f.name][0]
                artifacts.add_artifact("audit_oval_results", self._tmp_work_dir / oval_results_path)
            except IndexError:
                logger.error(f"Expected OVAL result file not found: {oval_results_path}")

            try:
                oval_cpe_results_path = [f for f in oval_result_files if "cpe" in f.name][0]
                artifacts.add_artifact("audit_oval_cpe_results", self._tmp_work_dir / oval_cpe_results_path)
            except IndexError:
                logger.error(f"Expected OVAL CPE result file not found: {oval_cpe_results_path}")
        
        logger.debug("Audit completed, parsing results")
        results = self._parse_audit_results(results_path)
        return results, artifacts

    def _parse_audit_results(
            self,
            results_path: Path
            ) -> AuditResults:
        """
        Parse Openscap results.xml and return AuditResults

        Args:
            results_path: path to results file

        Returns:
            AuditResults

        Raises:
            BackendError: if the results file is invalid
        """

        logger.debug(f"Parsing results file {results_path}")

        
        try:
            tree = ET.parse(results_path)
            xml_root = tree.getroot()
        except ET.ParseError as e:
            raise BackendError(
                    "XML parser failed to parse the results file"
                    ) from e

        if not xml_root.tag.endswith("Benchmark"):
            raise BackendError(
                    "Unknown root element of results file"
                    )

        audit_results = AuditResults()
        try:
            test_results = xml_root.find('{*}TestResult')
            if test_results is None:
                raise BackendError(
                        "No TestResult found in results file"
                        )
            for rule_result in test_results.findall('{*}rule-result'):
                rule_id = rule_result.get('idref')
                if rule_id is None:
                    raise BackendError(
                            f"No idref attribute found for rule-result {rule_result}"
                            )
                rule_id_short = rule_id.replace("xccdf_org.ssgproject.content_rule_", "")

                result = rule_result.find('{*}result')
                if result is None:
                    raise BackendError(
                            f"No result found for rule-result {rule_result}"
                            )
                result_text = result.text or ""

                if result_text == "notselected":
                    logger.debug(f"Skipping notselected rule {rule_id_short}")
                else:
                    logger.debug(f"Adding result for rule {rule_id_short}: {result_text}")
                    audit_results.add_result(rule_id_short, result_text, "")

        except Exception as e:
            raise BackendError(
                    f"Failed to parse Openscap results file: {e}"
                    ) from e

        logger.debug(f"Found {len(audit_results)} results")
        return audit_results

    def fix(self,
            cac_profile: str,
            tailoring_file: Path | str | None = None,
            audit_results_file: Path | str | None = None,
            ) -> BackendArtifacts:
        """
        Generate temporary fix file using oscap and run it

        Args:
            cac_profile: profile ID
            tailoring_file: path to tailoring file (if None, no tailoring file is used)
            audit_results_file: path to audit results file. If specified, only remediate failed rules (optional)
            
        Returns:
            BackendArtifacts

        Raises:
            BackendError: if the fix command fails or the fix file is invalid
        """

        logger.debug("Running remediation using openscap backend")
        logger.debug(f"cac_profile: {cac_profile}")
        logger.debug(f"tailoring_file: {tailoring_file}")
        logger.debug(f"audit_results_file: {audit_results_file}")

        fix_log_path = self._tmp_work_dir / self.ARTIFACT_FILENAMES["fix_log"]

        try:
            # generate and run the fix script
            artifacts = self.generate_fix(
                cac_profile,
                tailoring_file,
                audit_results_file,
            )
            fix_path = artifacts.get_by_type("fix_script").path

            cmd = ['/usr/bin/bash', str(fix_path)]

            with open(fix_log_path, 'w+') as fl:
                logger.debug(f"Running cmd: {" ".join(cmd)}")
                logger.debug(f"Writing output to: {fix_log_path}")
                subprocess.run(
                        cmd,
                        stdout=fl,
                        stderr=fl,
                        text=True,
                        check=False,
                        cwd=self._tmp_work_dir
                        )

        except BackendError:
            raise
        except Exception as e:
            logger.exception(e)
            raise BackendError(f"Error running backend fix command: {e}") from e

        logger.debug("Remediation finished")
        artifacts = BackendArtifacts()
        artifacts.add_artifact("fix_script", fix_path)
        artifacts.add_artifact("fix_log", fix_log_path)
        return artifacts

    def generate_fix(
            self,
            cac_profile: str,
            tailoring_file: Path | str | None = None,
            audit_results_file: Path | str | None = None,
            ) -> BackendArtifacts:
        """
        Generate fix file using oscap and save it

        Args:
            cac_profile: profile ID
            tailoring_file: path to tailoring file (if None, no tailoring file is used)
            audit_results_file: path to audit results file. If specified, only generate fix for failed rules (optional)
        """
        logger.debug("Generating remeditiation script with openscap")
        logger.debug(f"cac_profile: {cac_profile}")
        logger.debug(f"tailoring_file: {tailoring_file}")
        logger.debug(f"audit_results_file: {audit_results_file}")

        fix_path = self._tmp_work_dir / self.ARTIFACT_FILENAMES["fix_script"]
        cmd = [
            str(self._oscap_path), "xccdf", "generate", "fix",
            "--fix-type", "bash",
            "--output", str(fix_path),
        ]

        if tailoring_file is not None:
            tailoring_file = Path(tailoring_file).resolve()
            cmd.extend([
                "--tailoring-file", str(tailoring_file),
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

        logger.info(f"Running cmd: {' '.join(cmd)}")
        p = subprocess.run(
                cmd,
                cwd=self._tmp_work_dir,
                text=True,
                check=False
                )

        if p.returncode != 0:
            logger.error(f"Stdout: {p.stdout}")
            logger.error(f"Stderr: {p.stderr}")
            logger.error(f"Returncode: {p.returncode}")
            raise BackendError(
                (
                    f"Openscap command failed with error code "
                    f"{p.returncode}"
                )
            )
        logger.debug(f"Fix script generated at {fix_path}")

        artifacts = BackendArtifacts()
        artifacts.add_artifact("fix_script", fix_path)
        return artifacts

