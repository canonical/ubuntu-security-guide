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

"""Functions and CLI for generating USG tailoring files."""
import sys
import time

if sys.version_info < (3,12):
    sys.exit("Build tools require Python>=3.12")

import argparse
import datetime
import logging
import subprocess
from pathlib import Path

from cac_tools import CaCProfile
from lxml import etree

logger = logging.getLogger(__name__)

XMLNS = "http://checklists.nist.gov/xccdf/1.2"
BENCHMARK_HREF_PATTERN = "/usr/share/usg-benchmarks/{benchmark_id}"

class GenerateTailoringError(Exception):
    """General error when generating tailoring file."""

def generate_tailoring_file(
    profile_path: Path,
    datastream_path: Path,
    tailoring_template_path: Path,
    benchmark_id: str,
    tailoring_file_output_path: Path,
    timestamp: float,
) -> None:
    """Create a tailoring file based on provided args.

    Args:
        profile_path: ComplianceAsCode profile file
        datastream_path: ComplianceAsCode compiled source datastream file
        tailoring_template_path: template file for tailoring file
        benchmark_id: benchmark ID (e.g. ubuntu2404_CIS_1)
        tailoring_file_output_path: output path
        timestamp: timestamp to be used in "time" attribute

    Raises:
        GenerateTailoringError

    """
    logger.debug(
        f"Generating tailoring file {tailoring_file_output_path} for profile "
        f"{profile_path} with datastream file {datastream_path} and tailoring "
        f"template {tailoring_template_path}."
    )
    logger.debug(f"Benchmark ID: {benchmark_id}")

    profile = CaCProfile.from_yaml(profile_path)

    datastream_path = Path(datastream_path)
    tailoring_template_path = Path(tailoring_template_path)
    iso_timestamp = datetime.datetime.fromtimestamp(
        timestamp,
        datetime.timezone.utc
        ).isoformat()

    try:
        datastream_doc = etree.parse(datastream_path)
    except etree.XMLSyntaxError as e:
        raise GenerateTailoringError(f"Failed to process datastream file: {e}") from e

    try:
        logger.debug(f"Processing template tailoring file {tailoring_template_path}")
        parser = etree.XMLParser(remove_blank_text=True)
        tailor_doc = etree.parse(tailoring_template_path, parser)
        xml_bench = tailor_doc.find(f".//{{{XMLNS}}}benchmark")
        xml_bench.attrib["href"] = BENCHMARK_HREF_PATTERN.format(
            benchmark_id=benchmark_id
        )
        xml_ver = tailor_doc.find(f".//{{{XMLNS}}}version")
        xml_ver.attrib["time"] = iso_timestamp
    except etree.XMLSyntaxError as e:
        raise GenerateTailoringError(
            f"Failed to process template tailoring file: {e}"
            ) from e

    logger.debug(f"Mapping rules and variables to controls for profile {profile_path}")
    control_map = {cid: {"rules": [], "vars": []} for cid in profile.controls}
    for rule in profile.rules.values():
        logger.debug(f"Adding rule {rule.name} to control {rule.control.control_id}")
        control_map[rule.control.control_id]["rules"].append(rule)
    for var in profile.vars.values():
        logger.debug(f"Adding variable {var.name} to control {var.control.control_id}")
        control_map[var.control.control_id]["vars"].append(var)

    logger.debug("Inserting rules and variables into tailoring file")
    for control_id in control_map:
        logger.debug(f"Processing control {control_id}")
        control_rules = control_map[control_id]["rules"]
        control_vars = control_map[control_id]["vars"]
        if control_rules or control_vars:
            comment = f"{control_id}: {profile.controls[control_id].title}"
            _insert_into_xml(tailor_doc, "comment", comment)

            for var in control_vars:
                logger.debug(f"Processing variable {var.name} for control {control_id}")
                xccdf_var = f"xccdf_org.ssgproject.content_value_{var.name}"
                # map selector to actual value
                pval = _get_value_for_var_selector(datastream_doc, xccdf_var, var.value)
                _insert_into_xml(tailor_doc, "set-value", xccdf_var, pval)

            for rule in control_rules:
                logger.debug(f"Processing rule {rule.name} for control {control_id}")
                is_selected = "true" if rule.selected else "false"
                prule = f"xccdf_org.ssgproject.content_rule_{rule.name}"
                _insert_into_xml(tailor_doc, "select", prule, is_selected)
    logger.debug(f"Successfully generated tailoring file for profile {profile_path}")

    tailor_doc.write(
        tailoring_file_output_path,
        pretty_print=True,
        xml_declaration=True,
        encoding="utf-8",
    )
    logger.debug(f"Successfully wrote tailoring file {tailoring_file_output_path}")


def validate_tailoring_file(tailoring_path: Path) -> None:
    """Validate the tailoring file using oscap."""
    logger.debug(f"Validating tailoring file {tailoring_path}")
    cmd = [
        "/usr/bin/oscap",
        "oval",
        "validate",
        "--skip-schematron",
        str(tailoring_path),
    ]
    try:
        subprocess.run(cmd, check=True)  # noqa: S603
    except Exception as e:
        raise GenerateTailoringError(
            f"Executing `{' '.join(cmd)}` failed.: {e}"
            ) from e
    logger.info("Successfully validated the tailoring file")


def _get_value_for_var_selector(doc: etree._ElementTree, var: str, val: str) -> str:
    logger.debug(f"Getting value for variable {var} with selector {val}")
    root = doc.getroot()
    for xml_val in root.findall(f".//{{{XMLNS}}}Value"):
        if xml_val.get("id") == var:
            for xml_val2 in xml_val.findall(f".//{{{XMLNS}}}value"):
                if xml_val2.get("selector") == val:
                    return xml_val2.text
    raise GenerateTailoringError(
        f"No value found for variable {var}!"
        )


def _insert_into_xml(
        tailor_doc: etree._ElementTree,
        elem: str,
        idref: str,
        text: str | None = None
        ) -> None:
    logger.debug(f"Inserting {elem} into XML for {idref}")
    root = tailor_doc.getroot()
    for xml_prof in root.findall(f".//{{{XMLNS}}}Profile"):
        if elem == "set-value":
            value = etree.SubElement(xml_prof, elem, idref=idref)
            value.text = text
        elif elem == "select":
            value = etree.SubElement(xml_prof, elem, idref=idref, selected=text)
        else:
            value = etree.Comment(idref)
            xml_prof.append(value)


if __name__ == "__main__":
    description = (
        "Script for generating a tailoring file based on datastream file, "
        "profile yaml file, and tailoring file template."
    )

    argparser = argparse.ArgumentParser(description=description)
    argparser.add_argument("profile_path", type=Path, help="Path to profile yaml file")
    argparser.add_argument("datastream_path", type=Path, help="Path to datastream file")
    argparser.add_argument(
        "tailoring_template_path", type=Path, help="Path to tailoring template file"
    )
    argparser.add_argument("benchmark_id", type=str, help="Benchmark ID")
    argparser.add_argument(
        "output_tailoring_path", type=Path, help="Path to output tailoring file"
    )
    argparser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = argparser.parse_args()

    loglevel = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        stream=sys.stdout, level=loglevel, format="%(levelname)s: %(message)s"
    )

    logger.info(
        f"Generating tailoring file for profile {args.profile_path} "
        f"with datastream file {args.datastream_path} and "
        f"tailoring template {args.tailoring_template_path}"
    )
    logger.info(f"Benchmark ID: {args.benchmark_id}")
    logger.info(f"Output tailoring file: {args.output_tailoring_path}")

    try:
        generate_tailoring_file(
            args.profile_path,
            args.datastream_path,
            args.tailoring_template_path,
            args.benchmark_id,
            args.output_tailoring_path,
            time.time(),
        )
        validate_tailoring_file(args.output_tailoring_path)
    except GenerateTailoringError as e:
        sys.exit(f"Failed to generate tailoring file: {e}")
    logger.info(f"Successfully generated tailoring file {args.output_tailoring_path}")

