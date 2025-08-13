#!/usr/bin/python3
#
# Ubuntu Security Guide
# Copyright (C) 2025 Canonical Limited
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import subprocess
import sys
import datetime
import logging
import lxml.etree as etree
from pathlib import Path
from cac_tools import CaCProfile


logger = logging.getLogger(__name__)

XMLNS = "http://checklists.nist.gov/xccdf/1.2"
BENCHMARK_HREF_PATTERN = "/usr/share/usg-benchmarks/{benchmark_id}"

def generate_tailoring_file(profile_path, datastream_path, tailoring_path, benchmark_id):
    # create a tailoring file based on profile controls
    # and provided XCCDF file and tailoring file template
    logger.debug(f"Generating tailoring file for profile {profile_path} with datastream file {datastream_path} and tailoring template {tailoring_path}")
    logger.debug(f"Benchmark ID: {benchmark_id}")

    profile = CaCProfile.from_yaml(profile_path)

    datastream_path = Path(datastream_path)
    tailoring_path = Path(tailoring_path)
    current_timestamp = datetime.datetime.now(datetime.UTC).replace(microsecond=0)

    try:
        datastream_doc = etree.parse(datastream_path)
    except etree.XMLSyntaxError:
        sys.exit("Failed to process datastream file")

    try:
        logger.debug(f"Processing template tailoring file {tailoring_path}")
        parser = etree.XMLParser(remove_blank_text=True)
        tailor_doc = etree.parse(tailoring_path, parser)
        xml_bench = tailor_doc.find(".//{%s}benchmark" % XMLNS)
        xml_bench.attrib["href"] = BENCHMARK_HREF_PATTERN.format(benchmark_id = benchmark_id)
        xml_ver = tailor_doc.find(".//{%s}version" % XMLNS)
        xml_ver.attrib["time"] = current_timestamp.isoformat()
    except etree.XMLSyntaxError:
        sys.exit("Failed to process template tailoring file")

    logger.debug(f"Mapping rules and variables to controls for profile {profile_path}")
    control_map = {cid: {'rules':[], 'vars': []} for cid in profile.controls}
    for rule in profile.rules.values():
        logger.debug(f"Adding rule {rule.name} to control {rule.control.control_id}")
        control_map[rule.control.control_id]['rules'].append(rule)
    for var in profile.vars.values():
        logger.debug(f"Adding variable {var.name} to control {var.control.control_id}")
        control_map[var.control.control_id]['vars'].append(var)

    logger.debug("Inserting rules and variables into tailoring file")
    for control_id in sorted(control_map):
        logger.debug(f"Processing control {control_id}")
        control_rules = control_map[control_id]['rules']
        control_vars = control_map[control_id]['vars']
        if control_rules or control_vars:
            comment = f'{control_id}: {profile.controls[control_id].title}'
            _insert_into_xml(tailor_doc, "comment", comment)

            for var in control_vars:
                logger.debug(f"Processing variable {var.name} for control {control_id}")
                xccdf_var = f'xccdf_org.ssgproject.content_value_{var.name}'
                # map selector to actual value
                pval = _get_value_for_var_selector(datastream_doc, xccdf_var, var.value)
                _insert_into_xml(tailor_doc, "set-value", xccdf_var, pval)

            for rule in control_rules:
                logger.debug(f"Processing rule {rule.name} for control {control_id}")
                is_selected = "true" if rule.selected else "false"
                prule = f'xccdf_org.ssgproject.content_rule_{rule.name}'
                _insert_into_xml(tailor_doc, "select", prule, is_selected)

    logger.debug(f"Successfully generated tailoring file for profile {profile_path}")
    return tailor_doc


def validate_tailoring_file(tailoring_path):
    # validate the tailoring file using oscap
    logger.debug(f"Validating tailoring file {tailoring_path}")
    try:
        cmd = ["/usr/bin/oscap", "oval", "validate", "--skip-schematron", tailoring_path]
        subprocess.run(cmd, check=True)
    except Exception:
        sys.exit(f"Executing `{' '.join(cmd)}` failed.")
    logger.info("Successfully validated the tailoring file")


def _get_value_for_var_selector(doc, var, val):
    logger.debug(f"Getting value for variable {var} with selector {val}")
    root = doc.getroot()
    for xmlVal in root.findall(".//{%s}Value" % XMLNS):
        if xmlVal.get('id') == var:
            for xmlval in xmlVal.findall(".//{%s}value" % XMLNS):
                if xmlval.get('selector') == val:
                    return xmlval.text
    raise Exception(f"No value found for variable {var}!")


def _insert_into_xml(tailor_doc, elem, idref, text=None):
    logger.debug(f"Inserting {elem} into XML for {idref}")
    root = tailor_doc.getroot()
    for xmlProf in root.findall(".//{%s}Profile" % XMLNS):
        if elem == "set-value":
            value = etree.SubElement(xmlProf, f"{elem}",
                                     idref=idref)
            value.text = text
        elif elem == "select":
            value = etree.SubElement(xmlProf, f"{elem}",
                                     idref=idref, selected=text)
        else:
            value = etree.Comment(idref)
            xmlProf.append(value)


if __name__ == '__main__':
    description = (
        "Script for generating a tailoring file based on datastream file, "
        "profile yaml file, and tailoring file template."
    )

    argparser = argparse.ArgumentParser(description=description)
    argparser.add_argument('profile_path', type=Path, help='Path to profile yaml file')
    argparser.add_argument('datastream_path', type=Path, help='Path to datastream file')
    argparser.add_argument('tailoring_template_path', type=Path, help='Path to tailoring template file')
    argparser.add_argument('benchmark_id', type=str, help='Benchmark ID')
    argparser.add_argument('output_tailoring_path', type=Path, help='Path to output tailoring file')
    argparser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = argparser.parse_args()

    loglevel = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(stream=sys.stdout, level=loglevel, format='%(levelname)s: %(message)s')

    logger.info(f"Generating tailoring file for profile {args.profile_path} with datastream file {args.datastream_path} and tailoring template {args.tailoring_template_path}")
    logger.info(f"Benchmark ID: {args.benchmark_id}")
    logger.info(f"Output tailoring file: {args.output_tailoring_path}")

    tailor_doc = generate_tailoring_file(args.profile_path, args.datastream_path, args.tailoring_template_path, args.benchmark_id)
    tailor_doc.write(
        args.output_tailoring_path,
        pretty_print=True,
        xml_declaration=True,
        encoding="utf-8"
        )
    validate_tailoring_file(args.output_tailoring_path)

    logger.info(f'Successfully generated tailoring file {args.output_tailoring_path}')

    sys.exit(0)
