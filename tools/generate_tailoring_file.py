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


import sys
import datetime
import logging
import lxml.etree as etree
from pathlib import Path
from cac_tools import CaCProfile

logger = logging.getLogger(__name__)

XMLNS = "http://checklists.nist.gov/xccdf/1.2"

def generate_tailoring_file(profile, xccdf_path, tailoring_path, pkg_version):
    # create a tailoring file based on profile controls
    # and provided XCCDF file and tailoring file template
    xccdf_path = Path(xccdf_path)
    tailoring_path = Path(tailoring_path)
    current_timestamp = datetime.datetime.now(datetime.UTC).replace(microsecond=0)

    xccdf_doc = None
    tailor_doc = None
    try:
        xccdf_doc = etree.parse(xccdf_path)
    except etree.XMLSyntaxError:
        print("Could not process XCCDF file", file=sys.stderr)
        sys.exit(1)

    try:
        parser = etree.XMLParser(remove_blank_text=True)
        tailor_doc = etree.parse(tailoring_path, parser)
        xml_bench = tailor_doc.find(".//{%s}benchmark" % XMLNS)
        xml_bench.attrib["href"] = "/usr/share/ubuntu-scap-security-guides/" +\
            str(pkg_version) + "/benchmarks/" + str(xccdf_path.name)
        xml_ver = tailor_doc.find(".//{%s}version" % XMLNS)
        xml_ver.attrib["time"] = current_timestamp.isoformat()
    except etree.XMLSyntaxError:
        print("Could not process template tailoring file", file=sys.stderr)
        sys.exit(1)

    control_map = {cid: {'rules':[], 'vars': []} for cid in profile.controls}
    for rule in profile.rules.values():
        control_map[rule.control.control_id]['rules'].append(rule)
    for var in profile.vars.values():
        control_map[var.control.control_id]['vars'].append(var)

    for control_id in sorted(control_map):
        control_rules = control_map[control_id]['rules']
        control_vars = control_map[control_id]['vars']
        if control_rules or control_vars:
            comment = f'{control_id}: {profile.controls[control_id].title}'
            _insert_into_xml(tailor_doc, "comment", comment)

            for var in control_vars:
                xccdf_var = f'xccdf_org.ssgproject.content_value_{var.name}'
                # map selector to actual value
                pval = _get_value_for_var_selector(xccdf_doc, xccdf_var, var.value)
                _insert_into_xml(tailor_doc, "set-value", xccdf_var, pval)

            for rule in control_rules:
                is_selected = "true" if rule.selected else "false"
                prule = f'xccdf_org.ssgproject.content_rule_{rule.name}'
                _insert_into_xml(tailor_doc, "select", prule, is_selected)

    return tailor_doc


def _get_value_for_var_selector(doc, var, val):
    root = doc.getroot()
    for xmlVal in root.findall(".//{%s}Value" % XMLNS):
        if xmlVal.get('id') == var:
            for xmlval in xmlVal.findall(".//{%s}value" % XMLNS):
                if xmlval.get('selector') == val:
                    return xmlval.text
    raise Exception("No value found for variable { var }!")


def _insert_into_xml(tailor_doc, elem, idref, text=None):
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
    usage = f'''
Script for generating a tailoring file based on
XCCDF file, profile yaml file, and tailoring file template.

Usage: python {sys.argv[0]} <Profile file path> <XCCDF file path> <Tailoring template path> <Pkg version>
'''

    if len(sys.argv) != 5:
        print(usage)
        sys.exit(1)

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(levelname)s: %(message)s')

    yaml_path = Path(sys.argv[1])
    xccdf_path = Path(sys.argv[2])
    tailoring_path = Path(sys.argv[3])
    pkg_version = Path(sys.argv[4])

    profile = CaCProfile.from_yaml(yaml_path)
    tailor_doc = generate_tailoring_file(profile, xccdf_path, tailoring_path, pkg_version)

    out_path = str(tailoring_path).replace("templates", ".") # TODO whoa
    tailor_doc.write(out_path, pretty_print=True,
                     xml_declaration=True, encoding="utf-8")

    logger.info(f'Successfully generated tailoring file {out_path}')

    sys.exit(0)
