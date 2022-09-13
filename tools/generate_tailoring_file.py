#!/usr/bin/python3
#
# Ubuntu Security Guide
# Copyright (C) 2022 Canonical Limited
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


import datetime
import re
import lxml.etree as etree
import sys


def process_var(doc, var, val):
    root = doc.getroot()
    for xmlVal in root.findall(".//{http://checklists.nist.gov/xccdf/1.1}Value"):
        if xmlVal.get('id') == var:
            for xmlval in xmlVal.findall(".//{http://checklists.nist.gov/xccdf/1.1}value"):
                if xmlval.get('selector') == val:
                    return xmlval.text

    raise Exception("No value found for variable { var }!")


# If the raw rule name contains a '!' character, returns the name
# without it and return flag select as False
def process_rule(rule):
    if rule.startswith("!"):
        return (rule.lstrip('!'), "false")
    return (rule, "true")


def insert_into_xml(tailor_doc, elem, idref, text=None):
    root = tailor_doc.getroot()
    nsmap = root.nsmap['xccdf']
    for xmlProf in root.findall(".//{http://checklists.nist.gov/xccdf/1.1}Profile"):
        if elem == "set-value":
            value = etree.SubElement(xmlProf, f"{{{nsmap}}}{elem}",
                                     idref=idref)
            value.text = text
        elif elem == "select":
            value = etree.SubElement(xmlProf, f"{{{nsmap}}}{elem}",
                                     idref=idref, selected=text)
        else:
            value = etree.Comment(idref)
            xmlProf.append(value)


def create_tailoring_file(profile, xccdf_doc, tailor_doc):
    for item in profile:
        if item['rule'] or item['var']:
            insert_into_xml(tailor_doc, "comment", item['comment'])

            if item['var']:
                for i in range(len(item['var'])):
                    var = item['var'][i]
                    val = item['var_value'][i]
                    pval = process_var(xccdf_doc, var, val)
                    insert_into_xml(tailor_doc, "set-value", var, pval)

            for i in range(len(item['rule'])):
                prule, is_selected = process_rule(item['rule'][i])
                insert_into_xml(tailor_doc, "select", prule, is_selected)


def get_parent_yaml_path(yaml_path, parent_profile):
    return yaml_path.rsplit(sep="/", maxsplit=1)[0] + \
        "/" + parent_profile + ".profile"


def add_to_profile(profile, rule):
    # check if rule was already added to profile,
    # this means it is a child overwriting parent rule
    for r in profile:
        if r['comment'] == rule['comment']:
            r.update(rule)
            rule = {}
            break
    # this means the rule is not yet in the profile
    if rule:
        profile.append(rule)


def process_profile_file(yaml_path):
    fd = None
    profile = []
    rule = {}

    try:
        with open(yaml_path, 'r') as yaml_file:
            fd = yaml_file.readlines()
    except OSError:
        print("Could not open profile file", file=sys.stderr)
        sys.exit(1)

    for line in fd:
        if "extends:" in line:
            parent_profile = re.search(r"^extends:\s(.*)$", line).group(1).strip()
            parent_path = get_parent_yaml_path(yaml_path, parent_profile)
            profile = process_profile_file(parent_path)

        comment = re.search(r"^\s*#+\s*([\d+|\.]+\s.*|UBTU-.*)$", line)
        if comment:
            if rule:
                add_to_profile(profile, rule)
                rule = {}
            rule['comment'] = comment.group(1).strip()
            rule['rule'] = list()
            rule['var'] = list()
            rule['var_value'] = list()

        rul = re.search(r"^\s*-\s(.*)$", line)
        if rul:
            # check if it is not a var instead:
            var = re.search(r"^\s*-\s+(.*)\s*=\s*(.*)$", line)
            if var:
                rule['var'].append(var.group(1).strip())
                rule['var_value'].append(var.group(2).strip())
            else:
                rule['rule'].append(rul.group(1).strip(" '"))

    if rule:
        add_to_profile(profile, rule)
        rule = {}

    return profile


USAGE = f"Usage: python {sys.argv[0]} <Profile file path> <XCCDF file path>"
if __name__ == '__main__':
    if len(sys.argv) != 5:
        print(USAGE, file=sys.stderr)
        sys.exit(1)

    current_timestamp = datetime.datetime.utcnow().replace(microsecond=0)
    yaml_path = sys.argv[1]
    xccdf_path = sys.argv[2]
    tailoring_path = sys.argv[3]
    pkg_version = sys.argv[4]

    profile = process_profile_file(yaml_path)

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
        xml_bench = tailor_doc.find(".//{http://open-scap.org/page/Xccdf-1.1-tailoring}benchmark")
        xml_bench.attrib["href"] = "/usr/share/ubuntu-scap-security-guides/" +\
            pkg_version +\
            "/benchmarks/Canonical_Ubuntu_20.04_Benchmarks-xccdf.xml"
        xml_ver = tailor_doc.find(".//{http://open-scap.org/page/Xccdf-1.1-tailoring}version")
        xml_ver.attrib["time"] = current_timestamp.isoformat()
    except etree.XMLSyntaxError:
        print("Could not process template tailoring file", file=sys.stderr)
        sys.exit(1)

    create_tailoring_file(profile,
                          xccdf_doc,
                          tailor_doc)

    out_path = tailoring_path.replace("templates", ".")
    tailor_doc.write(out_path, pretty_print=True,
                     xml_declaration=True, encoding="utf-8")

    sys.exit(0)
