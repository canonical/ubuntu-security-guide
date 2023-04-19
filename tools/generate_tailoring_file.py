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

XMLNS = "http://checklists.nist.gov/xccdf/1.2"

def process_var(doc, var, val):
    root = doc.getroot()
    for xmlVal in root.findall(".//{%s}Value" % XMLNS):
        if xmlVal.get('id') == var:
            for xmlval in xmlVal.findall(".//{%s}value" % XMLNS):
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


def create_tailoring_file(profile, xccdf_doc, tailor_doc):
    for item in profile:
        if item['rule'] or item['var']:
            insert_into_xml(tailor_doc, "comment", item['comment'])

            if item['var']:
                for i in range(len(item['var'])):
                    var = 'xccdf_org.ssgproject.content_value_' + item['var'][i]
                    val = item['var_value'][i]
                    pval = process_var(xccdf_doc, var, val)
                    insert_into_xml(tailor_doc, "set-value", var, pval)

            for i in range(len(item['rule'])):
                prule, is_selected = process_rule(item['rule'][i])
                prule = 'xccdf_org.ssgproject.content_rule_' + prule
                insert_into_xml(tailor_doc, "select", prule, is_selected)


def get_parent_yaml_path(yaml_path, parent_profile):
    return yaml_path.rsplit(sep="/", maxsplit=1)[0] + \
        "/" + parent_profile + ".profile"


def add_to_profile(profile, item):
    # check if rule was already added to profile,
    # this means it is a child overwriting parent rule
    for i in profile:
        if i['comment'] == item['comment']:
            i.update(item)
            item = {}
            break
    # this means the rule is not yet in the profile
    if item:
        profile.append(item)


def update_variable_value(profile, var_name, value):
    # this means it is a child overwriting parent variable value
    for i in profile:
        for v in i['var']:
            if v == var_name:
                idx = i['var'].index(v)
                i['var_value'][idx] = value
                break


def process_profile_file(yaml_path):
    fd = None
    profile = []
    item = {}
    rules = []
    variables = []

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
            profile, variables, rules = process_profile_file(parent_path)

        comment = re.search(r"^\s*#+\s*([\d+|\.]+\s.*|UBTU-.*)$", line)
        if comment:
            if item:
                add_to_profile(profile, item)
                item = {}
            item['comment'] = comment.group(1).strip()
            item['rule'] = list()
            item['var'] = list()
            item['var_value'] = list()

        rule = re.search(r"^\s*-\s(.*)$", line)
        if rule:
            # check if it is not a var instead:
            var = re.search(r"^\s*-\s+(.*)\s*=\s*(.*)$", line)
            if var:
                var_name = var.group(1).strip()
                var_value = var.group(2).strip()
                if var_name not in variables:
                    variables.append(var_name)
                    item['var'].append(var_name)
                    item['var_value'].append(var_value)
                else:
                    update_variable_value(profile, var_name, var_value)
            else:
                rule_name = rule.group(1).strip(" '")
                # avoid adding duplicated rules
                if rule_name not in rules:
                    rules.append(rule_name)
                    item['rule'].append(rule_name)

    if item:
        add_to_profile(profile, item)
        item = {}

    return profile, variables, rules


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

    profile, _, _ = process_profile_file(yaml_path)

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
            pkg_version + "/benchmarks/" + xccdf_path.split('/')[-1]
        xml_ver = tailor_doc.find(".//{%s}version" % XMLNS)
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
