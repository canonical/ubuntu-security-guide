#!/usr/bin/python3

# Ubuntu Security Guides
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

"""
Helper script to extract existing XCCDF content from a single monolithic
file into smaller portions more suitable for the ComplianceAsCode/content
build system -- rule.yml entries.
"""

import sys
import xml.etree.ElementTree as ET
import textwrap

from extract_oval import find_entity
from extract_ruleset import hack_is_element

def extract_rule_num(identifier):
    assert '_CIS-' in identifier
    index = identifier.index('_CIS-')
    return identifier[index + 5:]

def get_child(parent, tag):
    for element in parent:
        if hack_is_element(element, tag):
            yield element

        for subelement in get_child(element, tag):
            yield subelement

def get_child_text(parent, tag):
    child = list(get_child(parent, tag))
    assert child
    assert len(child) == 1
    child = child[0]
    return child.text

def print_rule_yml(element):
    cis_id = extract_rule_num(element.attrib['id'])
    title = get_child_text(element, 'title')
    description = get_child_text(element, 'description')
    description = textwrap.fill(description, width=79, subsequent_indent=' '*4)

    string = f"""
documentation_complete: true

prodtype: ubuntu2004

title: '{title}'

description: |-
    {description}

severity: medium

references:
    cis@ubuntu2004: {cis_id}
"""

    print(string)

def main():
    if len(sys.argv) != 3:
        print("Usage: extract_rule_yml.py /path/to/xccdf.xml some.rule_id")
        return

    xccdf_path = sys.argv[1]
    rule_id = sys.argv[2]

    xccdf = ET.parse(xccdf_path).getroot()

    if not rule_id.startswith("xccdf"):
        if rule_id.startswith("CIS"):
            rule_id = "xccdf_com.ubuntu.focal.cis_rule_" + rule_id
        else:
            rule_id = "xccdf_com.ubuntu.focal.cis_rule_CIS-" + rule_id

    entity = list(find_entity(xccdf, rule_id))
    assert entity
    assert len(entity) == 1
    entity = entity[0]
    print_rule_yml(entity)

if __name__ == "__main__":
    main()
