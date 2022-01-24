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
Helper script to extract existing OVAL content from a single monolithic
file into smaller portions more suitable for the ComplianceAsCode/content
build system.
"""

import sys
import xml.etree.ElementTree as ET

def find_entity_with_reference(oval, ref):
    """
    Similar to find entity below, but finding a definition tag with a
    nested reference matching ref on it.
    """
    for element in oval:
        if 'definition' in element.tag:
            for subelement in element:
                if 'metadata' not in subelement.tag:
                    continue

                for subsubelement in subelement:
                    if 'reference' not in subsubelement.tag:
                        continue

                    if subsubelement.attrib['ref_id'] == ref:
                        yield element.attrib['id']

        for element_id in find_entity_with_reference(element, ref):
            yield element_id

def find_entity(oval, identifier):
    """
    There's probably a nice xpath we could use here, but I tried:
        oval.findall(f".//*[@id='{identifier}'|)
    but that didn't work.
    """
    for element in oval:
        if 'id' in element.attrib:
            if element.attrib['id'] == identifier:
                yield element

        for subelement in find_entity(element, identifier):
            yield subelement

def extract_references(element):
    """
    Assumption: Here we assume element itself has no _ref's on it. This
    seems valid as there are no currently matching cases.

    Again, probably a nice xpath we could use here instead.
    """
    for child in element:
        for attribute_key in child.attrib:
            if not attribute_key.endswith('_ref'):
                continue

            yield child.attrib[attribute_key]

        for reference in extract_references(child):
            yield reference

def resolve_entry_set(oval, entries):
    visited = set()
    queue = set(entries)

    while queue:
        entry = queue.pop()
        if entry in visited:
            continue

        element = list(find_entity(oval, entry))
        assert element
        assert len(element) == 1
        element = element[0]

        queue.update(set(extract_references(element)))

        visited.add(entry)

    return visited

def print_def_group(oval, entities):
    ET.register_namespace('', 'http://oval.mitre.org/XMLSchema/oval-definitions-5')
    ET.register_namespace('oval', 'http://oval.mitre.org/XMLSchema/oval-common-5')
    ET.register_namespace('ds', 'http://scap.nist.gov/schema/scap/source/1.2')
    ET.register_namespace('ocil', 'http://scap.nist.gov/schema/ocil/2.0')
    ET.register_namespace('xccdf-1.1', 'http://checklists.nist.gov/xccdf/1.1')
    ET.register_namespace('xccdf-1.2', 'http://checklists.nist.gov/xccdf/1.2')
    ET.register_namespace('xlink', 'http://www.w3.org/1999/xlink')
    ET.register_namespace('cpe-dict', 'http://cpe.mitre.org/dictionary/2.0')
    ET.register_namespace('cat', 'urn:oasis:names:tc:entity:xmlns:xml:catalog')
    ET.register_namespace('ind', 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent')
    ET.register_namespace('unix', 'http://oval.mitre.org/XMLSchema/oval-definitions-5#unix')
    ET.register_namespace('linux', 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux')
    root = ET.Element('def-group')
    for entity in entities:
        element = list(find_entity(oval, entity))[0]
        root.append(element)

    ET.dump(root)

def main():
    if len(sys.argv) != 3:
        print("Usage: extract_oval.py /path/to/oval.xml some.rule_id")
        return

    oval_path = sys.argv[1]
    rule_id = sys.argv[2]

    oval = ET.parse(oval_path).getroot()

    is_ref = list(find_entity_with_reference(oval, rule_id))
    if len(is_ref) > 1:
        print(is_ref)
        assert False
    elif len(is_ref) == 1:
        rule_id = is_ref[0]

    if not rule_id.startswith("oval"):
        if rule_id.startswith("def"):
            rule_id = "oval:com.ubuntu.focal.cis:" + rule_id
        else:
            rule_id = "oval:com.ubuntu.focal.cis:def:" + rule_id

    resolved = resolve_entry_set(oval, [rule_id])
    print_def_group(oval, sorted(resolved))

if __name__ == "__main__":
    main()
