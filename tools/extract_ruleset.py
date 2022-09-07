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
Helper script to extract rule numbers by profile from an XCCDF file
"""

from lxml.etree import ElementTree as ET

import sys
import textwrap

PROFILE_ID_TO_NAME = {
    'Level_1_Server': 'lvl1_server',
    'Level_2_Server': 'lvl2_server',
    'Level_1_Workstation': 'lvl1_workstation',
    'Level_2_Workstation': 'lvl2_workstation',
}

PROFILE_NAME_TO_ID = {v: k for k, v in PROFILE_ID_TO_NAME.items()}

PROFILE_ORDER = ['Level_1_Server', 'Level_2_Server',
                 'Level_1_Workstation', 'Level_2_Workstation']

MANUAL_RULES = {
    'common': {'1.1.19', '1.1.20', '1.1.21', '1.2.1', '1.2.2', '1.9',
               '2.2.1.2', '2.4', '3.5.1.5', '3.5.1.6', '3.5.2.3',
               '3.5.2.7', '3.5.3.2.3', '3.5.3.3.3', '3.5.3.3.4',
               '4.2.1.3', '4.2.1.6', '4.3', '5.5', '6.1.13', '6.1.14'},
    'Level_1_Server': set(),
    'Level_2_Server': {'1.1.1.7', '3.1.1', '6.1.1'},
    'Level_1_Workstation': set(),
    'Level_2_Workstation': {'1.1.1.7', '3.1.1', '6.1.1'},
}


def hack_is_element(element, needle):
    tag = element.tag.lower()
    return tag.endswith("}" + needle) or tag == needle


def clean_id(identifier, substr):
    assert substr in identifier
    index = identifier.index(substr)
    return identifier[index + len(substr):]


def clean_profile_id(profile_id):
    return clean_id(profile_id, '_profile_')


def clean_rule_id(rule_id):
    return clean_id(rule_id, '_CIS-')


def extract_rules(root):
    results = dict()
    common = None
    for profile in root:
        if not hack_is_element(profile, "profile"):
            continue
        profile_id = clean_profile_id(profile.attrib['id'])

        results[profile_id] = set()
        results[profile_id].update(MANUAL_RULES['common'])
        results[profile_id].update(MANUAL_RULES[profile_id])
        for select in profile:
            if not hack_is_element(select, "select"):
                continue
            rule_id = clean_rule_id(select.attrib['idref'])
            if not select.attrib['selected'] == "true":
                print(f"Found non-selected rule in profile: {rule_id} in {profile_id}")
                continue

            results[profile_id].add(rule_id)

        if common is None:
            common = results[profile_id]
        else:
            common = common.intersection(results[profile_id])

    results['common'] = common
    return results


def rule_to_int(section):
    # Hack: convert nested section number into an integer in the correct
    # order numerically. We use descending powers of 10 to accomplish this
    # magic. Note that we skip every other power in order to support 2-digit
    # section numbers (e.g., 1.10 -> 110 not 20).
    return sum([int(x)*10**(14-2*i) for i, x in enumerate(section.split('.'))])


def join_rules(rules):
    return ' '.join(sorted(rules, key=rule_to_int))


def pretty_print_readme(profile_rule_mapping):
    for profile_id in PROFILE_ORDER:
        profile_name = PROFILE_ID_TO_NAME[profile_id]
        print(f"\n# {profile_name} lists\n")
        for benchmark_section in map(str, range(1, 7)):
            filtered = filter_by_section(profile_rule_mapping,
                                         benchmark_section)
            joined_rules = join_rules(filtered[profile_id])
            line = f"ruleset{benchmark_section}=\"{joined_rules}\""
            line = textwrap.fill(line, width=79, subsequent_indent=' '*10)
            print(f"{line}\n")


def filter_by_section(profile_rule_mapping, section_id):
    results = {}
    for profile in profile_rule_mapping:
        results[profile] = set(filter(lambda x: x.startswith(section_id + "."),
                                      profile_rule_mapping[profile]))
    return results


def pretty_print_bash_section(profile_rule_mapping):
    common_joined = join_rules(profile_rule_mapping['common'])
    common_line = f"    local common=\"{common_joined}\""
    common_line = "\\\n".join(textwrap.wrap(common_line,
                                            width=78,
                                            subsequent_indent=' '*8))
    print(f"{common_line}")
    for profile_id in PROFILE_ORDER:
        profile_name = PROFILE_ID_TO_NAME[profile_id]
        ref = "$common"
        basis = profile_rule_mapping['common']
        if profile_name.startswith("lvl2_"):
            lvl1_name = "lvl1_" + profile_name[5:]
            lvl1_id = PROFILE_NAME_TO_ID[lvl1_name]
            ref = "${rulehash[" + lvl1_name + "]}"
            basis = profile_rule_mapping[lvl1_id]
        joined_rules = join_rules(
            profile_rule_mapping[profile_id].difference(basis))
        line = f"    rulehash[{profile_name}]=\"{ref}\""
        if joined_rules:
            line += f"\" {joined_rules}\""
        line = "\\\n".join(textwrap.wrap(line,
                                         width=78,
                                         subsequent_indent=' '*8))
        print(f"{line}")


def pretty_print_bash(profile_rule_mapping):
    for benchmark_section in map(str, range(1, 7)):
        print(f"\nruleset-{benchmark_section}.sh:\n")
        filtered = filter_by_section(profile_rule_mapping, benchmark_section)
        pretty_print_bash_section(filtered)


def main():
    if len(sys.argv) != 2:
        print("Usage: extract_ruleset.py /path/to/xccdf.xml")
        return

    xccdf_path = sys.argv[1]

    xccdf = ET.parse(xccdf_path).getroot()
    profile_rule_mapping = extract_rules(xccdf)
    print("==README==")
    pretty_print_readme(profile_rule_mapping)

    print("\n\n\n==Bash==")
    pretty_print_bash(profile_rule_mapping)


if __name__ == "__main__":
    main()
