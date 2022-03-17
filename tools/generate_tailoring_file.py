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

import ruamel.yaml
import re
import lxml.etree as etree
import sys

def search_comment(raw_yaml, linenum):
    result=None
    while result == None:
        assert(linenum >= 0)
        result=search_comment.prog.match(raw_yaml[linenum])
        if result:
            return raw_yaml[linenum]
        else:
            linenum -= 1
search_comment.prog = re.compile("^\s*#+\s*((?:\d+\.)*\d+\.?|UBTU-.*)\s+")

def process_comment(s):
    # Remove newline chars and the shebang
    return s.strip(' \n#')

def print_xml_comment(comment, add_line_before):
    ret_buf = ""
    if add_line_before:
        ret_buf += "\n"
    ret_buf += f"<!-- { comment } -->\n"
    return ret_buf

def process_var(doc, var, val):
    root = doc.getroot()
    for xmlVal in root.findall(".//{http://checklists.nist.gov/xccdf/1.1}Value"):
        if xmlVal.get('id') == var:
            for xmlval in xmlVal.findall(".//{http://checklists.nist.gov/xccdf/1.1}value"):
                if xmlval.get('selector') == val:
                    return (None, xmlval.text)

    return (Exception("No value found for variable { var }!"), None)

def print_xml_var(err, var, pval):
    if err != None:
        str_err = str(err)
        print(f"<!-- Could not extract value from variable { var } ! Error: { str_err } -->")
    else:
        return f'<xccdf:set-value idref="{ var }">{ pval }</xccdf:set-value>\n'

# If the raw rule name contains a '!' character, returns the name without it and return flag select as False
def process_rule(rule):
    if rule.startswith("!"):
        return (rule.lstrip('!'), False)
    return (rule, True)

def print_xml_rule(rule, is_selected):
    return f'<xccdf:select idref="{ rule }" selected="' + str(is_selected).lower() + '"/>\n'

def create_tailoring_file(parsed_yaml, raw_yaml, xccdf_doc):
    yaml_sel=parsed_yaml["selections"]
    prog=re.compile('^([^=]+)=(.*)$') # Regexp to fetch variable lines
    prev_linenum=-1
    ret_buf = []
    for i in range(len(yaml_sel)):
        ret_item = ""
        linenum=yaml_sel.lc.data[i][0]
        # If it's the first linenum of a block, get the comment
        if prev_linenum != (linenum - 1):
            comment_line = search_comment(raw_yaml, linenum - 1) # Start searching the previous line
            pc = process_comment(comment_line)
            if prev_linenum != -1:
                ret_item += print_xml_comment(pc, True)
            else: # First line doesn't need spaces
                ret_item += print_xml_comment(pc, False)

        # Now line can be a variable assignment or a rule line
        result=prog.match(yaml_sel[i])

        if result:
            # Real value must be extract from XCCDF file
            var = result.group(1)
            val = result.group(2)
            err, pval = process_var(xccdf_doc, var, val)
            ret_item += print_xml_var(err, var, pval)
        else:
            prule, is_selected = process_rule(yaml_sel[i])
            ret_item += print_xml_rule(prule, is_selected)

        prev_linenum=linenum
        re_match = re.search('^[\n]?<!-- (.+?) ', ret_item)
        if re_match is not None:
            ret_buf.append(ret_item)
        else:
            ret_buf[len(ret_buf)-1] += ret_item

    return ret_buf

def process_profile_file(yaml_path):
    parsed_yaml=None
    raw_yaml=None
    try:
        with open(yaml_path, 'r') as yaml_file:
            parsed_yaml=ruamel.yaml.round_trip_load(yaml_file)
            yaml_file.seek(0)
            raw_yaml=yaml_file.readlines()

    except OSError as err:
        print("Could not open profile file", file=sys.stderr)
        sys.exit(1)

    return raw_yaml,parsed_yaml

def merge_tailoring_data(extended_data, parent_data):
    extended_data_rules = []
    # Gather the changed rules in the extended profile.
    for i in range(len(extended_data)):
        re_match = re.search('^[\n]?<!-- (.+?) ', extended_data[i])
        if re_match is not None:
            extended_data_rules.append(re_match.group(1))

    if len(extended_data) != len(extended_data_rules):
        print("Error merging tailoring data: rule array lengths are different.", file=sys.stderr)
        sys.exit(1)

    # Replace any changed rules in the parent profile.
    for i in range(len(parent_data)):
        current_rule = re.search('^[\n]?<!-- (.+?) ', parent_data[i]).group(1)
        if current_rule in extended_data_rules:
            # extended_data and extended_data_rules should align. This assumes that.
            parent_data[i] = extended_data[extended_data_rules.index(current_rule)]

    return parent_data

def print_tailoring_array(tailoring_data):
    for i in range(len(tailoring_data)):
        print(tailoring_data[i])

USAGE = f"Usage: python {sys.argv[0]} <Profile file path> <XCCDF file path>"
if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(USAGE, file=sys.stderr)
        sys.exit(1)

    yaml_path = sys.argv[1]
    xccdf_path = sys.argv[2]

    raw_yaml, parsed_yaml = process_profile_file(yaml_path)

    xccdf_doc = None
    try:
        xccdf_doc = etree.parse(xccdf_path)
    except etree.XMLSyntaxError as err:
        print("Could not process XCCDF file", file=sys.stderr)
        sys.exit(1)

    tailoring_data = create_tailoring_file(parsed_yaml, raw_yaml, xccdf_doc)

    if "extends" in parsed_yaml:
        parent_yaml_path = yaml_path.rsplit(sep="/", maxsplit=1)[0] + "/" + parsed_yaml["extends"] + ".profile"
        parent_raw_yaml, parent_parsed_yaml = process_profile_file(parent_yaml_path)
        parent_tailoring_data = create_tailoring_file(parent_parsed_yaml, parent_raw_yaml, xccdf_doc)
        tailoring_data = merge_tailoring_data(tailoring_data, parent_tailoring_data)

    print_tailoring_array(tailoring_data)


    sys.exit(0)
