#!/usr/bin/python3
#
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

import lxml.etree as etree
import ruamel.yaml as yaml
import os.path as path
import re
import sys

XMLNS = "http://checklists.nist.gov/xccdf/1.2"


class DocItem(object):
    def __init__(self, id, title=None, description=None):
        self.id = id
        self.title = title
        self.description = description

    def __hash__(self):
        return hash(id)  # Only id must be unique

    def __eq__(self, other):
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.id == other.id

    def __str__(self):
        return f'{ self.id }, { self.title }, { self.description }'


def create_item_dict_using_profiles(profile_path_list, is_variable=False):
    prog = re.compile('^([^=]+)=.*$')  # Regexp to fetch variable lines
    item_dict = dict()

    for yaml_path in profile_path_list:
        try:
            with open(yaml_path, 'r') as yaml_file:
                parsed_yaml = yaml.safe_load(yaml_file)
        except OSError:
            print(f'Could not open profile file { yaml_path }',
                  file=sys.stderr)
            sys.exit(1)
        except YAMLError:
            print(f'Could not parse profile file { yaml_path }',
                  file=sys.stderr)
            sys.exit(1)

        if 'selections' not in parsed_yaml.keys():
            print(f'Missing key \'selections\' in profile', file=sys.stderr)
            sys.exit(1)

        # Create new object with id and add it to the set.
        for id in parsed_yaml["selections"]:
            # Now line can be a variable assignment or a rule line
            result = prog.match(id)
            if result and is_variable:
                # Remove everything just before the = sign.
                # Including the = sign
                id = result.group(1)
                id = 'xccdf_org.ssgproject.content_value_' + id
                item_dict[id] = DocItem(id)
            elif (result is None) and not is_variable:
                # Remove leftmost '!' before adding to dict
                id = id.lstrip('!')
                id = 'xccdf_org.ssgproject.content_rule_' + id
                item_dict[id] = DocItem(id)

    return item_dict


def fill_item_dict_using_xccdf(xccdf_path, item_dict, is_variable=False):
    xccdf_doc = None

    try:
        xccdf_doc = etree.parse(xccdf_path)
    except OSError:
        print(f'Could not open XCCDF file { xccdf_path }', file=sys.stderr)
        sys.exit(1)
    except XMLSyntaxError:
        print(f'Could not parse XCCDF file { xccdf_path }', file=sys.stderr)
        sys.exit(1)

    print('Successfully parsed xccdf file', file=sys.stderr)

    root = xccdf_doc.getroot()
    if is_variable:
        Elems = root.findall('.//{%s}Value' % XMLNS)
    else:
        Elems = root.findall('.//{%s}Rule' % XMLNS)

    for Elem in Elems:
        if 'id' in Elem.keys() and Elem.get('id') in item_dict:
            obj = item_dict[Elem.get('id')]
            for Elemchild in Elem.getchildren():
                if ('title' in Elemchild.tag):
                    obj.title = Elemchild.text
                if ('description' in Elemchild.tag):
                    desc = ''
                    for elems in Elemchild.xpath('*|text()'):
                        if isinstance(elems, etree._Element):
                            # Some text has HTML elements inside,
                            # which must be handled
                            if elems.text is not None:
                                desc += elems.text
                        else:
                            desc += str(elems)
                    obj.description = desc


def markdown_output(item_dict, is_variable=False):
    md_escape = r"([<>_*\[\]#\\])"
    if is_variable:
        print("# List of variables")
    else:
        print("# List of rules")

    for it in item_dict.values():
        print(f"## Rule id: %s" % re.sub(md_escape, r"\\\1", it.id))
        print(f"### Title: %s" % re.sub(md_escape, r"\\\1", it.title))
        if it.description is not None and len(it.description) > 0 \
                and it.description[0] != '\n':
            extra_char = '\n'
        else:
            extra_char = ''
        print(f"### Description:\n\n```{ extra_char }{ it.description }\n```\n")


def main(args):
    profiles = ['cis_level1_server.profile',
                'cis_level2_server.profile',
                'cis_level1_workstation.profile',
                'cis_level2_workstation.profile',
                'stig.profile']
    usage = f'Usage: {args[0]} [ rules | variables ] <profile path> <xccdf file path>'

    if len(args) != 4:
        print(usage, file=sys.stderr)
        sys.exit(1)

    command = args[1]
    profile_path = args[2]
    xccdf_path = args[3]

    is_variable = False
    if command == 'variables':
        is_variable = True
    elif command != 'rules':
        print(usage, file=sys.stderr)
        sys.exit(1)

    profile_paths = []
    for p in profiles:
        ppath = path.join(profile_path, p)
        if path.exists(ppath):
            profile_paths.append(ppath)

    item_dict = create_item_dict_using_profiles(profile_paths, is_variable)
    fill_item_dict_using_xccdf(xccdf_path, item_dict, is_variable)
    markdown_output(item_dict, is_variable)


if "__main__" == __name__:
    main(sys.argv)
