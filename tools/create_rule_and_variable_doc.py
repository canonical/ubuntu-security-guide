#!/usr/bin/python3
#
# Ubuntu Security Guides
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
import re
import logging
from pathlib import Path
import lxml.etree as etree
from typing import Dict, List

logger = logging.getLogger(__name__)

XMLNS = "http://checklists.nist.gov/xccdf/1.2"

class DocItem(object):
    def __init__(self, id: str, title: str | None = None, description: str | None = None):
        self.id = id
        self.title = title
        self.description = description

    def __hash__(self) -> int:
        return hash(self.id)  # Only id must be unique

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.id == other.id

    def __str__(self):
        return f'{ self.id }, { self.title }, { self.description }'


def _extract_data_from_datastream(datastream_path: Path, items_type: str) -> Dict[str, DocItem]:
    datastream_doc = None
    try:
        datastream_doc = etree.parse(datastream_path)
    except OSError:
        logger.error(f'Could not open datastream file { datastream_path }')
        sys.exit(1)
    except etree.XMLSyntaxError:
        logger.error(f'Could not parse datastream file { datastream_path }')
        sys.exit(1)

    item_dict = {}
    root = datastream_doc.getroot()
    if items_type == 'variables':
        Elems = root.findall('.//{%s}Value' % XMLNS)
    else:
        Elems = root.findall('.//{%s}Rule' % XMLNS)

    for Elem in Elems:
        if 'id' in Elem.keys():
            id_ = Elem.get('id')
            obj = DocItem(id_)
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
            item_dict[id_] = obj

    return item_dict

def generate_markdown_doc(datastream_path: Path, items_type: str) -> str:

    if items_type not in ['rules', 'variables']:
        raise ValueError('items_type must be either "rules" or "variables"')

    item_dict = _extract_data_from_datastream(datastream_path, items_type)

    md_escape = r"([<>_*\[\]#\\])"

    lines = []
    if items_type == 'variables':
        lines.append("# List of variables")
    else:
        lines.append("# List of rules")

    for it in item_dict.values():
        lines.append("## Rule id: %s" % re.sub(md_escape, r"\\\1", it.id))
        lines.append("### Title: %s" % re.sub(md_escape, r"\\\1", it.title))
        if it.description is not None and len(it.description) > 0 \
                and it.description[0] != '\n':
            extra_char = '\n'
        else:
            extra_char = ''
        lines.append((f"### Description:\n\n```{ extra_char }{ it.description }\n```\n"))
    return '\n'.join(lines)



def main(args: List[str]) -> None:
    usage = f'''
Script for generating markdown docs based on rule and variable metadata in the datastream file. 

Usage: {args[0]} [ rules | variables ] <datastream file path> <out file>
'''

    if len(args) != 4:
        print(usage)
        sys.exit(1)

    command = args[1]
    datastream_path = Path(args[2])
    out_path = Path(args[3])

    try:
        open(out_path, 'w').write(generate_markdown_doc(datastream_path, command))
        logger.info(f'Successfully wrote docs for {command} in {out_path}')
    except Exception as e:
        logger.error("Unknown exception:", e)
        sys.exit(1)

if "__main__" == __name__:
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format='%(levelname)s: %(message)s')
    main(sys.argv)
