#!/usr/bin/env python3
#
# Ubuntu Security Guide
# Copyright (C) 2025 Canonical Ltd.
#
# SPDX-License-Identifier: GPL-3.0-only
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see http://www.gnu.org/licenses/.

"""Functions for populating rule and variable markdown files."""
import sys

if sys.version_info < (3,12):
    sys.exit("Build tools require Python>=3.12")

import logging
import re
from pathlib import Path

from lxml import etree

logger = logging.getLogger(__name__)

XMLNS = "http://checklists.nist.gov/xccdf/1.2"


class DocItem:
    """Representation of single item (rule, var) in document."""

    def __init__(
        self, _id: str, title: str | None = None, description: str | None = None
    ) -> None:
        """Initialize DocItem."""
        self.id = _id
        self.title = title
        self.description = description

    def __hash__(self) -> int:
        """Return hash based only on ID attribute."""
        return hash(self.id)  # Only id must be unique

    def __eq__(self, other: object) -> bool:
        """Check if ID attribute of element matches."""
        if not isinstance(other, type(self)):
            return NotImplemented
        return self.id == other.id

    def __str__(self) -> str:
        """Return string representation of DocItem."""
        return f"{self.id}, {self.title}, {self.description}"


def _extract_data_from_datastream(
    datastream_path: Path, items_type: str
) -> dict[str, DocItem]:
    datastream_doc = None
    try:
        datastream_doc = etree.parse(datastream_path)
    except OSError:
        logger.error(f"Could not open datastream file {datastream_path}")
        sys.exit(1)
    except etree.XMLSyntaxError:
        logger.error(f"Could not parse datastream file {datastream_path}")
        sys.exit(1)

    item_dict = {}
    root = datastream_doc.getroot()
    if items_type == "variables":
        elements = root.findall(f".//{{{XMLNS}}}Value")
    else:
        elements = root.findall(f".//{{{XMLNS}}}Rule")

    for element in elements:
        if "id" in element.keys():
            id_ = element.get("id")
            obj = DocItem(id_)
            for element_child in element.getchildren():
                if "title" in element_child.tag:
                    obj.title = element_child.text
                if "description" in element_child.tag:
                    desc = ""
                    for desc_elements in element_child.xpath("*|text()"):
                        if isinstance(desc_elements, etree._Element):
                            # Some text has HTML elements inside,
                            # which must be handled
                            if desc_elements.text is not None:
                                desc += desc_elements.text
                        else:
                            desc += str(desc_elements)
                    obj.description = desc
            item_dict[id_] = obj

    return item_dict


def generate_markdown_doc(datastream_path: Path, items_type: str) -> str:
    """Generate markdown document describing rules and variables in SCAP datastream.

    Args:
        datastream_path: path to SCAP datastream file
        items_type: type of items to extract (rules, variables)

    Returns:
        markdown document in string format

    """
    if items_type not in ["rules", "variables"]:
        raise ValueError('items_type must be either "rules" or "variables"')

    item_dict = _extract_data_from_datastream(datastream_path, items_type)

    md_escape = r"([<>_*\[\]#\\])"

    lines = []
    if items_type == "variables":
        lines.append("# List of variables")
    else:
        lines.append("# List of rules")

    for it in item_dict.values():
        rule_escaped = re.sub(md_escape, r"\\\1", it.id)
        title_escaped = re.sub(md_escape, r"\\\1", it.title)
        lines.append(f"## Rule id: {rule_escaped}")
        lines.append(f"### Title: {title_escaped}")
        if (
            it.description is not None
            and len(it.description) > 0
            and it.description[0] != "\n"
        ):
            extra_char = "\n"
        else:
            extra_char = ""
        lines.append(f"### Description:\n\n```{extra_char}{it.description}\n```\n")
    return "\n".join(lines)


def main(args: list[str]) -> None:
    """CLI entry point."""
    usage = f"""
Script for generating markdown docs based on rule and variable metadata in the datastream file.

Usage: {args[0]} [ rules | variables ] <datastream file path> <out file>
"""

    if len(args) != 4:
        print(usage)
        sys.exit(1)

    command = args[1]
    datastream_path = Path(args[2])
    out_path = Path(args[3])

    try:
        out_path.open("w").write(generate_markdown_doc(datastream_path, command))
        logger.info(f"Successfully wrote docs for {command} in {out_path}")
    except Exception as e:
        logger.exception(f"Unknown exception: {e}")
        sys.exit(1)

if __name__ == "__main__":
    logging.basicConfig(
        stream=sys.stdout, level=logging.DEBUG, format="%(levelname)s: %(message)s"
    )
    main(sys.argv[1:])
