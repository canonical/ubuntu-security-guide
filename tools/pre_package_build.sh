#!/bin/bash
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

USAGE="$0 <path to CaC project> <path to usg package source>"
if [ $# -ne 2 ]; then
    echo $USAGE
    exit 1
fi

cac_path="$1/build"
usg_path="$2/benchmarks"
usg_doc_path="$2/doc"

usg_sce_path="${usg_path}/ubuntu2004/checks/sce"

# Copy XCCDF, OVAL, ocil and CPE dictionary files
# The XCCDF and CPE files must have their name changed
cp "${cac_path}/ssg-ubuntu2004-xccdf.xml" "${usg_path}/Canonical_Ubuntu_20.04_Benchmarks-xccdf.xml"
cp "${cac_path}/ssg-ubuntu2004-xccdf-1.2.xml" "${usg_path}/Canonical_Ubuntu_20.04_Benchmarks-xccdf-1.2.xml"
cp "${cac_path}/ssg-ubuntu2004-cpe-dictionary.xml" "${usg_path}/Canonical_Ubuntu_20.04_Benchmarks-cpe-dictionary.xml"
cp "${cac_path}/ssg-ubuntu2004-oval.xml" "${usg_path}"
cp "${cac_path}/ssg-ubuntu2004-ocil.xml" "${usg_path}"
cp "${cac_path}/ssg-ubuntu2004-cpe-oval.xml" "${usg_path}"

# Copy the license file
cp $(dirname "${cac_path}")/LICENSE "${usg_path}"

# Copy the SCE check scripts
cp "${cac_path}"/ubuntu2004/checks/sce/*.sh "${usg_sce_path}"

# Chmod the bash scripts
chmod u+x "${usg_sce_path}"/*.sh

echo "Directories prepared. Now run the build command"
exit 0
