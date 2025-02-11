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

function cleanup() {
    rm -rf "${usg_path:?}/"*
    rm -rf "${tailoring_path:?}/"*.xml
    rm -rf "${doc_path:?}/man7/"*.md
    rm -rf "${doc_path:?}/man8/"*.md
}

USAGE="$0 <path to CaC project> <target> <path to usg package source>"
if [ $# -ne 3 ]; then
    echo "$USAGE"
    exit 1
fi

cac_path="$1/build"
target="$2"
usg_path="$3/benchmarks"
tailoring_path="$3/tailoring"
doc_path="$3/doc"

cleanup

usg_sce_path="${usg_path}/$target/checks/sce"
mkdir -p "${usg_sce_path}"

# Copy XCCDF, OVAL, ocil and CPE dictionary files
# The XCCDF and CPE files must have their name changed
cp "${cac_path}/ssg-$target-xccdf.xml" "${usg_path}"
cp "${cac_path}/ssg-$target-cpe-dictionary.xml" "${usg_path}"
cp "${cac_path}/ssg-$target-oval.xml" "${usg_path}"
cp "${cac_path}/ssg-$target-ocil.xml" "${usg_path}"
cp "${cac_path}/ssg-$target-cpe-oval.xml" "${usg_path}"
cp "${cac_path}/ssg-$target-ds.xml" "${usg_path}"

# Copy the license file
cp "$(dirname "${cac_path}")/LICENSE" "${usg_path}/ComplianceAsCode-LICENSE"

# Copy the SCE check scripts
cp "${cac_path}"/"$target"/checks/sce/*.sh "${usg_sce_path}"

# Chmod the bash scripts
chmod u+x "${usg_sce_path}"/*.sh

echo "Directories prepared. Now run the build command"
exit 0
