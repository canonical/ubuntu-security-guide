#!/bin/bash
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


# project, source, data dirs
SCRIPT_DIR=$(dirname $(readlink -f "${BASH_SOURCE[0]}"))
PROJECT_DIR=${SCRIPT_DIR}/..
TEST_RELEASES="jammy"

source ${SCRIPT_DIR}/run_container.sh

rc_sum=0
for release in $TEST_RELEASES; do
    echo "**** Initializing testbed for $release ****"
    build_container $release

    echo "Running pytest on $release"
    if [[ $release == "noble" ]]; then
        test_dirs="tests/ tools/tests/"
    else
        test_dirs="tests/"
    fi
    run_cmd bash -c "PYTHONPATH=/usr/share/usg/ python3 -m pytest -vvv $test_dirs"
    rc_sum=$(( $rc_sum + $? ))

    echo "Running e2e tests on $release"
    run_cmd bash debian/tests/usg-cli-e2e
    rc_sum=$(( $rc_sum + $? ))
done

if [[ $rc_sum -ne 0 ]]; then
    echo "FAIL: At least one test failed" >&2
    exit 1
else
    echo "OK: All tests passed"
    exit 0
fi
