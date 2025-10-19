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

import pytest
import importlib.resources

@pytest.fixture(scope="session")
def dummy_benchmarks():
    base_test_data_dir = importlib.resources.files("tools") / "tests/data"
    test_metadata_file = (
        base_test_data_dir / "ubuntu2404/expected/benchmarks/benchmarks.json"
    )
    return test_metadata_file
