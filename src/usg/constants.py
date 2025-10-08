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

"""Default config options, paths, etc."""

from pathlib import Path

from usg.version import __version__

# Default tailoring file location
DEFAULT_TAILORING_PATH = Path("/etc/usg/default-tailoring.xml")

# CLI configurable options
CLI_LOG_FILE = "/var/log/usg.log"
DEFAULT_FIX_ONLY_FAILED = False

# Openscap backend options
# {DATE} and {PROFILE_ID} are placeholders which are replaced at runtime
# (main purpose is to ensure backwards compatilibity)
OPENSCAP_REPORT_FILE = "usg-report-{DATE}.html"
OPENSCAP_RESULTS_FILE = "usg-results-{DATE}.xml"
OPENSCAP_LOG_FILE = "usg-log-{DATE}.log"
OPENSCAP_FIX_FILE = "{PROFILE_ID}-{DATE}.sh"
OPENSCAP_OVAL_RESULTS_FILE = "ssg-{PRODUCT}-oval.xml.result-{DATE}.xml"
OPENSCAP_OVAL_CPE_RESULTS_FILE = "ssg-{PRODUCT}-cpe-oval.xml.result-{DATE}.xml"
OPENSCAP_SAVE_OVAL_RESULTS = False

# Paths for sensitive data are hardcoded to system paths
CONFIG_PATH = Path("/etc/usg.conf")
BENCHMARK_METADATA_PATH = Path("/usr/share/usg-benchmarks/benchmarks.json")
BENCHMARK_PKG = "usg-benchmarks"
STATE_DIR = Path("/var/lib/usg")
CLI_STATE_FILE = STATE_DIR / ".state.json"
OPENSCAP_BIN_PATH = Path("/usr/bin/oscap")
LOCK_PATH = Path("/run/lock/usg.lock")

# Set default benchmark product based on USG version (e.g. ubuntu2404)
DEFAULT_PRODUCT = f"ubuntu{__version__[:2]}04"
