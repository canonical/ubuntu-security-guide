"""Default config options, paths, etc."""

from pathlib import Path

# Default tailoring file location (deprecated)
DEFAULT_TAILORING_PATH = Path("/etc/usg/default-tailoring.xml")

# CLI configurable options
CLI_LOG_FILE = "/var/log/usg.log"
DEFAULT_PRODUCT = "ubuntu2404"
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
CLI_STATE_FILE = STATE_DIR / "state.json"
OPENSCAP_BIN_PATH = Path("/usr/bin/oscap")
LOCK_PATH = Path("/run/lock/usg.lock")
