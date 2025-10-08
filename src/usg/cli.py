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

"""Command line interface for USG."""

import argparse
import configparser
import datetime
import json
import logging
import os
import sys
import tempfile
import time
from pathlib import Path

from usg import constants
from usg.config import load_config, override_config_with_cli_args
from usg.exceptions import LockError, ProfileNotFoundError, StateFileError, USGError
from usg.models import Benchmark, Profile, TailoringFile
from usg.usg import USG
from usg.utils import acquire_lock, check_perms
from usg.version import __version__

logger = logging.getLogger(__name__)

# Add leading zero (removed by python packaging)
# to be consistent with usg package versioning
DISPLAY_VERSION = __version__.replace(".4.", ".04.")

# shared format strings
CLI_LIST_FORMAT = "{:35s}{:30s}{:s}"
CLI_INFO_FORMAT = "{:25s}{:s}"

# CLI help descriptions and usage
# keep descriptions as close to original bash USG as possible
EPILOG_COMMON = """\
Unless the `--tailoring-file` flag is provided, a profile must be given.
"""

CMD_LIST_HELP = {
    "description": "Lists available profiles.",
    "epilog": "",
}

CMD_INFO_HELP = {
    "description": """\
The info command prints out metadata on specific profile or tailoring file.
""",
    "epilog": EPILOG_COMMON,
}

CMD_AUDIT_HELP = {
    "description": """\
The audit command relies on the oscap command and the USG XCCDF and
OVAL files to audit the system, verifying if the system is compliant
with either a provided profile or a provided tailoring file.
""",
    "epilog": EPILOG_COMMON + """
Examples:
$ usg audit cis_level1_server
$ usg audit -t tailoring.xml --html-file report.html --results-file result.xml
"""
}

CMD_FIX_HELP = {
    "description": """\
The fix command relies on the oscap command, the XCCDF and OVAL files
to audit the system and then fix all the rules associated with either
a provided profile or a provided tailoring file.

The optional flag `--only-failed` can be used to avoid fixing all the rules,
but to fix only the rules which are marked as Failed during the initial audit.
Note that due to rule dependencies, the command might need to be rerun
for all rules to be fixed correctly.
""",
    "epilog": EPILOG_COMMON + """
Examples:
$ usg fix cis_level1_server
$ usg fix -t tailoring.xml --only-failed
"""
}

CMD_GENERATE_FIX_HELP = {
    "description": """\
The generate-fix command relies on the oscap command, the XCCDF and
OVAL files to create a bash script file containing all the fixes
associated with either a provided profile or a provided tailoring file.
""",
    "epilog": EPILOG_COMMON + """
Examples:
$ usg generate-fix cis_level1_server
$ usg generate-fix -t tailoring.xml
"""
}

CMD_GENERATE_TAILORING_HELP = {
    "description": f"""\
The generate-tailoring command creates a tailoring file based on the
provide profile and saves it to the provided output path. To make this
tailoring file the default save it as {constants.DEFAULT_TAILORING_PATH}

This command requires a profile upon which the tailoring file will be created.
All rules present in the base profile will also be present in the tailoring file.
""",
    "epilog": """
Examples:
$ usg generate-fix cis_level1_server -o fix.sh
$ usg generate-fix -t tailoring.xml -o fix.sh
"""
}


CLI_CMD_HELP = {
    "list": CMD_LIST_HELP,
    "info": CMD_INFO_HELP,
    "audit": CMD_AUDIT_HELP,
    "fix": CMD_FIX_HELP,
    "generate-fix": CMD_GENERATE_FIX_HELP,
    "generate-tailoring": CMD_GENERATE_TAILORING_HELP,
}


CLI_USG_HELP = {
    "description": """\
Available commands are:
    list                Lists available profiles
    audit               Audits the current system
    fix                 Audits and attempts to fix failed rules
    generate-fix        Creates a bash script containing the fixes
    generate-tailoring  Create a tailoring file based on a profile
    info                Shows info on profile/tailoring file
""",
    "epilog": """\
Use usg <command> --help for more information about a command.
""",
}

def error_exit(msg: str = "", rc: int = 1) -> None:
    """Write msg to standard error and exit with return code rc."""
    if msg:
        sys.stderr.write(msg)
        sys.stderr.write("\n")
    sys.exit(rc)


def command_list(usg: USG, args: argparse.Namespace) -> None:
    """List available profiles."""
    logger.debug("Starting command_list")
    if not args.machine_readable:
        print("Listing available profiles...\n")
        print(CLI_LIST_FORMAT.format("PROFILE", "BENCHMARK/PRODUCT", "VERSION"))

    profiles = [p for b in usg.benchmarks.values() for p in b.profiles.values()]
    for p in sorted(profiles, key=lambda p: p.profile_id):
        benchmark = usg.get_benchmark_by_id(p.benchmark_id)
        latest = benchmark.is_latest
        if not latest and not args.all:
            continue

        if args.machine_readable:
            print(":".join([  # noqa: FLY002
                p.profile_id,
                benchmark.benchmark_type,
                benchmark.product,
                benchmark.version,
                p.benchmark_id,
                "", "", "", "", "", "" # reserved
                ]))

        else:
            depr = "" if latest else " *deprecated*"
            print(
                CLI_LIST_FORMAT.format(
                    p.profile_id,
                    f"{benchmark.benchmark_type}/{benchmark.product}",
                    benchmark.version + depr,
                )
            )
    if not args.machine_readable:
        print("""

Use 'usg info' to print information about a specific profile or tailoring file:

$ usg info cis_level1_server
$ usg info -t my_tailoring.xml
""")
    logger.debug("Finished command_list")


def command_info(usg: USG, args: argparse.Namespace) -> None:
    """Print info about a specific profile or tailoring file."""
    logger.debug("Starting command_info")
    if hasattr(args, "tailoring_file"):
        tailoring = usg.load_tailoring(args.tailoring_file)
        print_info_tailoring(tailoring)
        usg_profile = tailoring.profile
    else:
        benchmark_version = load_benchmark_version_state(args.profile)
        if hasattr(args, "benchmark_version"):
            benchmark_version = args.benchmark_version
        try:
            usg_profile = usg.get_profile(
                args.profile, args.product, benchmark_version
            )
        except ProfileNotFoundError as e:
            error_exit(f"{e}\nSee `usg list --all` for list of available profiles.", rc=1)
    print_info_profile(usg_profile)
    print_info_benchmark(usg.get_benchmark_by_id(usg_profile.benchmark_id))
    logger.debug("Finished command_info")


def print_info_tailoring(tailoring: TailoringFile) -> None:
    """Print info about tailoring file."""
    print()
    for k, v in [
        ("Tailoring file", str(tailoring.tailoring_file.resolve())),
    ]:
        print(CLI_INFO_FORMAT.format(k, v))


def print_info_profile(profile: Profile) -> None:
    """Print info about profile."""
    print()
    for k, v in [("Profile name", profile.profile_id)]:
        print(CLI_INFO_FORMAT.format(k, v))


def print_info_benchmark(benchmark: Benchmark) -> None:
    """Print info about benchmark."""
    profiles = "\n".join([f"- {p.profile_id}" for p in benchmark.profiles.values()])

    upgrade_path = ", ".join(benchmark.breaking_upgrade_path)
    upgrade_path = upgrade_path or "None (latest)"

    compatible_versions = ", ".join(benchmark.compatible_versions)
    compatible_versions = compatible_versions or "None"

    if benchmark.is_latest:
        state = "Latest stable"
    else:
        state = "** Deprecated (see information below)**"

    release_date = datetime.datetime.fromtimestamp(
        benchmark.release_timestamp,
        datetime.timezone.utc
        ).isoformat()
    for k, v in [
        ("Benchmark", benchmark.benchmark_type),
        ("Target product", benchmark.product_long),
        ("Version", benchmark.version),
        ("Compatible with", compatible_versions),
        ("State", state),
        ("Upgrade candidates", upgrade_path),
        ("Description", benchmark.description.strip()),
        ("Release date", release_date),
        ("Release notes", benchmark.release_notes_url),
        ("USG benchmark ID", benchmark.id),
        ("Reference", benchmark.reference_url),
    ]:
        print(CLI_INFO_FORMAT.format(k, v))
    print(
        f"""

Available profiles:
{profiles}
"""
    )

    if not benchmark.is_latest:
        latest_version = benchmark.breaking_upgrade_path[-1]
        print(f"""
Note:
This benchmark version is no longer supported. To upgrade to the latest version use the flag
'--benchmark-version {latest_version}' when running 'audit,fix,generate-fix' commands.
If using a tailoring file, create a new file with 'usg generate-tailoring --benchmark-version {latest_version}.
""")  # noqa: E501


def command_generate_tailoring(usg: USG, args: argparse.Namespace) -> None:
    """Generate a tailoring file and writes it to disk."""
    logger.debug("Starting command_generate_tailoring")
    usg_profile = get_usg_profile_from_args(usg, args)
    print(
        f"USG will extract the tailoring file for profile "
        f"'{usg_profile.profile_id}' to '{args.output}'."
    )
    contents = usg.generate_tailoring(usg_profile)
    try:
        with Path(args.output).open("w") as f:
            f.write(contents)
    except OSError as e:
        error_exit(f"Failed to write file {args.output}: {e}")
    else:
        print("USG generate-tailoring command completed.")
    logger.debug("Finished command_generate_tailoring")


def command_generate_fix(usg: USG, args: argparse.Namespace) -> None:
    """Process args for generate-fix command and runs usg."""
    logger.debug("Starting command_generate_fix")
    usg_profile = get_usg_profile_from_args(usg, args)
    artifacts = usg.generate_fix(usg_profile)
    print(f"Wrote remediation script to '{artifacts.get_by_type('fix_script').path}'")
    logger.debug("Finished command_generate_fix")


def command_fix(usg: USG, args: argparse.Namespace) -> None:
    """Process args and runs USG audit and USG fix."""
    logger.debug("Starting command_fix")
    usg_profile = get_usg_profile_from_args(usg, args)
    print("Running audit and remediation script...")
    _ = usg.fix(usg_profile, only_failed=args.only_failed)
    print(
        "USG fix command completed.\n"
        "A system reboot is required to complete the fix process.\n"
        "Please run usg audit after reboot."
    )
    logger.debug("Finished command_fix")


def command_audit(usg: USG, args: argparse.Namespace) -> None:
    """Process args and runs USG audit."""
    logger.debug("Starting command_audit")
    usg_profile = get_usg_profile_from_args(usg, args)
    results, output_files = usg.audit(
        usg_profile, debug=args.debug, oval_results=args.oval_results
    )
    print(results.get_summary())
    logger.debug("Finished command_audit")


def load_benchmark_version_state(profile_id: str) -> str:
    """Load USG CLI state file and return benchmark version used in previous run.

    Args:
        profile_id: profile id (cis_level1_server, stig, ...)

    Returns:
        benchmark version: returns "latest" if no state file exists or version was
                           not yet set for this profile

    Raises:
        StateFileError if state file is corrupted

    """
    logger.debug(f"Loading benchmark version for profile {profile_id} from state file")
    cli_state_file = Path(constants.CLI_STATE_FILE)
    json_data = {}
    if cli_state_file.exists():
        check_perms(cli_state_file)
        try:
            with cli_state_file.open("r") as f:
                json_data.update(json.load(f))
            versions = json_data["benchmark_versions"]
        except (OSError, json.JSONDecodeError, KeyError) as e:
            raise StateFileError(
                f"Corrupted state file {cli_state_file}: {e}. "
                f"Remove the file to re-initialize USG."
                ) from e

        logger.debug(f"State file successfully loaded: {json_data}.")
        # get value from state file if it exists
        try:
            prev_benchmark_version = versions[profile_id]
            logger.debug(
                f"Found state benchmark version: {prev_benchmark_version}"
                )
        except KeyError:
            logger.debug("Benchmark version not found. Using 'latest'.")
            prev_benchmark_version = "latest"
    else:
        logger.debug("State file doesn't exist. Using 'latest' version.")
        prev_benchmark_version = "latest"

    return prev_benchmark_version


def save_benchmark_version_state(profile_id: str, benchmark_version: str) -> None:
    """Save the benchmark version to the USG state file.

    Args:
        profile_id: profile id (cis_level1_server, stig, ...)
        benchmark_version: version to save

    Raises:
        StateFileError if state file is corrupted or cannot be written to

    """
    logger.debug(f"Saving version {benchmark_version} for profile {profile_id}")

    cli_state_file = Path(constants.CLI_STATE_FILE)
    json_data = {
        "benchmark_versions": {}
    }

    # load existing state if exists
    if cli_state_file.exists():
        try:
            with cli_state_file.open("r") as f:
                json_data.update(json.load(f))
        except (OSError, json.JSONDecodeError) as e:
            raise StateFileError(
                f"Corrupted state file {cli_state_file}: {e}. "
                f"Remove the file to re-initialize USG."
                ) from e
        logger.debug(f"State file successfully loaded: {json_data}.")

    # update state if changed
    if json_data["benchmark_versions"].get(profile_id, "latest") == benchmark_version:
        logger.debug("Version is same, not writing to state file.")
        return

    logger.debug(f"Writing changes to state file {cli_state_file}")
    json_data["benchmark_versions"][profile_id] = benchmark_version
    try:
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            json.dump(json_data, f)
            f.flush()
            os.fsync(f.fileno())
            f.close()
            Path(f.name).replace(cli_state_file)
    except OSError as e:
        raise StateFileError(
            f"Failed to write to state file {cli_state_file}: {e}"
        ) from e
    logger.debug(f"Benchmark version updated to {benchmark_version} successfully.")


def get_usg_profile_from_args(usg: USG, args: argparse.Namespace) -> Profile:
    """Return a Profile object based on the provided args."""
    logger.debug("Loading profile from args: {args}")

    if hasattr(args, "profile"):
        # get previously used benchmark version if defined in state file
        stored_benchmark_version = load_benchmark_version_state(args.profile)

        # override with CLI argument if provided
        if hasattr(args, "benchmark_version") and \
                args.benchmark_version != stored_benchmark_version:
            logger.info(
                f"Overriding stored/default benchmark version "
                f"{stored_benchmark_version} with {args.benchmark_version}"
                )
            benchmark_version = args.benchmark_version
        else:
            benchmark_version = stored_benchmark_version

        try:
            # get the profile
            profile = usg.get_profile(
                args.profile,
                args.product,
                benchmark_version
                )
        except ProfileNotFoundError as e:
            error_exit(f"{e}\nSee `usg list --all` for list of available profiles.", rc=1)

        # update the benchmark version in the state file
        benchmark = usg.get_benchmark_by_id(profile.benchmark_id)
        save_benchmark_version_state(profile.profile_id, benchmark.version)

    else:
        profile = usg.load_tailoring(args.tailoring_file).profile

    return profile


def init_logging(log_path: Path, debug: bool) -> None:
    """Initialize logging.

    Logs are written to file, fallback to stderr.
    Warning logs are always written to stderr.

    Args:
        log_path: Path to log file
        debug: Whether to enable debug logging

    """
    root = logging.getLogger()
    if root.hasHandlers():
        root.handlers.clear()

    if debug:
        sys.stderr.write(f"Debug logging enabled. Writing to {log_path}.\n")

    try:
        log_handler = logging.FileHandler(log_path)
    except Exception:  # noqa: BLE001
        sys.stderr.write(
            f"Error: cannot open '{log_path}' for writing. Writing logs to stderr.\n"
        )
        log_handler = logging.StreamHandler()
    else:
        # warning logs go to console always
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(
            logging.Formatter("\n%(levelname)s: %(message)s\n")
        )
        root.addHandler(console_handler)

    if debug:
        fmt_string = "%(levelname)s - %(module)s %(funcName)s %(message)s"
        log_handler.setLevel(logging.DEBUG)
        root.setLevel(logging.DEBUG)
    else:
        fmt_string = "%(levelname)s - %(message)s"
        log_handler.setLevel(logging.INFO)
        root.setLevel(logging.INFO)

    log_handler.setFormatter(logging.Formatter(fmt_string))
    root.addHandler(log_handler)

    logger.info(80 * "-")
    logger.info(f"Initialized logging on {time.ctime()}")
    logger.info(f"USG version: {DISPLAY_VERSION}")


def parse_args(config_defaults: configparser.ConfigParser) -> argparse.Namespace:
    """Parse args for all subcommands.

    The arguments are mostly the same across subcommands thus
    all of the logic is contained in this one parsing function.

    Returns:
        - args: argparse Namespace

    """
    logger.debug(f"Parsing CLI args: {sys.argv}")

    parser = argparse.ArgumentParser(
        allow_abbrev=False,
        description=CLI_USG_HELP["description"],
        epilog=CLI_USG_HELP["epilog"],
        formatter_class=argparse.RawTextHelpFormatter,
        prog="usg",
    )

    parser.add_argument("-V", "--version", action="version", version=DISPLAY_VERSION)

    subparsers = parser.add_subparsers(dest="command", required=False)
    cmd_parsers = {}

    for command in CLI_CMD_HELP:
        cmd_parser = subparsers.add_parser(
            name=command,
            description=CLI_CMD_HELP[command]["description"],
            epilog=CLI_CMD_HELP[command]["epilog"],
            formatter_class=argparse.RawTextHelpFormatter,
            prog="usg",
            argument_default=argparse.SUPPRESS,
        )

        if command in ["info", "audit", "fix", "generate-fix"]:
            cmd_parser.add_argument(
                "profile",
                nargs="?",
                type=str,
                help="Profile name (see 'usg list' for list of profiles)",
            )
            cmd_parser.add_argument(
                "-t", "--tailoring-file", type=Path, help="Path to tailoring file"
            )

        if command in ["info", "audit", "fix", "generate-fix", "generate-tailoring"]:
            # Product argument is not needed until multiple products exist.
            # Avoid polluting the CLI and hardcode it to the default for now.
            cmd_parser.set_defaults(
                product=constants.DEFAULT_PRODUCT
            )
            cmd_parser.add_argument(
                "-b",
                "--benchmark-version",
                type=str,
                help="Select specific benchmark version",
                default=argparse.SUPPRESS,
            )

        if command in ["audit", "fix"]:
            cmd_parser.add_argument(
                "--html-file",
                type=Path,
                help="Override the HTML output file",
                default=argparse.SUPPRESS,
            )
            cmd_parser.add_argument(
                "--results-file",
                type=Path,
                help="Override the results file",
                default=argparse.SUPPRESS,
            )
            cmd_parser.add_argument(
                "--oval-results",
                action="store_true",
                default=config_defaults.getboolean(
                    "openscap_backend",
                    "save_oval_results",
                    fallback=constants.OPENSCAP_SAVE_OVAL_RESULTS,
                ),
                help="Write the OVAL results files",
            )

        if command in ["generate-fix"]:
            cmd_parser.add_argument(
                "-o",
                "--output",
                type=Path,
                help="Output file",
                default=argparse.SUPPRESS,
            )

        if command in ["generate-tailoring"]:
            cmd_parser.add_argument(
                "profile",
                type=str,
                help="Profile name (see 'usg list' for list of profiles)",
            )
            cmd_parser.add_argument("output", type=Path, help="Output file")

        if command in ["fix"]:
            cmd_parser.add_argument(
                "--only-failed",
                action="store_true",
                default=config_defaults.getboolean(
                    "cli", "fix_only_failed", fallback=constants.DEFAULT_FIX_ONLY_FAILED
                ),
                help="Fix only failed rules",
            )

        if command in ["list"]:
            cmd_parser.add_argument(
                "-a",
                "--all",
                action="store_true",
                default=False,
                help="List deprecated profiles",
            )
            cmd_parser.add_argument(
                "-m",
                "--machine-readable",
                action="store_true",
                default=False,
                help="Machine readable output",
            )

        cmd_parser.add_argument(
            "-d",
            "--debug",
            action="store_true",
            default=False,
            help="Enable debug logging",
        )

        cmd_parsers[command] = cmd_parser

    args = parser.parse_args()
    logger.debug(f"Parsed args: {args}")

    # print help if no command is provided (as legacy USG)
    if args.command is None:
        parser.print_help()
        error_exit(rc=2)

    # additional check for profile/tailoring file
    if args.command in ["info", "audit", "fix", "generate-fix"]:
        # Legacy USG requires either a positional arg "profile" or
        # --tailoring-file. Keeping the same UI for backwards compatibility.
        if hasattr(args, "profile") and hasattr(args, "tailoring_file"):
            error_exit("You cannot provide both a tailoring file and a profile!", rc=2)

        elif not hasattr(args, "profile") and not hasattr(args, "tailoring_file"):
            # Use default tailoring file if it exists
            default_tailoring = Path(constants.DEFAULT_TAILORING_PATH)
            if default_tailoring.exists():
                print(f"Using the default tailoring file at {default_tailoring}")
                args.tailoring_file = default_tailoring
            else:
                sys.stderr.write(
                    "Error: a profile or a tailoring file must be provided.\n"
                    )
                cmd_parsers[args.command].print_help()
                error_exit(rc=2)

    # benchmark_version/product are not compatible with tailoring-file
    if hasattr(args, "tailoring_file") and hasattr(args, "benchmark_version"):
        error_exit(
            ("Error: --benchmark-version cannot be used with a tailoring file."),
            rc=2,
        )

    return args


def cli() -> None:
    """Load configuration, parse args, run USG commands."""
    if os.geteuid() != 0:
        error_exit("Error: this script must be run with super-user privileges.")
    try:
        acquire_lock()
    except LockError as e:
        error_exit(str(e))

    # load config from defaults or file if exists
    config = load_config(constants.CONFIG_PATH)

    # parse args
    args = parse_args(config_defaults=config)

    # override config with CLI args
    override_config_with_cli_args(config, args)

    # initialize logging
    log_path = Path(config["cli"]["log_file"])
    if not log_path.is_absolute():
        log_path = Path(constants.STATE_DIR) / log_path
    init_logging(log_path, args.debug)

    # initialize USG with overriden config
    try:
        usg = USG(config)
    except USGError as e:
        error_exit(f"Error: failed to initialize USG: {e}")

    # run commands
    try:
        command_func = {
            "list": command_list,
            "info": command_info,
            "generate-tailoring": command_generate_tailoring,
            "generate-fix": command_generate_fix,
            "audit": command_audit,
            "fix": command_fix,
        }
        logger.info(f"Running command: {args.command}")
        command_func[args.command](usg, args)  # pyright: ignore[reportPossiblyUnboundVariable]

    except USGError as e:
        error_exit(f"Error: '{args.command}' command failed: {e}")


def main() -> None:
    """CLI entry point. Call cli() and catch runtime errors."""
    try:
        # setup basic logging in case we don't reach initialization
        logging.basicConfig(level=logging.INFO)
        cli()
    except KeyboardInterrupt:
        error_exit("Caught keyboard interrupt. Exiting USG...")
    except Exception as e:  # noqa: BLE001
        # info lvl is used to avoid dumping the traceback to the console handler
        logger.info("Uncaught exception:", exc_info=e)
        error_exit(
            "\nUSG encountered an unknown error. "
            "See the log file and report the issue to "
            "https://bugs.launchpad.net/usg\n"
        )


if __name__ == "__main__":
    main()
