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
import logging
import os
import shutil
import sys
import time
from copy import deepcopy
from pathlib import Path

from usg import constants
from usg.config import load_config, override_config_with_cli_args
from usg.exceptions import LockError, ProfileNotFoundError, USGError
from usg.models import Benchmark, Profile, TailoringFile
from usg.usg import USG
from usg.utils import acquire_lock, check_perms
from usg.version import __version__

logger = logging.getLogger(__name__)

# Add leading zero (removed by python packaging)
# to be consistent with usg package versioning
DISPLAY_VERSION = __version__.replace(".4.", ".04.")

# shared format strings
CLI_LIST_FORMAT = "{:40s}{:25s}{:25s}{:s}"
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
$ usg audit cis_level1_server-v1.0.0
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
$ usg fix cis_level1_server-v1.0.0
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
$ usg generate-fix cis_level1_server-v1.0.0
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
$ usg generate-fix cis_level1_server-v1.0.0 -o fix.sh
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
        printerr(msg)
    sys.exit(rc)

def printerr(msg: str) -> None:
    """Write msg to stderr with newline."""
    sys.stderr.write(msg+"\n")

def command_list(usg: USG, args: argparse.Namespace) -> None:
    """List available profiles."""
    logger.debug("Starting command_list")
    if not args.machine_readable:
        if not sys.stdout.isatty():
            printerr(
                "Warning: 'usg list' does not have a stable CLI interface. "
                "Use '--machine-readable' flag in scripts."
                )
        if args.all:
            print("\nListing all available profiles...\n")
        else:
            print("\nListing latest profiles (use `--all` to list all)...\n")
        print(CLI_LIST_FORMAT.format(
            "PROFILE", "BENCHMARK/PRODUCT", "BENCHMARK VERSION", "STATE"
            ))

    example_profile = "cis_level1_server"
    for profile in sorted(usg.profiles.values(), key=lambda p: p.id):
        is_latest = profile.latest_compatible_id is None \
            and profile.benchmark.channel.is_latest

        if not args.all and not is_latest:
            continue
        if args.machine_readable:
            print(":".join([  # noqa: FLY002
                profile.id,
                profile.cac_id,
                profile.benchmark.benchmark_type,
                profile.benchmark.product,
                profile.benchmark.version,
                profile.benchmark.id,
                profile.benchmark.state,
                profile.benchmark.channel.id,
                str(profile.benchmark.channel.channel_number),
                "", "", "", "", "", "" # reserved
                ]))

        else:
            print(
                CLI_LIST_FORMAT.format(
                    profile.id,
                    f"{profile.benchmark.benchmark_type}/{profile.benchmark.product}",
                    profile.benchmark.version,
                    profile.benchmark.state,
                )
            )
        example_profile = profile.id
    if not args.machine_readable:
        print(f"""

Use 'usg info' to print information about a specific profile or tailoring file:

$ usg info {example_profile}
$ usg info -t my_tailoring.xml
""")
    logger.debug("Finished command_list")


def command_info(usg: USG, args: argparse.Namespace) -> None:
    """Print info about a specific profile or tailoring file."""
    logger.debug("Starting command_info")
    if not sys.stdout.isatty():
        printerr(
            "Warning: 'usg info' does not have a stable CLI interface. "
            "Use with caution in scripts.\n"
            )
    if hasattr(args, "tailoring_file"):
        tailoring = usg.load_tailoring(args.tailoring_file)
        usg_profile = tailoring.profile
    else:
        usg_profile = get_usg_profile_from_args(usg, args)

    print_info_profile(usg_profile)
    logger.debug("Finished command_info")


def print_info_profile(profile: Profile) -> None:
    """Print information about profile, benchmark, release channel."""
    print()
    for k, v in [
        ("Profile", profile.id),
        ("Aliases", ", ".join(profile.alias_ids) or '(none)'),
        ("Extends", profile.extends_id or "(none)"),
    ]:
        print(CLI_INFO_FORMAT.format(k, v))

    benchmark = profile.benchmark
    state = "Latest stable" if benchmark.channel.is_latest \
        else "Maintenance (critical patches only)"

    release_date = datetime.datetime.fromtimestamp(
        benchmark.channel.release_timestamp,
        datetime.timezone.utc
        ).isoformat()
    for k, v in [
        ("Benchmark type", benchmark.benchmark_type),
        ("Target product", benchmark.product_long),
        ("Benchmark version", benchmark.version),
        ("State", state),
        ("Description", benchmark.description.strip()),
        ("Reference", benchmark.reference_url),
        ("Release date", release_date),
        ("Release notes", benchmark.channel.release_notes_url),
        ("Release channel", benchmark.channel.id),
    ]:
        print(CLI_INFO_FORMAT.format(k, v))

    profiles = "\n".join([f"- {p}" for p in benchmark.profiles.values()])
    print(f"\nAll profiles in this benchmark:\n{profiles}\n")

    if profile.latest_breaking_id is not None:
        print(
            f"\nNote:\nThis profile version is no longer supported. "
            f"Latest version is {profile.latest_breaking_id}.\n"
        )
    elif profile.latest_compatible_id is not None:
        print(
            f"\nNote:\nThis profile has been superseded by compatible version "
            f"{profile.latest_compatible_id}.\n"
        )


def command_generate_tailoring(usg: USG, args: argparse.Namespace) -> None:
    """Generate a tailoring file and writes it to disk."""
    logger.debug("Starting command_generate_tailoring")
    usg_profile = get_usg_profile_from_args(usg, args)

    printerr(
        f"USG will extract the tailoring file for profile "
        f"'{usg_profile.id}' to '{args.output}'."
    )
    try:
        contents = usg.generate_tailoring(usg_profile)
    except:
        printerr("USG generate-tailoring command failed!")
        raise
    try:
        with Path(args.output).open("w") as f:
            f.write(contents)
    except OSError as e:
        error_exit(f"Failed to write file {args.output}: {e}")
    else:
        printerr("USG generate-tailoring command completed.")
    logger.debug("Finished command_generate_tailoring")


def command_generate_fix(usg: USG, args: argparse.Namespace) -> None:
    """Process args for generate-fix command and runs usg."""
    logger.debug("Starting command_generate_fix")
    usg_profile = get_usg_profile_from_args(usg, args)

    try:
        artifacts = usg.generate_fix(usg_profile)
    except:
        # backwards compatible error msg
        printerr("USG generate-fix command failed!")
        raise

    output_path = artifacts.get_by_type("fix_script").path
    # Legacy USG writes the default output directly to cwd instead
    # of /var/lib/usg. Ensure we do the same.
    if not hasattr(args, "output"):
        try:
            shutil.copy(output_path, Path.cwd())
            output_path = output_path.name
        except OSError as e:
            logger.error(f"Failed to write fix script to CWD: {e}")
    printerr(
        f"USG generate-fix command completed."
        f"Wrote remediation script to '{output_path}'"
        )
    logger.debug("Finished command_generate_fix")


def command_fix(usg: USG, args: argparse.Namespace) -> None:
    """Process args and runs USG audit and USG fix."""
    logger.debug("Starting command_fix")
    usg_profile = get_usg_profile_from_args(usg, args)

    printerr("Running audit and remediation script...")
    try:
        _, output_files = usg.audit(
            usg_profile, debug=args.debug, oval_results=args.oval_results
        )
        audit_results_file = None
        if args.only_failed:
            audit_results_file = output_files.get_by_type("audit_results").path

        _ = usg.fix(usg_profile, audit_results_file=audit_results_file)
    except:
        printerr("USG fix command failed!")
        raise

    printerr(
        "USG fix command completed.\n"
        "A system reboot is required to complete the fix process.\n"
        "Please run usg audit after reboot."
    )
    logger.debug("Finished command_fix")


def command_audit(usg: USG, args: argparse.Namespace) -> None:
    """Process args and runs USG audit."""
    logger.debug("Starting command_audit")
    usg_profile = get_usg_profile_from_args(usg, args)

    try:
        results, output_files = usg.audit(
            usg_profile, debug=args.debug, oval_results=args.oval_results
        )
    except:
        printerr("USG audit scan command failed!")
        raise

    report_file = output_files.get_by_type("audit_report").path
    results_file = output_files.get_by_type("audit_results").path
    printerr(
        f"USG audit scan command completed. The scan results are available in "
        f"{report_file} report or in {results_file}"
        )
    logger.debug("Finished command_audit")


def get_usg_profile_from_args(usg: USG, args: argparse.Namespace) -> Profile:
    """Return a Profile object based on the provided args."""
    logger.debug(f"Loading profile from args: {args}")

    if hasattr(args, "profile"):

        try:
            # get the profile
            profile = usg.get_profile(
                args.profile,
                )
        except ProfileNotFoundError as e:
            raise USGError(
                f"{e}\nSee `usg list --all` for list of available profiles."
                ) from e
    else:
        profile = usg.load_tailoring(args.tailoring_file).profile

    logger.debug(f"Loaded profile {profile}")
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
        printerr(f"Debug logging enabled. Writing to {log_path}.")

    try:
        log_handler = logging.FileHandler(log_path)
    except Exception:  # noqa: BLE001
        printerr(
            f"Error: cannot open '{log_path}' for writing. Writing logs to stderr."
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
                printerr(f"Using the default tailoring file at {default_tailoring}")
                args.tailoring_file = default_tailoring
            else:
                printerr(
                    "Error: a profile or a tailoring file must be provided."
                    )
                cmd_parsers[args.command].print_help()
                error_exit(rc=2)

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
        usg = USG(config=config)
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
