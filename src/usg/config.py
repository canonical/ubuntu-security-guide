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

"""Config loader and default configuration."""

import argparse
import configparser
import logging
from pathlib import Path

from usg import constants

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "cli": {
        "log_file": constants.CLI_LOG_FILE,
        "product": constants.DEFAULT_PRODUCT,
        "fix_only_failed": constants.DEFAULT_FIX_ONLY_FAILED,
    },
    "openscap_backend": {
        "audit_report": constants.OPENSCAP_REPORT_FILE,
        "audit_results": constants.OPENSCAP_RESULTS_FILE,
        "audit_log": constants.OPENSCAP_LOG_FILE,
        "fix_script": constants.OPENSCAP_FIX_FILE,
        "audit_oval_results": constants.OPENSCAP_OVAL_RESULTS_FILE,
        "audit_oval_cpe_results": constants.OPENSCAP_OVAL_CPE_RESULTS_FILE,
        "save_oval_results": constants.OPENSCAP_SAVE_OVAL_RESULTS,
    },
}


def load_config(
    config_path: Path | str | None = None,
) -> configparser.ConfigParser:
    """Initialize and return config.

    Default config is loaded from DEFAULT_CONFIG and overridden with
    config from config_path, if provided.

    Args:
        config_path: path to config file (optional)

    Returns:
        configparser.ConfigParser

    """
    logger.debug(f"Loading config from {config_path}")

    config = configparser.ConfigParser()
    config.read_dict(DEFAULT_CONFIG)
    if config_path is not None and Path(config_path).exists():
        logger.debug(f"Loading config {config_path}")
        try:
            config.read(config_path)
        except Exception as e:  # noqa: BLE001
            logger.error(
                f"Failed to load config {config_path}: {e}. Using defaults.",
            )
    else:
        logger.info(f"Config {config_path} does not exist. Using defaults.")

    logger.debug(f"Config: {config}")
    return config


def get_artifact_destination_path(
    config: configparser.ConfigParser,
    option: str,
    timestamp: str,
    cac_profile: str,
    product: str,
) -> Path:
    """Get destination path of a backend artifact file from the config.

    Replace placeholders to maintain backwards compatibility with legacy USG
    (PRODUCT, DATE and PROFILE_ID).
    If the path is not absolute, prefix with STATE_DIR.

    Args:
        config: config parser
        option: option name in [opensca_backend] section ofconfig
        timestamp: timestamp (YYYYMMDD.HHMM)
        cac_profile: profile id (e.g. cis_level1_server)
        product: product name (e.g. ubuntu2404)

    Returns:
        Path

    """
    logger.debug(
        f"Getting artifact destination path for {option} "
        f"with profile {cac_profile} and timestamp {timestamp}"
    )
    path_str = config["openscap_backend"][option]
    path = Path(
        path_str.format(PRODUCT=product, DATE=timestamp, PROFILE_ID=cac_profile),
    )
    if not path.is_absolute():
        path = constants.STATE_DIR / path
    path = path.resolve()
    logger.debug(f"Artifact destination path: {path}")
    return path


def override_config_with_cli_args(
    config: configparser.ConfigParser, args: argparse.Namespace
) -> None:
    """Override config paths with CLI args.

    Args:
        config: config parser
        args: CLI args

    """
    # Define how CLI args map to config options:
    # (args) command.option -> (config) section.option
    map_cli_paths_to_config = {
        "audit.html_file": "openscap_backend.audit_report",
        "audit.results_file": "openscap_backend.audit_results",
        "generate-fix.output": "openscap_backend.fix_script",
    }
    for cli_arg, cfg_opt in map_cli_paths_to_config.items():
        command, option = cli_arg.split(".")
        if args.command == command and hasattr(args, option):
            config_section, config_option = cfg_opt.split(".")
            new_path = Path(getattr(args, option).resolve())
            config.set(config_section, config_option, str(new_path))
