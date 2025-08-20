#!/usr/bin/python3
#
# Ubuntu Security Guide
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

import argparse
import datetime
import gzip
import json
import logging
import shutil
import sys
import tempfile
from pathlib import Path

import toml
from create_rule_and_variable_doc import generate_markdown_doc
from process_benchmarks import (
    BenchmarkProcessingError,
    get_pat_token,
    process_benchmarks,
)

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RELEASE_METADATA_DIR = Path("tools/release_metadata")
TEMPLATES_DIR = Path("templates")
BENCHMARKS_DIR = Path("benchmarks")
TEST_INPUTS_DIR = Path("tools/tests/data/input")
TEST_PB_DOWNLOAD_DIR = (
    Path(TEST_INPUTS_DIR) / RELEASE_METADATA_DIR / "process_benchmarks_mock_data"
)


def exit_error(msg):
    logger.error(f"Build script exiting with error:\n{msg}\n")
    sys.exit(1)


def run_process_benchmarks(
    release_metadata_dir: Path,
    templates_dir: Path,
    pb_download_dir: Path | None,
    output_benchmarks_dir: Path,
) -> None:
    # Run process_benchmarks() to generate benchmark data.
    # If pb_mock_download_dir is provided, use mock data from that directory
    # instead of downloading the actual data from GitHub.

    logger.debug(
        f"Running process_benchmarks() with release_metadata_dir: {release_metadata_dir}"
    )
    logger.debug(f"Running process_benchmarks() with templates_dir: {templates_dir}")
    logger.debug(
        f"Running process_benchmarks() with pb_download_dir: {pb_download_dir}"
    )
    logger.debug(
        f"Running process_benchmarks() with output_benchmarks_dir: {output_benchmarks_dir}"
    )

    release_metadata_files = list(release_metadata_dir.glob("*.yml"))

    logger.debug(f"Found benchmark metadata files: {release_metadata_files}")
    if not release_metadata_files:
        exit_error(f"No yml files fonud in ${RELEASE_METADATA_DIR}")

    if pb_download_dir is not None:
        github_pat_token = None
    else:
        github_pat_token = get_pat_token()

    try:
        process_benchmarks(
            release_metadata_files,
            templates_dir,
            github_pat_token,
            pb_download_dir,
            output_benchmarks_dir,
        )

    except BenchmarkProcessingError as e:
        exit_error(f"Error while processing benchmarks: {e}")

    logger.debug("process_benchmarks() completed successfully")


def gen_documentation(output_benchmarks_dir: Path) -> tuple[str, str]:
    # generate docs for rules and variables for the latest benchmark

    logger.debug("Generating documentation...")

    benchmark_metadata_path = output_benchmarks_dir / "benchmarks.json"
    benchmark_metadata = json.loads(benchmark_metadata_path.read_text())

    try:
        latest = [
            b
            for b in benchmark_metadata["benchmarks"]
            if b["backend"] == "openscap" and b["is_latest"]
        ][0]
        datastream_gz_path = (
            output_benchmarks_dir / latest["data_files"]["datastream_gz"]["path"]
        )
    except Exception:
        exit_error(
            f"Could not find 'latest' openscap datastream in {benchmark_metadata_path}"
        )

    logger.debug(f"Using datastream: {datastream_gz_path}")

    # Unpack datastream used for generating documentation
    with tempfile.TemporaryDirectory() as tmp_dir:
        unpacked_datastream_path = Path(tmp_dir) / datastream_gz_path.name.replace(
            ".gz", ""
        )
        logger.debug(f"Unpacking datastream to {unpacked_datastream_path}...")
        with gzip.open(datastream_gz_path, "rb") as ds_gz:
            with open(unpacked_datastream_path, "wb") as ds:
                shutil.copyfileobj(ds_gz, ds)

        try:
            rules_output = generate_markdown_doc(unpacked_datastream_path, "rules")
            vars_output = generate_markdown_doc(unpacked_datastream_path, "variables")
        except Exception as e:
            exit_error(f"Failed to generate documentation: {e}")

    return (rules_output, vars_output)


def mass_replacer(
    the_meat: str,
    meat_placeholder: str,
    current_timestamp: datetime.datetime,
    file_lines: str,
) -> str:
    # This function significantly reduces code reuse and other potential
    # ickyness. "the_meat" refers to the main data that needs to be put
    # in the file,ie the generated documentation.
    # "meat_placeholder" is the template placeholder string for "the_meat"

    # Generate the different time-related values that this function will use.
    current_datestring = datetime.datetime.strftime(current_timestamp, "%d %B %Y")
    current_year = current_timestamp.year

    corrected_lines = (
        file_lines.replace("<<YEAR_PLACEHOLDER>>", str(current_year))
        .replace("<<DATE_PLACEHOLDER>>", str(current_datestring))
        .replace("<<USG_BENCHMARKS_VERSION_PLACEHOLDER>>", _get_usg_version())
        .replace(meat_placeholder, str(the_meat))
    )

    return corrected_lines


def build_files(
    templates_dir: Path,
    output_dir: Path,
    rules_doc: str,
    vars_doc: str,
    current_timestamp: datetime.datetime,
) -> None:
    # An array of [path, data, placeholder]
    data_info = [
        ["doc/man8/usg.md", "", "<<DOESNT_EXIST>>"],
        ["doc/man7/usg-cis.md", "", "<<DOESNT_EXIST>>"],
        ["doc/man7/usg-disa-stig.md", "", "<<DOESNT_EXIST>>"],
        ["doc/man7/usg-rules.md", rules_doc, "<<USG_MAN_RULES_PLACEHOLDER>>"],
        ["doc/man7/usg-variables.md", vars_doc, "<<USG_MAN_VARIABLE_PLACEHOLDER>>"],
    ]

    for specific_file_data in data_info:
        try:
            template_path = templates_dir / specific_file_data[0]
            template_data = template_path.read_text()
        except FileNotFoundError:
            exit_error(f"Template file at {template_path} cannot be opened.")

        built_data = mass_replacer(
            specific_file_data[1],
            specific_file_data[2],
            current_timestamp,
            template_data,
        )
        try:
            output_path = output_dir / specific_file_data[0]
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(built_data)
        except FileNotFoundError:
            exit_error("File at {output_path} cannot be opened for writing.")


def _get_usg_version() -> str:
    pyproject_path = PROJECT_ROOT / "pyproject.toml"
    pyproject_toml = toml.load(pyproject_path)
    return pyproject_toml["project"]["version"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true")
    parser.add_argument("--test-mode", action="store_true")
    parser.add_argument(
        "--pre-downloaded-data-dir",
        type=Path,
        help="Data dir containing pre-downloaded data (also used for testing)",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=PROJECT_ROOT, help="Root output dir"
    )
    args = parser.parse_args()

    loglevel = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        stream=sys.stdout, level=loglevel, format="%(levelname)s: %(message)s"
    )

    if args.test_mode:
        logger.warning(f"In test mode, using mock data from {TEST_INPUTS_DIR}")
        templates_dir = PROJECT_ROOT / TEST_INPUTS_DIR / TEMPLATES_DIR
        release_metadata_dir = PROJECT_ROOT / TEST_INPUTS_DIR / RELEASE_METADATA_DIR
        pb_download_dir = PROJECT_ROOT / TEST_PB_DOWNLOAD_DIR
    else:
        templates_dir = PROJECT_ROOT / TEMPLATES_DIR
        release_metadata_dir = PROJECT_ROOT / RELEASE_METADATA_DIR
        pb_download_dir = (
            args.pre_downloaded_data_dir.resolve()
            if args.pre_downloaded_data_dir
            else None
        )

    output_benchmarks_dir = args.output_dir / BENCHMARKS_DIR

    logger.debug(f"Templates directory: {templates_dir}")
    logger.debug(f"Release metadata directory: {release_metadata_dir}")
    logger.debug(f"Mock download directory: {pb_download_dir}")
    logger.debug(f"Root output directory: {args.output_dir}")
    logger.debug(f"Output benchmarks directory: {output_benchmarks_dir}")

    # Get the current timestamp
    current_timestamp = datetime.datetime.now(datetime.UTC).replace(microsecond=0)

    logger.info("Running `process_benchmarks.py`")
    run_process_benchmarks(
        release_metadata_dir, templates_dir, pb_download_dir, output_benchmarks_dir
    )

    logger.info("Generating the rules and variables documentation")
    rules_doc, vars_doc = gen_documentation(output_benchmarks_dir)

    logger.info(
        "Building the template files from all of the data that we've collected."
    )
    build_files(templates_dir, args.output_dir, rules_doc, vars_doc, current_timestamp)


if __name__ == "__main__":
    main()
