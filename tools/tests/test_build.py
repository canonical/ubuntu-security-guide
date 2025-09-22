import filecmp
import importlib.resources
import os
import re
import subprocess
import shutil
from pathlib import Path
import pytest

BUILD_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "build.py"
TEST_DATA_DIR = importlib.resources.files("tools") / "tests/data"


def replace_dynamic_content(expected_text, actual_text, regex):
    expected_text_subbed = re.sub(regex, "", expected_text, flags=re.MULTILINE)
    actual_text_subbed = re.sub(regex, "", actual_text, flags=re.MULTILINE)
    return expected_text_subbed, actual_text_subbed


def compare_files(expected_file, actual_file):
    if expected_file.is_dir():
        assert actual_file.is_dir()
    elif expected_file.suffix == ".gz":
        assert filecmp.cmp(expected_file, actual_file, shallow=False)
    else:
        expected_text = expected_file.read_text()
        actual_text = actual_file.read_text()

        if expected_file.name == "benchmarks.json":
            expected_text_subbed, actual_text_subbed = replace_dynamic_content(
                expected_text, actual_text, r'"sha256":.*'
            )
        elif "tailoring" in expected_file.name:
            expected_text_subbed, actual_text_subbed = replace_dynamic_content(
                expected_text, actual_text, r"<version time=.*</version>"
            )
        elif expected_file.suffix == ".md":
            expected_text_subbed, actual_text_subbed = replace_dynamic_content(
                expected_text, actual_text, r"^% .*"
            )
        else:
            expected_text_subbed = expected_text
            actual_text_subbed = actual_text

        assert actual_text_subbed == expected_text_subbed


@pytest.mark.parametrize("test_product", [("ubuntu2404"), ("ubuntu2204"),])
def test_build(test_product, tmpdir):

    test_data_dir = TEST_DATA_DIR / test_product
    output_dir = Path(tmpdir) / "output"

    p = subprocess.run(
        [
            BUILD_SCRIPT_PATH,
            "--test-data", test_data_dir,
#            "--debug",
            "--output-dir",
            output_dir,
        ],
        check=False,
    )
    assert p.returncode == 0, f"Build process failed with RC: {p.returncode}"

    expected_output_dir = TEST_DATA_DIR / test_product / "expected"
    expected_output_files = sorted(list(expected_output_dir.rglob("*")))
    actual_output_files = sorted(list(output_dir.rglob("*")))

    assert len(expected_output_files) == len(actual_output_files), \
            "Number of built files does not match expected number"
    for expected_file, actual_file in zip(
        expected_output_files, actual_output_files, strict=False
    ):
        compare_files(expected_file, actual_file)
