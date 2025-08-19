"""
Helper functions
"""

import os
import stat
from pathlib import Path
import gzip
import shutil

import hashlib
import logging

from usg.exceptions import IntegrityError, PermValidationError, MissingFileError

logger = logging.getLogger(__name__)


def verify_integrity(file: Path | str, hexdigest: str, hash_algorithm: str) -> None:
    """
    Verifies integrity of a file

    Args:
        file: path to file
        hexdigest: expected hexdigest of the file
        hash_algorithm: hash algorithm to use

    Raises:
        IntegrityError: if the file is corrupted
    """
    logger.debug(f"Verifying integrity of {file}.")

    with open(file, "rb") as f:
        digest = hashlib.file_digest(f, hash_algorithm)

    if digest.hexdigest() != hexdigest:
        logger.error(
            f"Integrity check failed for {file}: "
            f"expected {hexdigest}, got {digest.hexdigest()}"
            )
        raise IntegrityError(f"Corrupted file {file}.")

    logger.debug(f"Integrity of {file} is ok.")


def validate_perms(filepath: Path | str, is_dir: bool = False):
    """
    Ensure file/dir exists and is not world-writable or a symlink.

    Raises:
       - MissingFileError on missing file
       - PermValidationError on other issues
    """
    logger.debug(f"Validating permissions of {filepath}.")

    filepath = Path(filepath)

    if not filepath.exists():
        raise MissingFileError(f"'{filepath}' doesn't exist.")

    if filepath.is_symlink():
        raise PermValidationError(f"'{filepath}' is a symlink.")

    if is_dir and not filepath.is_dir():
        raise PermValidationError(
                f"'{filepath}' is not a directory."
                )
    elif not is_dir and not filepath.is_file():
        raise PermValidationError(
                f"'{filepath}' is not a regular file."
                )

    stat_result = os.stat(filepath)
    if bool(stat_result.st_mode & stat.S_IWOTH) and \
            not bool(stat_result.st_mode & stat.S_ISVTX):
        raise PermValidationError(
                f"'{filepath}' is world-writable."
                )

    if not is_dir:
        stat_result_parent = os.stat(filepath.parent)
        if bool(stat_result_parent.st_mode & stat.S_IWOTH) and \
                not bool(stat_result_parent.st_mode & stat.S_ISVTX):
            raise PermValidationError(
                    f"Parent directory of '{filepath}' "
                    f"is world-writable."
                    )

    if (stat_result.st_uid == 0 and stat_result.st_gid == 0) or \
       (stat_result.st_uid == os.getuid() and stat_result.st_gid == os.getgid()):
        pass # all good
    else:
        raise PermValidationError(
                f"'{filepath}' is not owned by root:root or "
                f"running user's uid:gid."
                )

    logger.debug(f"Permissions of {filepath} are ok.")


def gunzip_file(gzipped_file: Path, unzipped_file: Path) -> None:
    """
    Gunzips the file to the output path
    """
    logger.debug(f"Gunzipping file {gzipped_file} to {unzipped_file}")
    unzipped_file.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(gzipped_file, "rb") as f:
        with open(unzipped_file, "wb") as f_out:
            shutil.copyfileobj(f, f_out)

