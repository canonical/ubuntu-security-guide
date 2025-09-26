"""Utility functions."""

import atexit
import fcntl
import gzip
import hashlib
import logging
import os
import shutil
import stat
from pathlib import Path

from usg import constants
from usg.exceptions import (
    IntegrityError,
    LockError,
    MissingFileError,
    PermValidationError,
)

logger = logging.getLogger(__name__)


def verify_integrity(file: Path | str, hexdigest: str, hash_algorithm: str) -> None:
    """Verify integrity of a file.

    Args:
        file: path to file
        hexdigest: expected hexdigest of the file
        hash_algorithm: hash algorithm to use

    Raises:
        IntegrityError: if the file is corrupted

    """
    logger.debug(f"Verifying integrity of {file}.")

    with Path(file).open("rb") as f:
        try:
            digest = hashlib.file_digest(f, hash_algorithm)
        except AttributeError:
            # python < 3.11
            digest = hashlib.new(hash_algorithm, f.read())

    if digest.hexdigest() != hexdigest:
        logger.error(
            f"Integrity check failed for {file}: "
            f"expected {hexdigest}, got {digest.hexdigest()}"
        )
        raise IntegrityError(f"Corrupted file {file}.")

    logger.debug(f"Integrity of {file} is ok.")


def check_perms(filepath: Path | str, is_dir: bool = False) -> None:
    """Check and log potentially unsafe file/dir permissions.

    Raises:
       - MissingFileError on missing file/dir

    """
    logger.debug(f"Checking permissions of {filepath}.")
    filepath = Path(filepath).resolve()

    if not filepath.exists():
        raise MissingFileError(f"'{filepath}' doesn't exist.")
    if is_dir and not filepath.is_dir():
        raise MissingFileError(f"'{filepath}' is not a directory.")
    if not is_dir and not filepath.is_file():
        raise MissingFileError(f"'{filepath}' is not a regular file.")

    try:
        uid, gid = os.getuid(), os.getgid()
        stat_result = filepath.stat()

        if _is_world_writable(stat_result):
            logger.warning(f"'{filepath}' is world-writable.")
        if not _has_good_ownership(stat_result, uid, gid):
            logger.warning(
                f"'{filepath}' is not owned by root or current user."
            )

        for parent in filepath.parents:
            stat_result_parent = parent.stat()
            if _is_world_writable(stat_result_parent):
                logger.warning(
                    f"Parent directory of '{filepath}' is world-writable: '{parent}'."
                )
            if not _has_good_ownership(stat_result_parent, uid, gid):
                logger.warning(
                    f"'Parent directory of '{filepath}' is not owned "
                    f"by root or current user: '{parent}'."
                )
    except OSError:
        logger.error("Failed to check permissions for '{filepath}'.")


def _is_world_writable(stat_result: os.stat_result) -> bool:
    # return true if path is world-writable and not sticky
    return bool(stat_result.st_mode & stat.S_IWOTH) and \
           not bool(stat_result.st_mode & stat.S_ISVTX)


def _has_good_ownership(stat_result: os.stat_result, uid: int, gid: int) -> bool:
    # return true if owned by root or uid:gid
    return stat_result.st_uid in [0, uid] and stat_result.st_gid in [0, gid]


def gunzip_file(gzipped_file: Path, unzipped_file: Path) -> None:
    """Gunzip the file to the output path."""
    logger.debug(f"Gunzipping file {gzipped_file} to {unzipped_file}")
    with gzip.open(gzipped_file, "rb") as f_gz, Path(unzipped_file).open("wb") as f_out:
            shutil.copyfileobj(f_gz, f_out)


def acquire_lock() -> None:
    """Aquire lock for running process."""
    lock_path = constants.LOCK_PATH
    mode = 0o600
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, mode)
    except OSError as e:
        # don't fail completely if file can't be created
        logger.error(f"Failed to create lock file: {e}")
        return

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as e:
        raise LockError(
            f"Failed to acquire lock {lock_path}. "
            f"Is another instance of USG running?"
            ) from e
    atexit.register(
        lambda: (fcntl.flock(fd, fcntl.LOCK_UN), os.close(fd))
        )

