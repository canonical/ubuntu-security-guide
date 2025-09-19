import os

import pytest
import logging

from usg import utils, constants
from usg.exceptions import IntegrityError, PermValidationError, LockError


def test_verify_integrity_success(tmp_path):
    file = tmp_path / "testfile"
    content = b"hello world"
    file.write_bytes(content)
    hexdigest = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    # Should not raise
    utils.verify_integrity(file, hexdigest, "sha256")


def test_verify_integrity_failure(tmp_path):
    file = tmp_path / "testfile"
    file.write_bytes(b"something else")
    wrong_digest = "0" * 64
    with pytest.raises(IntegrityError):
        utils.verify_integrity(file, wrong_digest, "sha256")


def test_validate_perms_file_ok(tmp_path):
    file = tmp_path / "afile"
    file.touch()
    os.chmod(file, mode=0o600)
    # Should not raise
    utils.validate_perms(file)


def test_validate_perms_dir_ok(tmp_path):
    d = tmp_path / "adir"
    d.mkdir()
    os.chmod(d, mode=0o700)
    utils.validate_perms(d, is_dir=True)


def test_validate_perms_file_not_exist(tmp_path):
    file = tmp_path / "doesnotexist"
    with pytest.raises(PermValidationError):
        utils.validate_perms(file)


def test_validate_perms_symlink(tmp_path):
    link = tmp_path / "alink"
    link.symlink_to(".")
    with pytest.raises(PermValidationError):
        utils.validate_perms(link)


def test_validate_perms_not_dir(tmp_path):
    file = tmp_path / "afile"
    file.touch()
    os.chmod(file, mode=0o600)
    with pytest.raises(PermValidationError):
        utils.validate_perms(file, is_dir=True)


def test_validate_perms_not_file(tmp_path):
    d = tmp_path / "adir"
    d.mkdir()
    os.chmod(d, mode=0o700)
    with pytest.raises(PermValidationError):
        utils.validate_perms(d, is_dir=False)


def test_validate_perms_world_writable_file(tmp_path):
    file = tmp_path / "afile"
    file.touch()
    os.chmod(file, mode=0o666)
    with pytest.raises(PermValidationError):
        utils.validate_perms(file)


def test_validate_perms_world_writable_dir(tmp_path):
    d = tmp_path / "adir"
    d.mkdir()
    os.chmod(d, mode=0o777)
    with pytest.raises(PermValidationError):
        utils.validate_perms(d, is_dir=True)


def test_validate_perms_world_writable_parent(tmp_path):
    d = tmp_path / "parent"
    d.mkdir()
    file = d / "afile"
    file.touch()
    os.chmod(d, mode=0o777)
    os.chmod(file, mode=0o600)
    with pytest.raises(PermValidationError):
        utils.validate_perms(file)


def test_validate_perms_not_owned(tmp_path, monkeypatch):
    # test that validate perms failed if file is not owned by current user (or root)
    # patch stat to return UID=12345
    file = tmp_path / "afile"
    file.touch()
    os.chmod(file, mode=0o600)

    class FakeStatResult(object):
        def __init__(self, st):
            self.st_mode = st.st_mode
            self.st_ino = st.st_ino
            self.st_dev = st.st_dev
            self.st_nlink = st.st_nlink
            self.st_size = st.st_size
            self.st_atime = st.st_atime
            self.st_mtime = st.st_mtime
            self.st_ctime = st.st_ctime
            self.st_uid = 12345
            self.st_gid = 12345

    def fake_stat(path, *args, **kwargs):
        st = os.stat(path, *args, **kwargs)
        return FakeStatResult(st)

    from pathlib import Path
    monkeypatch.setattr(Path, "stat", fake_stat)

    with pytest.raises(PermValidationError):
        utils.validate_perms(file)

def test_aqcuire_lock_fail(monkeypatch, tmp_path):
    # test that failure to acquire lock raises an exception
    tmp_lock = tmp_path / "lockfile"
    monkeypatch.setattr(constants, "LOCK_PATH", tmp_lock)

    utils.acquire_lock()
    assert tmp_lock.exists()

    with pytest.raises(LockError, match="Failed to acquire lock"):
        utils.acquire_lock()

def test_aqcuire_lock_failed_creation(monkeypatch, tmp_path, caplog):
    # test that failure to create lock file doesnt fail the program
    tmp_lock = tmp_path / "nonwritabledir/lockfile2"
    tmp_lock.parent.mkdir(mode=0o500, parents=True, exist_ok=True)
    monkeypatch.setattr(constants, "LOCK_PATH", tmp_lock)

    with caplog.at_level(logging.ERROR):
        utils.acquire_lock()
        assert "Failed to create lock file" in caplog.text
    assert not tmp_lock.exists()


