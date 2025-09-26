import os
import subprocess

import pytest
import logging

from usg import constants
from usg.utils import (
        acquire_lock,
        gunzip_file,
        verify_integrity,
        check_perms,
        _has_good_ownership,
        _is_world_writable
        )
from usg.exceptions import IntegrityError, LockError, MissingFileError


def test_verify_integrity_success(tmp_path):
    file = tmp_path / "testfile"
    content = b"hello world"
    file.write_bytes(content)
    hexdigest = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    # Should not raise
    verify_integrity(file, hexdigest, "sha256")


def test_verify_integrity_failure(tmp_path):
    file = tmp_path / "testfile"
    file.write_bytes(b"something else")
    wrong_digest = "0" * 64
    with pytest.raises(IntegrityError):
        verify_integrity(file, wrong_digest, "sha256")


def test_check_perms_file_ok(tmp_path, caplog):
    file = tmp_path / "afile"
    file.touch()
    os.chmod(file, mode=0o664)
    os.chmod(tmp_path, mode=0o700)
    with caplog.at_level("WARNING"):
        check_perms(file)
    assert "is world-writable" not in caplog.text


def test_check_perms_dir_ok(tmp_path, caplog):
    d = tmp_path / "adir"
    d.mkdir()
    os.chmod(d, mode=0o775)
    with caplog.at_level("WARNING"):
        check_perms(d, is_dir=True)
    assert "is world-writable" not in caplog.text


def test_check_perms_file_not_exist(tmp_path):
    file = tmp_path / "doesnotexist"
    with pytest.raises(MissingFileError):
        check_perms(file)


def test_check_perms_not_dir(tmp_path):
    file = tmp_path / "afile"
    file.touch()
    os.chmod(file, mode=0o600)
    with pytest.raises(MissingFileError):
        check_perms(file, is_dir=True)


def test_check_perms_not_file(tmp_path):
    d = tmp_path / "adir"
    d.mkdir()
    os.chmod(d, mode=0o700)
    with pytest.raises(MissingFileError):
        check_perms(d, is_dir=False)


def test_check_perms_world_writable_file(tmp_path, caplog):
    file = tmp_path / "afile"
    file.touch()
    os.chmod(file, mode=0o666)
    with caplog.at_level("WARNING"):
        check_perms(file)
    assert "is world-writable" in caplog.text


def test_check_perms_world_writable_dir(tmp_path, caplog):
    d = tmp_path / "adir"
    d.mkdir()
    os.chmod(d, mode=0o777)
    with caplog.at_level("WARNING"):
        check_perms(d, is_dir=True)
    assert "is world-writable" in caplog.text


def test_check_perms_world_writable_parent(tmp_path, caplog):
    d = tmp_path / "parent"
    d.mkdir()
    file = d / "afile"
    file.touch()
    os.chmod(file, mode=0o600)
    os.chmod(d, mode=0o775)
    with caplog.at_level("WARNING"):
        check_perms(d, is_dir=True)
    assert "is world-writable" not in caplog.text
    os.chmod(d, mode=0o777)
    with caplog.at_level("WARNING"):
        check_perms(d, is_dir=True)
    assert "is world-writable" in caplog.text


def test_check_perms_not_owned(tmp_path, monkeypatch, caplog):
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

    with caplog.at_level("WARNING"):
        check_perms(file)
    assert "not owned by root or current user" in caplog.text


@pytest.mark.parametrize("uid,gid,expected_return", [
    [0, 0, True],
    [0, os.getgid(), True],
    [os.getuid(), os.getgid(), True],
    [0, 12345, False],
    [12345, 0, False]
    ])
def test_has_good_ownership(uid, gid, expected_return):
    class FakeStatResult(object):
        def __init__(self, uid, gid):
            self.st_uid = uid
            self.st_gid = gid
    assert _has_good_ownership(FakeStatResult(uid, gid), 1000, 1000) == expected_return


@pytest.mark.parametrize("perms,expected_return", [
    [0o0775, False],
    [0o0777, True],
    [0o0007, True],
    [0o1777, False],
    ])
def test_is_world_writable(tmp_path, perms, expected_return):
    file = tmp_path / "file"
    file.touch()
    file.chmod(perms)
    assert _is_world_writable(file.stat()) == expected_return


def test_aqcuire_lock_fail(monkeypatch, tmp_path):
    # test that failure to acquire lock raises an exception
    tmp_lock = tmp_path / "lockfile"
    monkeypatch.setattr(constants, "LOCK_PATH", tmp_lock)

    acquire_lock()
    assert tmp_lock.exists()

    with pytest.raises(LockError, match="Failed to acquire lock"):
        acquire_lock()

def test_aqcuire_lock_failed_creation(monkeypatch, tmp_path, caplog):
    # test that failure to create lock file doesnt fail the program
    tmp_lock = tmp_path / "nonexistantdir/lockfile2"
    monkeypatch.setattr(constants, "LOCK_PATH", tmp_lock)

    with caplog.at_level(logging.ERROR):
        acquire_lock()
        assert "Failed to create lock file" in caplog.text
    assert not tmp_lock.exists()


def test_gunzip(tmp_path):
    # test that gunzip function works as expected (assuming gzip works)
    f = tmp_path / "file"
    f.write_text("testing gunziping")
    subprocess.check_call(["gzip", "-kn", f], cwd=tmp_path)
    f_gunzipped = f.with_suffix(".new")
    gunzip_file(f.with_suffix(".gz"), f_gunzipped)
    assert f.read_bytes() == f_gunzipped.read_bytes()
