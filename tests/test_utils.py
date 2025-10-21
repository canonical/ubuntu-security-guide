import os
import pytest

from usg import utils
from usg.exceptions import IntegrityError, PermValidationError

def test_verify_integrity_success(tmp_path):
    file = tmp_path / "testfile"
    content = b"hello world"
    file.write_bytes(content)
    hexdigest = utils.hashlib.file_digest(open(file, "rb"), "sha256").hexdigest()
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
    file = tmp_path / "afile"
    file.touch()
    os.chmod(file, mode=0o600)
    # Patch os.stat to fake different uid/gid
    orig_stat = os.stat

    class FakeStat(dict):
        def __init__(self, st, uid=12345, gid=12345):
            self.st_mode = st.st_mode
            self.st_uid = uid
            self.st_gid = gid

    def fake_stat(path, *args, **kwargs):
        st = orig_stat(path, *args, **kwargs)
        return FakeStat(st, uid=12345, gid=12345)

    monkeypatch.setattr(os, "stat", fake_stat)
    with pytest.raises(PermValidationError):
        utils.validate_perms(file)
