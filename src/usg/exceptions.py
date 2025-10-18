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

"""Custom exceptions."""

class USGError(Exception):
    """Base class for all user-visible USG exceptions."""


class ProfileNotFoundError(USGError):
    """Requested profile cannot be found."""


class MetadataError(USGError):
    """Invalid benchmark data."""


class IntegrityError(USGError):
    """File integrity check failed."""


class BackendError(USGError):
    """Failure inside an auditing/remediation backend."""


class BackendCommandError(USGError):
    """Failure inside an auditing/remediation backend."""


class TailoringFileError(USGError):
    """Malformed or unsupported tailoring file."""


class PermValidationError(USGError):
    """Unsafe permissions or ownership on a file/directory."""


class MissingFileError(PermValidationError):
    """File doesn't exist error."""


class FileMoveError(USGError):
    """Failed to move a file."""


class LockError(USGError):
    """Failed to acquire lock on file."""

