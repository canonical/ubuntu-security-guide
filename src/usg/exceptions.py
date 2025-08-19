class USGError(Exception):
    """Base class for all user-visible USG exceptions"""


class ProfileNotFoundError(USGError):
    """Requested profile cannot be found."""


class BenchmarkError(USGError):
    """Invalid benchmark data."""


class IntegrityError(USGError):
    """File integrity check failed."""


class BackendError(USGError):
    """Failure inside an auditing/remediation backend."""


class TailoringFileError(USGError):
    """Malformed or unsupported tailoring file."""


class PermValidationError(USGError):
    """Unsafe permissions or ownership on a file/directory."""


class MissingFileError(PermValidationError):
    """File doesn't exist error."""


class FileMoveError(USGError):
    """Failed to move a file."""