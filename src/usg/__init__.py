"""USG.

This package contains the core module
and CLI for the Ubuntu Security Guide (USG).

"""

from usg.usg import USG, USGError
from usg.version import __version__

__all__ = ["USG", "USGError", "__version__"]
