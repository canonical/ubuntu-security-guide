"""USG package version."""

import importlib.metadata

try:
    # try to get the version from the installed package
    # (based on value in pyproject.toml)
    __version__ = importlib.metadata.version("usg")
except importlib.metadata.PackageNotFoundError:
    __version__ = "unknown: usg not installed"
