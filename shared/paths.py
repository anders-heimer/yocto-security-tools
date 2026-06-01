# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""XDG Base Directory compliant paths for yocto-security-tools.

Follows https://specifications.freedesktop.org/basedir-spec/latest/
Override with CVE_TOOLS_DATA_DIR / CVE_TOOLS_CACHE_DIR for CI environments.
"""
import os
from pathlib import Path

_APP = "yocto-security-tools"


def data_dir() -> Path:
    """Persistent data: repos, knowledge base, results."""
    base = os.environ.get("CVE_TOOLS_DATA_DIR") or os.environ.get(
        "XDG_DATA_HOME", str(Path.home() / ".local" / "share")
    )
    return Path(base) / _APP


def cache_dir() -> Path:
    """Expendable cache: API responses, downloaded CVE JSON."""
    base = os.environ.get("CVE_TOOLS_CACHE_DIR") or os.environ.get(
        "XDG_CACHE_HOME", str(Path.home() / ".cache")
    )
    return Path(base) / _APP
