from __future__ import annotations

import platform
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from py_landlock.errors import LandlockError
from py_landlock.landlock_sys import get_abi_version

if TYPE_CHECKING:
    from collections.abc import Generator


def _is_linux() -> bool:
    """Check if running on Linux."""
    return sys.platform == "linux"


def _is_supported_arch() -> bool:
    """Check if running on supported architecture."""
    return platform.machine() in ("x86_64", "aarch64")


def _get_landlock_abi_version() -> int:
    """Get Landlock ABI version from kernel via syscall, or 0 if not available."""
    if not _is_linux() or not _is_supported_arch():
        return 0
    try:
        return get_abi_version()
    except LandlockError:
        return 0


def _has_landlock_support() -> bool:
    """Check if kernel supports Landlock via syscall."""
    return _get_landlock_abi_version() > 0


def _landlock_enabled() -> bool:
    """Check if Landlock is enabled (alias for _has_landlock_support)."""
    return _has_landlock_support()


skip_not_linux = pytest.mark.skipif(not _is_linux(), reason="Landlock is only available on Linux")

skip_unsupported_arch = pytest.mark.skipif(
    not _is_supported_arch(), reason="Landlock only supported on x86_64 and aarch64"
)

requires_landlock = pytest.mark.skipif(
    not (_is_linux() and _is_supported_arch() and _has_landlock_support() and _landlock_enabled()),
    reason="Requires working Landlock (Linux, supported arch, kernel support, enabled)",
)

requires_abi_v4 = pytest.mark.skipif(_get_landlock_abi_version() < 4, reason="Requires Landlock ABI v4+")

requires_abi_v6 = pytest.mark.skipif(_get_landlock_abi_version() < 6, reason="Requires Landlock ABI v6+")


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_file(temp_dir: Path) -> Path:
    """Create a temporary file for testing."""
    filepath = temp_dir / "test_file.txt"
    _ = filepath.write_text("test content")
    return filepath
