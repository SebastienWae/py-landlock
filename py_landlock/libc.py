import ctypes.util
import platform
import sys
import threading
from typing import Protocol

from .errors import LandlockNotAvailableError

_lock = threading.Lock()
_libc: ctypes.CDLL | None = None
_initialized = False


_SUPPORTED_ARCHS = frozenset(("x86_64", "aarch64"))


class _SyscallFunc(Protocol):
    """Protocol defining the libc syscall function signature."""

    def __call__(self, __nr: int, *args: object) -> int: ...


class _PrctlFunc(Protocol):
    """Protocol defining the libc prctl function signature."""

    def __call__(self, *args: int) -> int: ...


def _ensure_initialized() -> None:
    """
    Initialize libc bindings on first use (thread-safe).

    Raises:
        LandlockNotAvailableError: Running on non-Linux platform, unsupported
            architecture, or libc could not be found.

    """
    global _libc, _initialized  # noqa: PLW0603

    if _initialized:
        return

    with _lock:
        if _initialized:
            return

        if sys.platform != "linux":
            msg = "Landlock is only available on Linux"
            raise LandlockNotAvailableError(msg)

        arch = platform.machine()
        if arch not in _SUPPORTED_ARCHS:
            msg = f"Landlock is only supported on x86_64 and aarch64, not {arch}"
            raise LandlockNotAvailableError(msg)

        libc_path = ctypes.util.find_library("c")
        if libc_path is None:
            msg = "Could not find libc"
            raise LandlockNotAvailableError(msg)

        _libc = ctypes.CDLL(libc_path, use_errno=True)

        _libc.syscall.restype = ctypes.c_long
        _libc.prctl.restype = ctypes.c_int
        _libc.prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]

        _initialized = True


def get_syscall() -> _SyscallFunc:
    """
    Get the libc syscall function, initializing libc bindings if needed.

    Returns:
        The libc syscall function for making raw system calls.

    Raises:
        LandlockNotAvailableError: Running on non-Linux platform or unsupported
            architecture, or libc could not be found.
        RuntimeError: libc was not properly loaded (should not happen in normal use).

    """
    _ensure_initialized()
    if _libc is None:
        msg = "libc not loaded"
        raise RuntimeError(msg)
    return _libc.syscall


def get_prctl() -> _PrctlFunc:
    """
    Get the libc prctl function, initializing libc bindings if needed.

    Returns:
        The libc prctl function for process control operations.

    Raises:
        LandlockNotAvailableError: Running on non-Linux platform or unsupported
            architecture, or libc could not be found.
        RuntimeError: libc was not properly loaded (should not happen in normal use).

    """
    _ensure_initialized()
    if _libc is None:
        msg = "libc not loaded"
        raise RuntimeError(msg)
    return _libc.prctl
