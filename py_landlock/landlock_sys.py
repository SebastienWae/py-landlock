import ctypes
import errno
from enum import IntFlag
from typing import NewType

from .abi import ABIVersion
from .errors import (
    LandlockDisabledError,
    LandlockNotAvailableError,
    NetworkDisabledError,
    RulesetError,
)
from .libc import get_syscall

RulesetFd = NewType("RulesetFd", int)

_LANDLOCK_CREATE_RULESET = 444
_LANDLOCK_ADD_RULE = 445
_LANDLOCK_RESTRICT_SELF = 446

_LANDLOCK_RULE_PATH_BENEATH = 1
_LANDLOCK_RULE_NET_PORT = 2

_LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
_LANDLOCK_CREATE_RULESET_ERRATA = 1 << 1


class RestrictSelfFlag(IntFlag):
    """
    Flags for restrict_self() to control audit logging behavior.

    Attributes:
        LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF: Disable logging for the current
            executable (useful to reduce noise from self-imposed restrictions).
        LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON: Enable logging for newly executed
            programs (logs denials after execve).
        LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF: Disable logging for nested
            Landlock domains created by this process.

    """

    LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF = 1 << 0
    LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON = 1 << 1
    LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF = 1 << 2


class RulesetAttr(ctypes.Structure):
    """
    Attributes for creating a Landlock ruleset via create_ruleset().

    Attributes:
        handled_access_fs: Bitmask of filesystem access rights that this ruleset
            will handle. Only rights included here can be granted by rules.
        handled_access_net: Bitmask of network access rights (e.g., bind, connect)
            that this ruleset will handle. Requires ABI v4+.
        scoped: Bitmask of scoping flags to restrict IPC and signals.
            Requires ABI v5+.

    """

    RULE_TYPE: int = _LANDLOCK_RULE_PATH_BENEATH

    _fields_ = (  # pyright: ignore[reportUnannotatedClassAttribute]
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    )


class PathBeneathAttr(ctypes.Structure):
    """
    Attributes for a filesystem path rule (LANDLOCK_RULE_PATH_BENEATH).

    Grants the specified access rights to a directory or file and all its
    descendants (for directories).

    Attributes:
        allowed_access: Bitmask of filesystem access rights to grant for this path.
            Must be a subset of the ruleset's handled_access_fs.
        parent_fd: Open file descriptor to the target directory or file.
            The fd can be closed after add_rule() returns.

    """

    RULE_TYPE: int = _LANDLOCK_RULE_PATH_BENEATH

    _fields_ = (  # pyright: ignore[reportUnannotatedClassAttribute]
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    )


class NetPortAttr(ctypes.Structure):
    """
    Attributes for a network port rule (LANDLOCK_RULE_NET_PORT).

    Grants the specified network access rights for a specific TCP port.
    Requires ABI v4+.

    Attributes:
        allowed_access: Bitmask of network access rights to grant (bind/connect).
            Must be a subset of the ruleset's handled_access_net.
        port: TCP port number (0-65535) to grant access to.

    """

    RULE_TYPE: int = _LANDLOCK_RULE_NET_PORT

    _fields_ = (  # pyright: ignore[reportUnannotatedClassAttribute]
        ("allowed_access", ctypes.c_uint64),
        ("port", ctypes.c_uint64),
    )


def _handle_landlock_create_ruleset_errno(result: int) -> None:
    """Handle errno for sys_landlock_create_ruleset()."""
    if result < 0:
        err = ctypes.get_errno()
        if err == errno.ENOSYS:
            msg = "Landlock syscalls not available (kernel too old or not built with Landlock)"
            raise LandlockNotAvailableError(msg)
        if err == errno.EOPNOTSUPP:
            msg = "Landlock is supported by the kernel but disabled at boot time"
            raise LandlockDisabledError(msg)
        if err == errno.EINVAL:
            msg = "unknown flags, or unknown access, or unknown scope, or too small size"
            raise RulesetError(msg)
        if err == errno.E2BIG:
            msg = "attr or size inconsistencies"
            raise RulesetError(msg)
        if err == errno.EFAULT:
            msg = "attr or size inconsistencies"
            raise RulesetError(msg)
        if err == errno.ENOMSG:
            msg = "empty landlock_ruleset_attr.handled_access_fs"
            raise RulesetError(msg)
        msg = f"landlock_create_ruleset failed: {errno.errorcode.get(err, 'unknown')} ({err})"
        raise RulesetError(msg)


def get_abi_version() -> ABIVersion:
    """
    Get the highest supported Landlock ABI version (starting at 1).

    Returns:
        The highest Landlock ABI version supported by the kernel.

    Raises:
        LandlockNotAvailableError: Landlock syscalls not available (kernel too old
            or not built with Landlock support).
        LandlockDisabledError: Landlock is supported but disabled at boot time.
        RulesetError: Invalid flags or other syscall errors.

    """
    syscall = get_syscall()
    result = syscall(
        _LANDLOCK_CREATE_RULESET,
        None,
        ctypes.c_size_t(0),
        ctypes.c_uint32(_LANDLOCK_CREATE_RULESET_VERSION),
    )
    _handle_landlock_create_ruleset_errno(result)
    return ABIVersion(result)


def get_abi_errata() -> int:
    """
    Get a bitmask of fixed issues for the current Landlock ABI version.

    Returns:
        A bitmask indicating which errata have been fixed in this kernel version.

    Raises:
        LandlockNotAvailableError: Landlock syscalls not available (kernel too old
            or not built with Landlock support).
        LandlockDisabledError: Landlock is supported but disabled at boot time.
        RulesetError: Invalid flags or other syscall errors.

    """
    syscall = get_syscall()
    result = syscall(
        _LANDLOCK_CREATE_RULESET,
        None,
        ctypes.c_size_t(0),
        ctypes.c_uint32(_LANDLOCK_CREATE_RULESET_ERRATA),
    )
    _handle_landlock_create_ruleset_errno(result)
    return result


def create_ruleset(attr: RulesetAttr) -> RulesetFd:
    """
    Create a Landlock ruleset.

    Args:
        attr: Ruleset attributes specifying handled access rights.

    Returns:
        A file descriptor for the new ruleset.

    Raises:
        LandlockNotAvailableError: Landlock syscalls not available (kernel too old
            or not built with Landlock support).
        LandlockDisabledError: Landlock is supported but disabled at boot time.
        RulesetError: Invalid attributes, empty handled_access_fs, or other
            syscall errors.

    """
    syscall = get_syscall()
    result = syscall(
        _LANDLOCK_CREATE_RULESET,
        ctypes.byref(attr),
        ctypes.c_size_t(ctypes.sizeof(attr)),
        ctypes.c_uint32(0),
    )
    _handle_landlock_create_ruleset_errno(result)
    return RulesetFd(result)


def add_rule(ruleset_fd: RulesetFd, attr: PathBeneathAttr | NetPortAttr) -> None:
    """
    Add a rule to a Landlock ruleset.

    Args:
        ruleset_fd: File descriptor for the ruleset to modify.
        attr: Rule attributes (PathBeneathAttr for filesystem rules,
            NetPortAttr for network rules).

    Raises:
        NetworkDisabledError: TCP/IP is not supported by the kernel (CONFIG_INET=n).
        RulesetError: Invalid arguments, empty accesses, invalid file descriptor,
            permission denied, or other syscall errors.

    """
    syscall = get_syscall()
    result = syscall(
        _LANDLOCK_ADD_RULE,
        ctypes.c_int(ruleset_fd),
        ctypes.c_int(attr.RULE_TYPE),
        ctypes.byref(attr),
        ctypes.c_uint32(0),
    )

    if result < 0:
        err = ctypes.get_errno()
        if err == errno.EAFNOSUPPORT:
            msg = "TCP/IP is not supported by the running kernel (CONFIG_INET=n)"
            raise NetworkDisabledError(msg)
        if err == errno.EINVAL:
            msg = (
                "invalid argument: flags is not 0, "
                "or rule accesses are not a subset of the ruleset handled accesses, "
                "or port is greater than 65535"
            )
            raise RulesetError(msg)
        if err == errno.ENOMSG:
            msg = "empty accesses (allowed_access is 0)"
            raise RulesetError(msg)
        if err == errno.EBADF:
            msg = (
                "ruleset_fd is not a file descriptor for the current thread, "
                "or a member of rule_attr is not a file descriptor as expected"
            )
            raise RulesetError(msg)
        if err == errno.EPERM:
            msg = "ruleset_fd has no write access to the underlying ruleset"
            raise RulesetError(msg)
        if err == errno.EFAULT:
            msg = "rule_attr was not a valid address"
            raise RulesetError(msg)
        msg = f"landlock_add_rule failed: {errno.errorcode.get(err, 'unknown')} ({err})"
        raise RulesetError(msg)


def restrict_self(
    ruleset_fd: RulesetFd,
    flags: RestrictSelfFlag | None,
) -> None:
    """
    Apply a Landlock ruleset to the current thread.

    Args:
        ruleset_fd: File descriptor for the ruleset to apply.
        flags: Optional flags to control logging behavior, or None for defaults.

    Raises:
        LandlockDisabledError: Landlock is supported but disabled at boot time.
        RulesetError: Invalid flags, invalid file descriptor, permission denied
            (no_new_privs not set or missing CAP_SYS_ADMIN), or maximum stacked
            rulesets limit exceeded.

    """
    syscall = get_syscall()
    flag_value = 0 if flags is None else int(flags)
    result = syscall(
        _LANDLOCK_RESTRICT_SELF,
        ctypes.c_int(ruleset_fd),
        ctypes.c_uint32(flag_value),
    )

    if result < 0:
        err = ctypes.get_errno()
        if err == errno.EOPNOTSUPP:
            msg = "Landlock is supported by the kernel but disabled at boot time"
            raise LandlockDisabledError(msg)
        if err == errno.EINVAL:
            msg = "flags contains an unknown bit"
            raise RulesetError(msg)
        if err == errno.EBADF:
            msg = "ruleset_fd is not a file descriptor for the current thread"
            raise RulesetError(msg)
        if err == errno.EPERM:
            msg = (
                "ruleset_fd has no read access to the underlying ruleset, "
                "or the current thread is not running with no_new_privs, "
                "or it doesn't have CAP_SYS_ADMIN in its namespace"
            )
            raise RulesetError(msg)
        if err == errno.E2BIG:
            msg = "the maximum number of stacked rulesets is reached for the current thread"
            raise RulesetError(msg)
        msg = f"landlock_restrict_self failed: {errno.errorcode.get(err, 'unknown')} ({err})"
        raise RulesetError(msg)
