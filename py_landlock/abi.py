from typing import NewType

from .flags import AccessFs, AccessNet, Scope

ABIVersion = NewType("ABIVersion", int)

_ACCESS_FS_V1 = (
    AccessFs.EXECUTE
    | AccessFs.WRITE_FILE
    | AccessFs.READ_FILE
    | AccessFs.READ_DIR
    | AccessFs.REMOVE_DIR
    | AccessFs.REMOVE_FILE
    | AccessFs.MAKE_CHAR
    | AccessFs.MAKE_DIR
    | AccessFs.MAKE_REG
    | AccessFs.MAKE_SOCK
    | AccessFs.MAKE_FIFO
    | AccessFs.MAKE_BLOCK
    | AccessFs.MAKE_SYM
)
_ACCESS_FS_V2 = _ACCESS_FS_V1 | AccessFs.REFER
_ACCESS_FS_V3 = _ACCESS_FS_V2 | AccessFs.TRUNCATE
_ACCESS_FS_V5 = _ACCESS_FS_V3 | AccessFs.IOCTL_DEV
_ACCESS_FS_BY_ABI: dict[ABIVersion, AccessFs] = {
    ABIVersion(1): _ACCESS_FS_V1,
    ABIVersion(2): _ACCESS_FS_V2,
    ABIVersion(3): _ACCESS_FS_V3,
    ABIVersion(4): _ACCESS_FS_V3,  # V4 added network, no new fs flags
    ABIVersion(5): _ACCESS_FS_V5,
    ABIVersion(6): _ACCESS_FS_V5,  # V6 added scope, no new fs flags
    ABIVersion(7): _ACCESS_FS_V5,  # V7 added logging, no new fs flags
}

_ACCESS_NET_V4 = AccessNet.BIND_TCP | AccessNet.CONNECT_TCP
_ACCESS_NET_BY_ABI: dict[ABIVersion, AccessNet] = {
    ABIVersion(4): _ACCESS_NET_V4,
    ABIVersion(5): _ACCESS_NET_V4,
    ABIVersion(6): _ACCESS_NET_V4,
    ABIVersion(7): _ACCESS_NET_V4,
}

_SCOPE_V6 = Scope.ABSTRACT_UNIX_SOCKET | Scope.SIGNAL
_SCOPE_BY_ABI: dict[ABIVersion, Scope] = {
    ABIVersion(6): _SCOPE_V6,
    ABIVersion(7): _SCOPE_V6,
}

MAX_KNOWN_ABI = ABIVersion(7)
MIN_FS_ABI = ABIVersion(1)
MIN_NET_ABI = ABIVersion(4)
MIN_SCOPE_ABI = ABIVersion(6)


def get_supported_fs(abi: ABIVersion) -> AccessFs:
    """
    Get the AccessFs flags supported by a given ABI version.

    Args:
        abi: The Landlock ABI version (1-7+).

    Returns:
        Combined AccessFs flags supported by that ABI version.
        Returns AccessFs(0) for abi < 1.

    """
    if abi < MIN_FS_ABI:
        return AccessFs(0)
    abi = min(abi, MAX_KNOWN_ABI)
    return _ACCESS_FS_BY_ABI[abi]


def get_supported_net(abi: ABIVersion) -> AccessNet:
    """
    Get the AccessNet flags supported by a given ABI version.

    Args:
        abi: The Landlock ABI version (1-7+).

    Returns:
        Combined AccessNet flags supported by that ABI version.
        Returns AccessNet(0) for abi < 4 (network added in V4).

    """
    if abi < MIN_NET_ABI:
        return AccessNet(0)
    abi = min(abi, MAX_KNOWN_ABI)
    return _ACCESS_NET_BY_ABI[abi]


def get_supported_scope(abi: ABIVersion) -> Scope:
    """
    Get the Scope flags supported by a given ABI version.

    Args:
        abi: The Landlock ABI version (1-7+).

    Returns:
        Combined Scope flags supported by that ABI version.
        Returns Scope(0) for abi < 6 (scope added in V6).

    """
    if abi < MIN_SCOPE_ABI:
        return Scope(0)
    abi = min(abi, MAX_KNOWN_ABI)
    return _SCOPE_BY_ABI[abi]


def get_min_abi_for_fs_flags(flags: AccessFs) -> ABIVersion:
    """
    Determine minimum ABI version needed for given filesystem flags.

    Args:
        flags: Filesystem access flags to check.

    Returns:
        Minimum ABI version required (1+), or 0 if flags is empty.

    """
    if not flags:
        return ABIVersion(0)
    for abi in range(1, MAX_KNOWN_ABI + 1):
        if (flags & _ACCESS_FS_BY_ABI[ABIVersion(abi)]) == flags:
            return ABIVersion(abi)
    return MAX_KNOWN_ABI
