import ctypes
import errno

from .errors import LandlockNotAvailableError, RulesetError
from .libc import get_prctl

_PR_SET_NO_NEW_PRIVS = 38


def set_no_new_privs() -> None:
    """
    Set the PR_SET_NO_NEW_PRIVS flag to prevent privilege escalation.

    This must be called before restrict_self() unless the process has
    CAP_SYS_ADMIN in its namespace. Once set, this flag cannot be unset
    and is inherited by child processes.

    Raises:
        LandlockNotAvailableError: PR_SET_NO_NEW_PRIVS not supported (kernel < 3.5),
            or running on non-Linux platform or unsupported architecture.
        RulesetError: prctl arguments caused a memory fault or other syscall error.

    """
    prctl = get_prctl()
    result = prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if result != 0:
        err = ctypes.get_errno()
        if err == errno.EINVAL:
            msg = "PR_SET_NO_NEW_PRIVS not supported (kernel too old, requires >= 3.5)"
            raise LandlockNotAvailableError(msg)
        if err == errno.EFAULT:
            msg = "prctl arguments caused a memory fault"
            raise RulesetError(msg)
        msg = f"prctl(PR_SET_NO_NEW_PRIVS) failed: {errno.errorcode.get(err, 'unknown')} ({err})"
        raise RulesetError(msg)
