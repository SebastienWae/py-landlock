import os
import subprocess
import sys

from tests.conftest import requires_abi_v4, requires_landlock


@requires_landlock
class TestLandlockSyscallIntegration:
    """Integration tests for Landlock syscalls."""

    def test_get_abi_version_returns_positive(self) -> None:
        """get_abi_version should return a positive integer."""
        from py_landlock.landlock_sys import get_abi_version

        version = get_abi_version()
        assert version >= 1
        assert version <= 20  # Reasonable upper bound for future versions

    def test_get_abi_errata_returns_int(self) -> None:
        """get_abi_errata should return an integer."""
        from py_landlock.landlock_sys import get_abi_errata

        errata = get_abi_errata()
        assert isinstance(errata, int)
        assert errata >= 0

    def test_create_ruleset_returns_fd(self) -> None:
        """create_ruleset should return a valid file descriptor."""
        from py_landlock.abi import get_supported_fs
        from py_landlock.landlock_sys import RulesetAttr, create_ruleset, get_abi_version

        attr = RulesetAttr()
        abi = get_abi_version()
        attr.handled_access_fs = get_supported_fs(abi)

        fd = create_ruleset(attr)
        try:
            assert fd >= 0
            _ = os.fstat(fd)
        finally:
            os.close(fd)

    def test_create_ruleset_and_close(self) -> None:
        """Should be able to create and close a ruleset."""
        from py_landlock.flags import AccessFs
        from py_landlock.landlock_sys import RulesetAttr, create_ruleset

        attr = RulesetAttr()
        attr.handled_access_fs = AccessFs.READ_FILE

        fd = create_ruleset(attr)
        os.close(fd)

    def test_full_workflow_in_subprocess(self) -> None:
        """Test complete workflow: create ruleset, add rule, restrict_self."""
        code = """
import os
import tempfile
from py_landlock.landlock_sys import (
    create_ruleset, add_rule, restrict_self,
    RulesetAttr, PathBeneathAttr, get_abi_version
)
from py_landlock.abi import get_supported_fs
from py_landlock.prctl import set_no_new_privs
from py_landlock.flags import AccessFs

with tempfile.NamedTemporaryFile(delete=False) as f:
    test_path = f.name
    f.write(b"test")

tmp_dir = os.path.dirname(test_path)

set_no_new_privs()

attr = RulesetAttr()
abi = get_abi_version()
attr.handled_access_fs = get_supported_fs(abi)

ruleset_fd = create_ruleset(attr)

path_fd = os.open(test_path, os.O_PATH | os.O_CLOEXEC)
try:
    rule_attr = PathBeneathAttr()
    rule_attr.allowed_access = AccessFs.READ_FILE
    rule_attr.parent_fd = path_fd
    add_rule(ruleset_fd, rule_attr)
finally:
    os.close(path_fd)

tmp_fd = os.open(tmp_dir, os.O_PATH | os.O_CLOEXEC)
try:
    rule_attr = PathBeneathAttr()
    rule_attr.allowed_access = AccessFs.REMOVE_FILE
    rule_attr.parent_fd = tmp_fd
    add_rule(ruleset_fd, rule_attr)
finally:
    os.close(tmp_fd)

restrict_self(ruleset_fd, None)
os.close(ruleset_fd)

os.unlink(test_path)

print("SUCCESS")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "SUCCESS" in result.stdout


@requires_abi_v4
class TestNetworkSyscallIntegration:
    """Integration tests for network Landlock syscalls (ABI v4+)."""

    def test_can_add_net_rule(self) -> None:
        """Should be able to add a network rule."""
        code = """
import os
from py_landlock.landlock_sys import (
    create_ruleset, add_rule,
    RulesetAttr, NetPortAttr, get_abi_version
)
from py_landlock.abi import get_supported_fs, get_supported_net
from py_landlock.flags import AccessNet

attr = RulesetAttr()
abi = get_abi_version()
attr.handled_access_fs = get_supported_fs(abi)
attr.handled_access_net = get_supported_net(abi)

ruleset_fd = create_ruleset(attr)
try:
    net_attr = NetPortAttr()
    net_attr.allowed_access = AccessNet.CONNECT_TCP
    net_attr.port = 443
    add_rule(ruleset_fd, net_attr)
    print("SUCCESS")
finally:
    os.close(ruleset_fd)
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "SUCCESS" in result.stdout

    def test_can_add_multiple_net_rules(self) -> None:
        """Should be able to add multiple network rules."""
        code = """
import os
from py_landlock.landlock_sys import (
    create_ruleset, add_rule,
    RulesetAttr, NetPortAttr, get_abi_version
)
from py_landlock.abi import get_supported_fs, get_supported_net
from py_landlock.flags import AccessNet

attr = RulesetAttr()
abi = get_abi_version()
attr.handled_access_fs = get_supported_fs(abi)
attr.handled_access_net = get_supported_net(abi)

ruleset_fd = create_ruleset(attr)
try:
    for port in [80, 443, 8080]:
        net_attr = NetPortAttr()
        net_attr.allowed_access = AccessNet.CONNECT_TCP | AccessNet.BIND_TCP
        net_attr.port = port
        add_rule(ruleset_fd, net_attr)
    print("SUCCESS")
finally:
    os.close(ruleset_fd)
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "SUCCESS" in result.stdout
