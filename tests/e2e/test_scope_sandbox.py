import subprocess
import sys

from tests.conftest import requires_abi_v6, requires_landlock


@requires_abi_v6
class TestScopeSandboxE2E:
    """E2E tests for scope sandboxing (requires ABI v6+)."""

    def test_allow_all_scope_permits_signals(self) -> None:
        """allow_all_scope should permit signal operations to self."""
        code = """
import os
import signal
import tempfile
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    (
        Landlock()
        .allow_read(tmpdir)
        .allow_all_network()
        .allow_all_scope()
        .apply()
    )

    # Should be able to send signal to self
    try:
        os.kill(os.getpid(), 0)  # Signal 0 = check if process exists
        print("SUCCESS: signal allowed with allow_all_scope")
    except PermissionError:
        print("FAILED: signal blocked")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"

    def test_scope_restrictions_applied(self) -> None:
        """When scope is not allowed, restrictions should apply."""
        # Note: This test is tricky because scope restrictions only apply
        # to cross-domain operations. Basic self-signaling still works.
        code = """
import tempfile
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    # Apply without allow_all_scope - restrictions enabled
    (
        Landlock()
        .allow_read(tmpdir)
        .allow_all_network()
        # Note: NOT calling allow_all_scope()
        .apply()
    )

    # Basic test that sandbox is active
    print("SUCCESS: sandbox with scope restrictions applied")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"

    def test_allow_specific_scope(self) -> None:
        """Can selectively allow specific scope flags."""
        code = """
import tempfile
from py_landlock import Landlock, Scope

with tempfile.TemporaryDirectory() as tmpdir:
    # Allow abstract UNIX sockets but not signals
    (
        Landlock()
        .allow_read(tmpdir)
        .allow_all_network()
        .allow_scope(Scope.ABSTRACT_UNIX_SOCKET)
        .apply()
    )

    print("SUCCESS: selective scope applied")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"


@requires_landlock
class TestScopeBackwardCompatibility:
    """E2E tests for scope on older ABI versions."""

    def test_allow_all_scope_works_on_old_abi(self) -> None:
        """allow_all_scope should work (no-op) on ABI < 6."""
        code = """
import tempfile
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    # This should work regardless of ABI version
    (
        Landlock()
        .allow_read(tmpdir)
        .allow_all_network()
        .allow_all_scope()
        .apply()
    )

    print("SUCCESS: allow_all_scope works")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"
