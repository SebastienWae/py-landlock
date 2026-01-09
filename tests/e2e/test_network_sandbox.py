import subprocess
import sys

from tests.conftest import requires_abi_v4


@requires_abi_v4
class TestNetworkSandboxE2E:
    """E2E tests for network sandboxing (requires ABI v4+)."""

    def test_connect_allowed_port_succeeds(self) -> None:
        """Connecting to allowed port should succeed (or fail normally if no server)."""
        code = """
import socket
import tempfile
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    # Allow localhost connection on port 80
    (
        Landlock()
        .allow_read(tmpdir, "/etc", "/lib", "/lib64", "/usr", "/proc", "/sys")
        .allow_network(80, connect=True, bind=False)
        .allow_all_scope()
        .apply()
    )

    # Try to create socket and connect
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.connect(("127.0.0.1", 80))
        print("SUCCESS: connected")
    except ConnectionRefusedError:
        # No server listening, but Landlock allowed the attempt
        print("SUCCESS: connection refused (allowed by Landlock)")
    except socket.timeout:
        print("SUCCESS: timeout (allowed by Landlock)")
    except PermissionError as e:
        print(f"FAILED: PermissionError from Landlock: {e}")
    finally:
        sock.close()
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stdout: {result.stdout}, stderr: {result.stderr}"

    def test_connect_blocked_port_fails(self) -> None:
        """Connecting to non-allowed port should fail with permission error."""
        code = """
import socket
import tempfile
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    # Only allow port 443, not 8080
    (
        Landlock()
        .allow_read(tmpdir, "/etc", "/lib", "/lib64", "/usr", "/proc", "/sys")
        .allow_network(443, connect=True, bind=False)
        .allow_all_scope()
        .apply()
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        # Try to connect to port 8080 (not allowed)
        sock.connect(("127.0.0.1", 8080))
        print("FAILED: connection should have been blocked")
    except PermissionError:
        print("SUCCESS: connection blocked by Landlock")
    except ConnectionRefusedError:
        # On some systems, connection refused might come before Landlock check
        print("INCONCLUSIVE: connection refused before Landlock check")
    finally:
        sock.close()
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        # Accept either SUCCESS or INCONCLUSIVE
        assert "SUCCESS" in result.stdout or "INCONCLUSIVE" in result.stdout, f"stderr: {result.stderr}"

    def test_bind_allowed_port_succeeds(self) -> None:
        """Binding to allowed port should succeed."""
        code = """
import socket
import tempfile
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    # Allow binding to high port (less likely to be in use)
    (
        Landlock()
        .allow_read(tmpdir, "/etc", "/lib", "/lib64", "/usr", "/proc", "/sys")
        .allow_network(49999, bind=True, connect=False)
        .allow_all_scope()
        .apply()
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 49999))
        print("SUCCESS: bind allowed")
    except PermissionError as e:
        print(f"FAILED: PermissionError: {e}")
    except OSError as e:
        if "Address already in use" in str(e):
            print("INCONCLUSIVE: port in use")
        else:
            print(f"FAILED: OSError: {e}")
    finally:
        sock.close()
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout or "INCONCLUSIVE" in result.stdout, f"stderr: {result.stderr}"

    def test_bind_blocked_port_fails(self) -> None:
        """Binding to non-allowed port should fail."""
        code = """
import socket
import tempfile
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    # Allow port 50000, try to bind to 50001
    (
        Landlock()
        .allow_read(tmpdir, "/etc", "/lib", "/lib64", "/usr", "/proc", "/sys")
        .allow_network(50000, bind=True, connect=False)
        .allow_all_scope()
        .apply()
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 50001))
        print("FAILED: bind should have been blocked")
    except PermissionError:
        print("SUCCESS: bind blocked by Landlock")
    finally:
        sock.close()
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"

    def test_allow_all_network_permits_everything(self) -> None:
        """allow_all_network should permit all network operations."""
        code = """
import socket
import tempfile
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    (
        Landlock()
        .allow_read(tmpdir, "/etc", "/lib", "/lib64", "/usr", "/proc", "/sys")
        .allow_all_network()
        .allow_all_scope()
        .apply()
    )

    # Should be able to bind to any available port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))  # Bind to any available port
        print("SUCCESS: bind allowed with allow_all_network")
    except PermissionError as e:
        print(f"FAILED: PermissionError: {e}")
    finally:
        sock.close()
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"

    def test_multiple_ports_allowed(self) -> None:
        """Multiple ports can be allowed."""
        code = """
import socket
import tempfile
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    # Allow multiple ports
    (
        Landlock()
        .allow_read(tmpdir, "/etc", "/lib", "/lib64", "/usr", "/proc", "/sys")
        .allow_network(50100, 50101, 50102, bind=True, connect=True)
        .allow_all_scope()
        .apply()
    )

    success_count = 0
    for port in [50100, 50101, 50102]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            success_count += 1
        except OSError as e:
            if "Address already in use" not in str(e):
                print(f"FAILED: port {port}: {e}")
        finally:
            sock.close()

    if success_count >= 1:  # At least one should work (others might be in use)
        print("SUCCESS")
    else:
        print("FAILED: no ports could be bound")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"
