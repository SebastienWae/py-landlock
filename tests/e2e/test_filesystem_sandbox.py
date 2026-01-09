import subprocess
import sys

from tests.conftest import requires_landlock


@requires_landlock
class TestFilesystemSandboxE2E:
    """E2E tests for filesystem sandboxing."""

    def test_read_allowed_path_succeeds(self) -> None:
        """Reading from allowed path should succeed."""
        code = """
import tempfile
from pathlib import Path
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    test_file = Path(tmpdir) / "test.txt"
    test_file.write_text("secret data")

    Landlock().allow_read(tmpdir).allow_all_network().allow_all_scope().apply()

    content = test_file.read_text()
    if content == "secret data":
        print("SUCCESS")
    else:
        print("FAILED: wrong content")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"

    def test_read_blocked_path_fails(self) -> None:
        """Reading from non-allowed path should fail with PermissionError."""
        code = """
import tempfile
from pathlib import Path
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as allowed_dir:
    with tempfile.TemporaryDirectory() as blocked_dir:
        blocked_file = Path(blocked_dir) / "secret.txt"
        blocked_file.write_text("secret")

        Landlock().allow_read(allowed_dir).allow_all_network().allow_all_scope().apply()

        try:
            blocked_file.read_text()
            print("FAILED: should have raised PermissionError")
        except PermissionError:
            print("SUCCESS")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"

    def test_write_allowed_path_succeeds(self) -> None:
        """Writing to allowed path should succeed."""
        code = """
import tempfile
from pathlib import Path
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    test_file = Path(tmpdir) / "output.txt"

    Landlock().allow_read_write(tmpdir).allow_all_network().allow_all_scope().apply()

    test_file.write_text("written data")
    content = test_file.read_text()
    if content == "written data":
        print("SUCCESS")
    else:
        print("FAILED")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"

    def test_write_blocked_path_fails(self) -> None:
        """Writing to non-allowed path should fail."""
        code = """
import tempfile
from pathlib import Path
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as allowed_dir:
    with tempfile.TemporaryDirectory() as blocked_dir:
        blocked_file = Path(blocked_dir) / "output.txt"

        Landlock().allow_read(allowed_dir).allow_all_network().allow_all_scope().apply()

        try:
            blocked_file.write_text("should fail")
            print("FAILED: should have raised PermissionError")
        except PermissionError:
            print("SUCCESS")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"

    def test_create_file_in_allowed_dir_succeeds(self) -> None:
        """Creating new file in allowed directory should succeed."""
        code = """
import tempfile
from pathlib import Path
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    new_file = Path(tmpdir) / "new_file.txt"

    Landlock().allow_read_write(tmpdir).allow_all_network().allow_all_scope().apply()

    new_file.write_text("new content")
    if new_file.exists() and new_file.read_text() == "new content":
        print("SUCCESS")
    else:
        print("FAILED")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"

    def test_create_directory_blocked(self) -> None:
        """Creating directory in non-allowed path should fail."""
        code = """
import tempfile
from pathlib import Path
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as allowed_dir:
    with tempfile.TemporaryDirectory() as blocked_dir:
        new_dir = Path(blocked_dir) / "newdir"

        Landlock().allow_read_write(allowed_dir).allow_all_network().allow_all_scope().apply()

        try:
            new_dir.mkdir()
            print("FAILED: should have raised PermissionError")
        except PermissionError:
            print("SUCCESS")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"

    def test_nested_paths_inherit_permissions(self) -> None:
        """Permissions should apply to nested paths."""
        code = """
import tempfile
from pathlib import Path
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    nested = Path(tmpdir) / "a" / "b" / "c"
    nested.mkdir(parents=True)
    test_file = nested / "deep.txt"
    test_file.write_text("deep content")

    Landlock().allow_read(tmpdir).allow_all_network().allow_all_scope().apply()

    content = test_file.read_text()
    if content == "deep content":
        print("SUCCESS")
    else:
        print("FAILED")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"

    def test_read_only_blocks_write(self) -> None:
        """Read-only permission should block write operations."""
        code = """
import tempfile
from pathlib import Path
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    test_file = Path(tmpdir) / "readonly.txt"
    test_file.write_text("original")

    Landlock().allow_read(tmpdir).allow_all_network().allow_all_scope().apply()

    content = test_file.read_text()
    assert content == "original"

    try:
        test_file.write_text("modified")
        print("FAILED: write should have been blocked")
    except PermissionError:
        print("SUCCESS")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"

    def test_execute_allowed_succeeds(self) -> None:
        """Executing from allowed path should succeed."""
        code = """
import tempfile
import subprocess
from pathlib import Path
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as tmpdir:
    script = Path(tmpdir) / "test.sh"
    script.write_text("#!/bin/sh\\necho EXEC_SUCCESS")
    script.chmod(0o755)

    (
        Landlock()
        .allow_read_write(tmpdir)
        .allow_read("/bin", "/usr/bin", "/lib", "/lib64", "/usr/lib")
        .allow_execute(tmpdir, "/bin", "/usr/bin", "/lib", "/lib64", "/usr/lib")
        .allow_all_network()
        .allow_all_scope()
        .apply()
    )

    result = subprocess.run([str(script)], capture_output=True, text=True)
    if "EXEC_SUCCESS" in result.stdout:
        print("SUCCESS")
    else:
        print(f"FAILED: {result.stderr}")
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
class TestFilesystemFluentAPI:
    """E2E tests for fluent API."""

    def test_chained_allow_methods(self) -> None:
        """Chained allow methods should all work."""
        code = """
import tempfile
from pathlib import Path
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as read_dir:
    with tempfile.TemporaryDirectory() as write_dir:
        read_file = Path(read_dir) / "read.txt"
        read_file.write_text("readable")

        (
            Landlock()
            .allow_read(read_dir)
            .allow_read_write(write_dir)
            .allow_all_network()
            .allow_all_scope()
            .apply()
        )

        assert read_file.read_text() == "readable"

        write_file = Path(write_dir) / "write.txt"
        write_file.write_text("written")
        assert write_file.read_text() == "written"

        try:
            (Path(read_dir) / "new.txt").write_text("fail")
            print("FAILED")
        except PermissionError:
            print("SUCCESS")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"

    def test_multiple_paths_in_single_call(self) -> None:
        """Should accept multiple paths in a single allow call."""
        code = """
import tempfile
from pathlib import Path
from py_landlock import Landlock

with tempfile.TemporaryDirectory() as dir1:
    with tempfile.TemporaryDirectory() as dir2:
        file1 = Path(dir1) / "file1.txt"
        file2 = Path(dir2) / "file2.txt"
        file1.write_text("content1")
        file2.write_text("content2")

        Landlock().allow_read(dir1, dir2).allow_all_network().allow_all_scope().apply()

        assert file1.read_text() == "content1"
        assert file2.read_text() == "content2"
        print("SUCCESS")
"""
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert "SUCCESS" in result.stdout, f"stderr: {result.stderr}"
