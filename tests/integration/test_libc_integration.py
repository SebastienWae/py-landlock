from tests.conftest import skip_not_linux, skip_unsupported_arch


@skip_not_linux
@skip_unsupported_arch
class TestLibcIntegration:
    """Integration tests for libc loading."""

    def test_libc_loads_successfully(self) -> None:
        """Should load libc successfully on supported systems."""
        from py_landlock.libc import get_syscall

        syscall = get_syscall()
        assert callable(syscall)

    def test_prctl_loads_successfully(self) -> None:
        """Should load prctl successfully on supported systems."""
        from py_landlock.libc import get_prctl

        prctl = get_prctl()
        assert callable(prctl)

    def test_multiple_calls_return_same_function(self) -> None:
        """Multiple calls should return the same function (cached)."""
        from py_landlock.libc import get_syscall

        syscall1 = get_syscall()
        syscall2 = get_syscall()
        assert syscall1 is syscall2

    def test_prctl_multiple_calls_return_same_function(self) -> None:
        """Multiple prctl calls should return the same function (cached)."""
        from py_landlock.libc import get_prctl

        prctl1 = get_prctl()
        prctl2 = get_prctl()
        assert prctl1 is prctl2
