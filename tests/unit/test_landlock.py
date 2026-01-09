from pathlib import Path
from unittest.mock import patch

import pytest

from py_landlock.abi import ABIVersion
from py_landlock.errors import CompatibilityError, PathError, RulesetError
from py_landlock.flags import AccessFs, AccessNet, Scope
from py_landlock.landlock import Landlock


class TestLandlockAddPathRule:
    """Tests for Landlock.add_path_rule method."""

    def test_raises_path_error_for_nonexistent(self, temp_dir: Path) -> None:
        """Should raise PathError for nonexistent path."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            nonexistent = temp_dir / "does_not_exist"
            with pytest.raises(PathError) as exc_info:
                _ = ll.add_path_rule(nonexistent, access=AccessFs.READ_FILE)
            assert "does_not_exist" in str(exc_info.value.path)

    def test_accepts_existing_path(self, temp_file: Path) -> None:
        """Should accept existing path."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            result = ll.add_path_rule(temp_file, access=AccessFs.READ_FILE)
            assert result is ll

    def test_raises_after_apply(self, temp_file: Path) -> None:
        """Should raise RulesetError after apply() is called."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            ll._applied = True
            with pytest.raises(RulesetError, match="after apply"):
                _ = ll.add_path_rule(temp_file, access=AccessFs.READ_FILE)

    def test_stores_resolved_path(self, temp_file: Path) -> None:
        """Should store resolved (absolute) path."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            _ = ll.add_path_rule(temp_file, access=AccessFs.READ_FILE)
            stored_path, _ = ll._pending_path_rules[0]
            assert stored_path.is_absolute()

    def test_skips_rule_if_access_filtered_to_empty(self, temp_file: Path) -> None:
        """Should skip rule if access filtered to empty (best-effort mode)."""
        # ABI 1 doesn't support REFER, so in best-effort mode, REFER alone becomes empty
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(1)):
            ll = Landlock(strict=False)
            _ = ll.add_path_rule(temp_file, access=AccessFs.REFER)
            assert len(ll._pending_path_rules) == 0


class TestLandlockAddNetRule:
    """Tests for Landlock.add_net_rule method."""

    def test_raises_for_negative_port(self) -> None:
        """Should raise ValueError for negative port."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            with pytest.raises(ValueError, match="Port must be"):
                _ = ll.add_net_rule(-1, access=AccessNet.BIND_TCP)

    def test_raises_for_port_over_65535(self) -> None:
        """Should raise ValueError for port > 65535."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            with pytest.raises(ValueError, match="Port must be"):
                _ = ll.add_net_rule(65536, access=AccessNet.BIND_TCP)

    def test_accepts_valid_port(self) -> None:
        """Should accept valid port (0-65535)."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            result = ll.add_net_rule(443, access=AccessNet.CONNECT_TCP)
            assert result is ll

    def test_accepts_boundary_port_0(self) -> None:
        """Should accept port 0."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            _ = ll.add_net_rule(0, access=AccessNet.BIND_TCP)
            assert len(ll._pending_net_rules) == 1

    def test_accepts_boundary_port_65535(self) -> None:
        """Should accept port 65535."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            _ = ll.add_net_rule(65535, access=AccessNet.CONNECT_TCP)
            assert len(ll._pending_net_rules) == 1

    def test_raises_after_apply(self) -> None:
        """Should raise RulesetError after apply()."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            ll._applied = True
            with pytest.raises(RulesetError, match="after apply"):
                _ = ll.add_net_rule(443, access=AccessNet.CONNECT_TCP)

    def test_skips_rule_if_abi_too_old_best_effort(self) -> None:
        """Should skip rule if ABI < 4 in best-effort mode."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(3)):
            ll = Landlock(strict=False)
            _ = ll.add_net_rule(443, access=AccessNet.CONNECT_TCP)
            assert len(ll._pending_net_rules) == 0


class TestLandlockAllowScope:
    """Tests for Landlock.allow_scope method."""

    def test_raises_after_apply(self) -> None:
        """Should raise RulesetError after apply()."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(6)):
            ll = Landlock()
            ll._applied = True
            with pytest.raises(RulesetError, match="after apply"):
                _ = ll.allow_scope(Scope.SIGNAL)

    def test_accumulates_scope_flags(self) -> None:
        """Should accumulate scope flags across multiple calls."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(6)):
            ll = Landlock()
            _ = ll.allow_scope(Scope.ABSTRACT_UNIX_SOCKET)
            _ = ll.allow_scope(Scope.SIGNAL)
            assert Scope.ABSTRACT_UNIX_SOCKET in ll._allowed_scope
            assert Scope.SIGNAL in ll._allowed_scope


class TestLandlockConvenienceMethods:
    """Tests for convenience methods (allow_read, allow_write, etc.)."""

    def test_allow_read_sets_correct_flags(self, temp_dir: Path) -> None:
        """allow_read should set READ_FILE and READ_DIR flags."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            _ = ll.allow_read(temp_dir)

            assert len(ll._pending_path_rules) == 1
            _, access = ll._pending_path_rules[0]
            assert AccessFs.READ_FILE in access
            assert AccessFs.READ_DIR in access

    def test_allow_write_sets_correct_flags(self, temp_dir: Path) -> None:
        """allow_write should set write-related flags."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            _ = ll.allow_write(temp_dir)

            assert len(ll._pending_path_rules) == 1
            _, access = ll._pending_path_rules[0]
            assert AccessFs.WRITE_FILE in access
            assert AccessFs.MAKE_REG in access
            assert AccessFs.REMOVE_FILE in access
            assert AccessFs.TRUNCATE in access

    def test_allow_execute_sets_correct_flag(self, temp_dir: Path) -> None:
        """allow_execute should set EXECUTE flag."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            _ = ll.allow_execute(temp_dir)

            assert len(ll._pending_path_rules) == 1
            _, access = ll._pending_path_rules[0]
            assert AccessFs.EXECUTE in access

    def test_allow_read_write_combines_flags(self, temp_dir: Path) -> None:
        """allow_read_write should set both read and write flags."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            _ = ll.allow_read_write(temp_dir)

            _, access = ll._pending_path_rules[0]
            assert AccessFs.READ_FILE in access
            assert AccessFs.READ_DIR in access
            assert AccessFs.WRITE_FILE in access
            assert AccessFs.MAKE_REG in access


class TestLandlockAllowNetwork:
    """Tests for Landlock.allow_network method."""

    def test_raises_when_neither_bind_nor_connect(self) -> None:
        """Should raise ValueError when neither bind nor connect is True."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            with pytest.raises(ValueError, match="At least one of"):
                _ = ll.allow_network(443, bind=False, connect=False)

    def test_bind_only(self) -> None:
        """Should set only BIND_TCP when connect=False."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            _ = ll.allow_network(8080, bind=True, connect=False)

            _, access = ll._pending_net_rules[0]
            assert AccessNet.BIND_TCP in access
            assert AccessNet.CONNECT_TCP not in access

    def test_connect_only(self) -> None:
        """Should set only CONNECT_TCP when bind=False."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            _ = ll.allow_network(443, bind=False, connect=True)

            _, access = ll._pending_net_rules[0]
            assert AccessNet.CONNECT_TCP in access
            assert AccessNet.BIND_TCP not in access

    def test_both_bind_and_connect(self) -> None:
        """Should set both flags by default."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            _ = ll.allow_network(443)

            _, access = ll._pending_net_rules[0]
            assert AccessNet.BIND_TCP in access
            assert AccessNet.CONNECT_TCP in access


class TestLandlockAllowAllNetwork:
    """Tests for Landlock.allow_all_network method."""

    def test_raises_after_apply(self) -> None:
        """Should raise RulesetError after apply()."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            ll._applied = True
            with pytest.raises(RulesetError, match="after apply"):
                _ = ll.allow_all_network()


class TestLandlockAllowAllScope:
    """Tests for Landlock.allow_all_scope method."""

    def test_raises_after_apply(self) -> None:
        """Should raise RulesetError after apply()."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            ll._applied = True
            with pytest.raises(RulesetError, match="after apply"):
                _ = ll.allow_all_scope()


class TestLandlockStrictMode:
    """Tests for strict vs best-effort mode."""

    def test_strict_mode_raises_for_unsupported_fs(self, temp_dir: Path) -> None:
        """Strict mode should raise for unsupported fs flags."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(1)):
            ll = Landlock(strict=True)
            with pytest.raises(CompatibilityError, match="REFER"):
                _ = ll.add_path_rule(temp_dir, access=AccessFs.REFER)

    def test_best_effort_mode_filters_unsupported_fs(self, temp_dir: Path) -> None:
        """Best-effort mode should filter unsupported fs flags."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(1)):
            ll = Landlock(strict=False)
            _ = ll.add_path_rule(temp_dir, access=AccessFs.READ_FILE | AccessFs.REFER)

            _, access = ll._pending_path_rules[0]
            assert AccessFs.READ_FILE in access
            assert AccessFs.REFER not in access

    def test_strict_mode_raises_for_unsupported_net(self) -> None:
        """Strict mode should raise for network on ABI < 4."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(3)):
            ll = Landlock(strict=True)
            with pytest.raises(CompatibilityError):
                _ = ll.add_net_rule(443, access=AccessNet.CONNECT_TCP)

    def test_best_effort_mode_ignores_unsupported_net(self) -> None:
        """Best-effort mode should ignore network rules on ABI < 4."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(3)):
            ll = Landlock(strict=False)
            _ = ll.add_net_rule(443, access=AccessNet.CONNECT_TCP)
            assert len(ll._pending_net_rules) == 0

    def test_strict_mode_raises_for_unsupported_scope(self) -> None:
        """Strict mode should raise for scope on ABI < 6."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock(strict=True)
            with pytest.raises(CompatibilityError):
                _ = ll.allow_scope(Scope.SIGNAL)

    def test_best_effort_mode_ignores_unsupported_scope(self) -> None:
        """Best-effort mode should ignore scope on ABI < 6."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock(strict=False)
            _ = ll.allow_scope(Scope.SIGNAL)
            assert ll._allowed_scope == Scope(0)


class TestLandlockMethodChaining:
    """Tests for fluent API method chaining."""

    def test_full_chain(self, temp_dir: Path, temp_file: Path) -> None:
        """Should support full method chaining."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = (
                Landlock()
                .allow_read(temp_file)
                .allow_execute(temp_dir)
                .allow_network(443, connect=True, bind=False)
                .allow_all_scope()
            )
            assert len(ll._pending_path_rules) == 2
            assert len(ll._pending_net_rules) == 1
            assert ll._allow_all_scope is True


class TestLandlockApply:
    """Tests for Landlock.apply method (mocked)."""

    def test_raises_when_already_applied(self) -> None:
        """Should raise RulesetError when called twice."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            ll._applied = True
            with pytest.raises(RulesetError, match="after apply"):
                ll.apply()

    def test_sets_applied_flag(self) -> None:
        """apply() should set _applied flag."""
        with (
            patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)),
            patch("py_landlock.landlock.set_no_new_privs"),
            patch("py_landlock.landlock.create_ruleset", return_value=10),
            patch("py_landlock.landlock.restrict_self"),
            patch("py_landlock.landlock.os.close"),
        ):
            ll = Landlock()
            ll.apply()
            assert ll._applied is True

    def test_calls_set_no_new_privs(self) -> None:
        """apply() should call set_no_new_privs."""
        with (
            patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)),
            patch("py_landlock.landlock.set_no_new_privs") as mock_no_new_privs,
            patch("py_landlock.landlock.create_ruleset", return_value=10),
            patch("py_landlock.landlock.restrict_self"),
            patch("py_landlock.landlock.os.close"),
        ):
            ll = Landlock()
            ll.apply()
            mock_no_new_privs.assert_called_once()

    def test_calls_create_ruleset(self) -> None:
        """apply() should call create_ruleset."""
        with (
            patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)),
            patch("py_landlock.landlock.set_no_new_privs"),
            patch("py_landlock.landlock.create_ruleset", return_value=10) as mock_create,
            patch("py_landlock.landlock.restrict_self"),
            patch("py_landlock.landlock.os.close"),
        ):
            ll = Landlock()
            ll.apply()
            mock_create.assert_called_once()

    def test_calls_restrict_self(self) -> None:
        """apply() should call restrict_self."""
        with (
            patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)),
            patch("py_landlock.landlock.set_no_new_privs"),
            patch("py_landlock.landlock.create_ruleset", return_value=10),
            patch("py_landlock.landlock.restrict_self") as mock_restrict,
            patch("py_landlock.landlock.os.close"),
        ):
            ll = Landlock()
            ll.apply()
            mock_restrict.assert_called_once()

    def test_closes_ruleset_fd(self) -> None:
        """apply() should close the ruleset fd."""
        fd = 10
        with (
            patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)),
            patch("py_landlock.landlock.set_no_new_privs"),
            patch("py_landlock.landlock.create_ruleset", return_value=fd),
            patch("py_landlock.landlock.restrict_self"),
            patch("py_landlock.landlock.os.close") as mock_close,
        ):
            ll = Landlock()
            ll.apply()
            mock_close.assert_called_with(fd)


class TestLandlockEnsureNotApplied:
    """Tests for _ensure_not_applied method."""

    def test_raises_when_applied(self) -> None:
        """Should raise RulesetError when _applied is True."""
        with patch("py_landlock.landlock.get_abi_version", return_value=ABIVersion(5)):
            ll = Landlock()
            ll._applied = True
            with pytest.raises(RulesetError, match="Cannot modify"):
                ll._ensure_not_applied()
