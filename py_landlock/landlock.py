from __future__ import annotations

import os
from pathlib import Path

from .abi import (
    MIN_NET_ABI,
    MIN_SCOPE_ABI,
    ABIVersion,
    get_min_abi_for_fs_flags,
    get_supported_fs,
    get_supported_net,
    get_supported_scope,
)
from .errors import CompatibilityError, PathError, RulesetError
from .flags import AccessFs, AccessNet, Scope
from .landlock_sys import (
    NetPortAttr,
    PathBeneathAttr,
    RulesetAttr,
    add_rule,
    create_ruleset,
    get_abi_version,
    restrict_self,
)
from .prctl import set_no_new_privs

_MAX_TCP_PORT = 65535


class Landlock:
    """
    High-level Pythonic wrapper for Linux Landlock security module.

    Provides a fluent API for creating and applying filesystem and network
    sandboxing rules with automatic ABI compatibility handling.

    Args:
        strict: If True (default), raise CompatibilityError when a feature
            is not supported by the kernel. If False, silently ignore or
            downgrade unsupported features (best-effort mode).

    Example:
        >>> Landlock().allow_read("/usr", "/lib").allow_execute("/bin").apply()

        >>> (
        ...     Landlock()
        ...     .allow_read("/usr", "/lib", "/etc")
        ...     .allow_execute("/bin", "/usr/bin")
        ...     .allow_read_write("/tmp/app")
        ...     .allow_network(80, 443, bind=False, connect=True)
        ...     .apply()
        ... )

    """

    def __init__(self, *, strict: bool = True) -> None:
        """
        Initialize a new Landlock ruleset builder.

        Args:
            strict: If True (default), raise CompatibilityError for unsupported
                features. If False, silently filter to supported features.

        """
        self._strict: bool = strict
        self._applied: bool = False
        self._abi_version: ABIVersion | None = None

        self._allow_all_net: bool = False
        self._allow_all_scope: bool = False

        self._allowed_scope: Scope = Scope(0)

        self._pending_path_rules: list[tuple[Path, AccessFs]] = []
        self._pending_net_rules: list[tuple[int, AccessNet]] = []

    @property
    def abi_version(self) -> ABIVersion:
        """
        Get the kernel's Landlock ABI version (cached).

        Returns:
            The highest ABI version supported by the kernel.

        Raises:
            LandlockNotAvailableError: Landlock not available.
            LandlockDisabledError: Landlock disabled at boot.

        """
        if self._abi_version is None:
            self._abi_version = get_abi_version()
        return self._abi_version

    @property
    def applied(self) -> bool:
        """Return True if apply() has been called."""
        return self._applied

    @property
    def strict(self) -> bool:
        """Return True if running in strict mode."""
        return self._strict

    def _ensure_not_applied(self) -> None:
        """
        Raise RulesetError if apply() has been called.

        Raises:
            RulesetError: If the ruleset has already been applied.

        """
        if self._applied:
            msg = "Cannot modify Landlock ruleset after apply() has been called"
            raise RulesetError(msg)

    def _get_abi_version_typed(self) -> ABIVersion:
        """Get the ABI version (cached)."""
        if self._abi_version is None:
            self._abi_version = get_abi_version()
        return self._abi_version

    def _filter_fs_access(self, access: AccessFs) -> AccessFs:
        """
        Filter filesystem access flags to only those supported by the kernel.

        In strict mode, raises CompatibilityError for unsupported flags.
        In best-effort mode, returns only the supported subset.

        Args:
            access: Requested access flags.

        Returns:
            Filtered access flags (only supported ones).

        Raises:
            CompatibilityError: In strict mode, if any flag is unsupported.

        """
        supported = get_supported_fs(self._get_abi_version_typed())
        unsupported = access & ~supported

        if unsupported and self._strict:
            required_abi = get_min_abi_for_fs_flags(unsupported)
            feature = f"AccessFs flags {unsupported!r}"
            raise CompatibilityError(feature, required_abi, self.abi_version)

        return access & supported

    def _filter_net_access(self, access: AccessNet) -> AccessNet:
        """
        Filter network access flags to only those supported by the kernel.

        In strict mode, raises CompatibilityError for unsupported flags.
        In best-effort mode, returns only the supported subset.

        Args:
            access: Requested access flags.

        Returns:
            Filtered access flags (only supported ones).

        Raises:
            CompatibilityError: In strict mode, if network is unsupported.

        """
        supported = get_supported_net(self._get_abi_version_typed())
        unsupported = access & ~supported

        if unsupported and self._strict:
            feature = f"AccessNet flags {unsupported!r}"
            raise CompatibilityError(feature, MIN_NET_ABI, self.abi_version)

        return access & supported

    def _filter_scope(self, scope: Scope) -> Scope:
        """
        Filter scope flags to only those supported by the kernel.

        In strict mode, raises CompatibilityError for unsupported flags.
        In best-effort mode, returns only the supported subset.

        Args:
            scope: Requested scope flags.

        Returns:
            Filtered scope flags (only supported ones).

        Raises:
            CompatibilityError: In strict mode, if scope is unsupported.

        """
        supported = get_supported_scope(self._get_abi_version_typed())
        unsupported = scope & ~supported

        if unsupported and self._strict:
            feature = f"Scope flags {unsupported!r}"
            raise CompatibilityError(feature, MIN_SCOPE_ABI, self.abi_version)

        return scope & supported

    def add_path_rule(self, *paths: str | os.PathLike[str], access: AccessFs) -> Landlock:
        """
        Add a filesystem access rule for one or more paths.

        Args:
            *paths: One or more paths to files or directories.
            access: AccessFs flags specifying allowed operations.

        Returns:
            Self for method chaining.

        Raises:
            PathError: If any path does not exist.
            RulesetError: If apply() was already called.
            CompatibilityError: In strict mode, if any access flag unsupported.

        """
        self._ensure_not_applied()

        filtered_access = self._filter_fs_access(access)

        if not filtered_access:
            return self

        for path in paths:
            resolved_path = Path(path).resolve()
            if not resolved_path.exists():
                raise PathError(str(path))

            self._pending_path_rules.append((resolved_path, filtered_access))

        return self

    def add_net_rule(self, *ports: int, access: AccessNet) -> Landlock:
        """
        Add a network access rule for one or more TCP ports.

        Args:
            *ports: One or more TCP port numbers (0-65535).
            access: AccessNet flags (BIND_TCP, CONNECT_TCP).

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If any port is out of range.
            RulesetError: If apply() was already called.
            CompatibilityError: In strict mode, if network unsupported.

        """
        self._ensure_not_applied()

        for port in ports:
            if not (0 <= port <= _MAX_TCP_PORT):
                msg = f"Port must be 0-{_MAX_TCP_PORT}, got {port}"
                raise ValueError(msg)

        filtered_access = self._filter_net_access(access)

        if not filtered_access:
            return self

        for port in ports:
            self._pending_net_rules.append((port, filtered_access))

        return self

    def allow_scope(self, scope: Scope) -> Landlock:
        """
        Disable specific scope restrictions selectively.

        By default, all scope restrictions are enabled (blocking abstract UNIX
        socket connections and signal delivery outside the Landlock domain).
        Call this method to disable specific restrictions while keeping others active.

        Example:
            # Allow abstract UNIX sockets, but still block signals outside domain
            Landlock().allow_scope(Scope.ABSTRACT_UNIX_SOCKET).apply()

        Args:
            scope: Scope flags to ALLOW (i.e., disable restriction for).

        Returns:
            Self for method chaining.

        Raises:
            RulesetError: If apply() was already called.
            CompatibilityError: In strict mode, if scope unsupported (ABI < 6).

        """
        self._ensure_not_applied()

        filtered_scope = self._filter_scope(scope)

        if filtered_scope:
            self._allowed_scope |= filtered_scope

        return self

    def allow_read(self, *paths: str | os.PathLike[str]) -> Landlock:
        """
        Allow reading files and listing directories under the given paths.

        Args:
            *paths: One or more paths to files or directories.

        Returns:
            Self for method chaining.

        Raises:
            PathError: If any path does not exist.
            RulesetError: If apply() was already called.
            CompatibilityError: In strict mode, if features unsupported.

        """
        access = AccessFs.READ_FILE | AccessFs.READ_DIR
        return self.add_path_rule(*paths, access=access)

    def allow_write(self, *paths: str | os.PathLike[str]) -> Landlock:
        """
        Allow writing to files under the given paths.

        Includes creating, modifying, truncating, and removing files/dirs.
        Does not include REFER (cross-directory ops) or device creation.

        Args:
            *paths: One or more paths to allow writing.

        Returns:
            Self for method chaining.

        Raises:
            PathError: If any path does not exist.
            RulesetError: If apply() was already called.
            CompatibilityError: In strict mode, if features unsupported.

        """
        access = (
            AccessFs.WRITE_FILE
            | AccessFs.TRUNCATE
            | AccessFs.MAKE_REG
            | AccessFs.MAKE_DIR
            | AccessFs.MAKE_SYM
            | AccessFs.REMOVE_FILE
            | AccessFs.REMOVE_DIR
        )
        return self.add_path_rule(*paths, access=access)

    def allow_execute(self, *paths: str | os.PathLike[str]) -> Landlock:
        """
        Allow executing files under the given paths.

        Args:
            *paths: One or more paths to allow execution from.

        Returns:
            Self for method chaining.

        Raises:
            PathError: If any path does not exist.
            RulesetError: If apply() was already called.
            CompatibilityError: In strict mode, if features unsupported.

        """
        return self.add_path_rule(*paths, access=AccessFs.EXECUTE)

    def allow_read_write(self, *paths: str | os.PathLike[str]) -> Landlock:
        """
        Allow both reading and writing under the given paths.

        Convenience method combining allow_read() and allow_write() flags.

        Args:
            *paths: One or more paths to allow read/write access.

        Returns:
            Self for method chaining.

        Raises:
            PathError: If any path does not exist.
            RulesetError: If apply() was already called.
            CompatibilityError: In strict mode, if features unsupported.

        """
        access = (
            AccessFs.READ_FILE
            | AccessFs.READ_DIR
            | AccessFs.WRITE_FILE
            | AccessFs.TRUNCATE
            | AccessFs.MAKE_REG
            | AccessFs.MAKE_DIR
            | AccessFs.MAKE_SYM
            | AccessFs.REMOVE_FILE
            | AccessFs.REMOVE_DIR
        )
        return self.add_path_rule(*paths, access=access)

    def allow_network(
        self,
        *ports: int,
        bind: bool = True,
        connect: bool = True,
    ) -> Landlock:
        """
        Allow network access to specific TCP ports.

        Args:
            *ports: One or more TCP port numbers (0-65535).
            bind: Allow binding to these ports.
            connect: Allow connecting to these ports.

        Returns:
            Self for method chaining.

        Raises:
            ValueError: If any port is out of range or neither bind nor connect is True.
            RulesetError: If apply() was already called.
            CompatibilityError: In strict mode, if network unsupported (ABI < 4).

        """
        if not bind and not connect:
            msg = "At least one of bind or connect must be True"
            raise ValueError(msg)

        access = AccessNet(0)
        if bind:
            access |= AccessNet.BIND_TCP
        if connect:
            access |= AccessNet.CONNECT_TCP

        return self.add_net_rule(*ports, access=access)

    def allow_all_network(self) -> Landlock:
        """
        Disable network sandboxing (allow all TCP bind/connect).

        By default, the ruleset blocks all network access. Call this method
        to allow unrestricted network access while still enforcing filesystem rules.

        Returns:
            Self for method chaining.

        Raises:
            RulesetError: If apply() was already called.

        """
        self._ensure_not_applied()
        self._allow_all_net = True
        return self

    def allow_all_scope(self) -> Landlock:
        """
        Disable all scope restrictions (allow unrestricted IPC and signals).

        By default, the ruleset restricts abstract UNIX socket connections
        and signal delivery to processes within the Landlock domain. Call this
        method to allow unrestricted IPC and signals.

        Returns:
            Self for method chaining.

        Raises:
            RulesetError: If apply() was already called.

        """
        self._ensure_not_applied()
        self._allow_all_scope = True
        return self

    def apply(self) -> None:
        """
        Apply the Landlock ruleset to the current thread.

        This method:
        1. Calls set_no_new_privs() to prevent privilege escalation
        2. Creates the ruleset with accumulated handled access flags
        3. Adds all pending rules to the ruleset
        4. Calls restrict_self() to enforce the ruleset
        5. Closes the ruleset fd

        After calling apply(), no more rules can be added and calling
        apply() again will raise RulesetError.

        Raises:
            RulesetError: If apply() was already called.
            LandlockNotAvailableError: If Landlock syscalls unavailable.
            LandlockDisabledError: If Landlock disabled at boot.

        """
        self._ensure_not_applied()

        set_no_new_privs()

        abi = self._get_abi_version_typed()

        attr = RulesetAttr()
        attr.handled_access_fs = get_supported_fs(abi)

        if abi >= MIN_NET_ABI and not self._allow_all_net:
            attr.handled_access_net = get_supported_net(abi)
        else:
            attr.handled_access_net = AccessNet(0)

        if abi >= MIN_SCOPE_ABI and not self._allow_all_scope:
            all_scope = get_supported_scope(abi)
            attr.scoped = all_scope & ~self._allowed_scope
        else:
            attr.scoped = Scope(0)

        ruleset_fd = create_ruleset(attr)

        try:
            for resolved_path, access in self._pending_path_rules:
                fd = os.open(str(resolved_path), os.O_PATH | os.O_CLOEXEC)
                try:
                    rule_attr = PathBeneathAttr()
                    rule_attr.allowed_access = access
                    rule_attr.parent_fd = fd
                    add_rule(ruleset_fd, rule_attr)
                finally:
                    os.close(fd)

            for port, access in self._pending_net_rules:
                rule_attr = NetPortAttr()
                rule_attr.allowed_access = access
                rule_attr.port = port
                add_rule(ruleset_fd, rule_attr)

            restrict_self(ruleset_fd, None)

        finally:
            os.close(ruleset_fd)

        self._applied = True
