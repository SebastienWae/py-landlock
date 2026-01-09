class LandlockError(Exception):
    """Base exception for all Landlock-related errors."""


class LandlockNotAvailableError(LandlockError):
    """
    Landlock is not available on this system.

    Raised when:
    - Running on a non-Linux platform (macOS, Windows, etc.)
    - Running on Linux < 5.13 (kernel returns ENOSYS)
    """


class LandlockDisabledError(LandlockError):
    """
    Landlock is disabled at boot time.

    Raised when the kernel was built with Landlock support but it was
    disabled via boot parameter (kernel returns EOPNOTSUPP).
    """


class RulesetError(LandlockError):
    """
    Error creating or configuring a Landlock ruleset.

    Raised when:
    - Ruleset creation fails
    - Adding rules to a ruleset fails
    - Applying a ruleset fails
    - Attempting to apply() twice on the same Sandbox
    - Attempting to add rules after apply() was called
    - Maximum ruleset layer limit (16) exceeded (kernel returns E2BIG)
    """


class PathError(LandlockError):
    """
    Path does not exist or cannot be accessed.

    Raised immediately when adding a rule for a path that doesn't exist.
    """

    path: str

    def __init__(self, path: str, message: str | None = None) -> None:
        """
        Initialize PathError with the problematic path.

        Args:
            path: The path that caused the error.
            message: Optional custom message. If not provided, a default is used.

        """
        self.path = path
        if message is None:
            message = f"Path does not exist: {path}"
        super().__init__(message)


class CompatibilityError(LandlockError):
    """
    Requested feature is not supported by the kernel's Landlock ABI version.

    Raised in strict mode (default) when attempting to use a feature that
    requires a higher ABI version than the kernel supports.

    In best_effort mode, unsupported features are silently ignored instead.
    """

    feature: str
    required_abi: int
    current_abi: int

    def __init__(self, feature: str, required_abi: int, current_abi: int) -> None:
        """
        Initialize CompatibilityError with version details.

        Args:
            feature: Description of the unsupported feature.
            required_abi: The minimum ABI version required for the feature.
            current_abi: The ABI version supported by the current kernel.

        """
        self.feature = feature
        self.required_abi = required_abi
        self.current_abi = current_abi
        message = f"{feature} requires Landlock ABI V{required_abi}, but kernel only supports V{current_abi}"
        super().__init__(message)


class NetworkDisabledError(LandlockError):
    """
    TCP networking is not supported by the kernel.

    Raised when attempting to add network rules but the kernel was built
    without TCP support (CONFIG_INET=n), indicated by EAFNOSUPPORT.
    """
