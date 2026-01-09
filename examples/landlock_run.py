#!/usr/bin/env python3
# ruff: noqa: T201, S606
# pyright: reportUnusedCallResult=false
"""
Landlock sandbox runner - apply restrictions and execute a command.

Usage:
    python examples/landlock_run.py [OPTIONS] -- COMMAND [ARGS...]

Example:
    python examples/landlock_run.py
        --allow-read /tmp --allow-execute /usr
        --allow-all-network --allow-all-scope
        -- ls /tmp

"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from typing import NoReturn, cast

from py_landlock import (
    CompatibilityError,
    Landlock,
    LandlockError,
    LandlockNotAvailableError,
    PathError,
    Scope,
)


@dataclass
class Args:
    """Typed container for parsed CLI arguments."""

    allow_read: list[str] = field(default_factory=list)
    allow_write: list[str] = field(default_factory=list)
    allow_execute: list[str] = field(default_factory=list)
    allow_read_write: list[str] = field(default_factory=list)

    allow_connect: list[int] = field(default_factory=list)
    allow_bind: list[int] = field(default_factory=list)
    allow_all_network: bool = False

    allow_abstract_unix: bool = False
    allow_signals: bool = False
    allow_all_scope: bool = False

    best_effort: bool = False
    verbose: bool = False

    command: list[str] = field(default_factory=list)


def parse_args() -> Args:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Apply Landlock sandbox restrictions and execute a command.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run ls with read-only access to /tmp
  %(prog)s --allow-read /tmp --allow-execute /usr --allow-all-network --allow-all-scope -- ls /tmp

  # Run a Python script with write access to /tmp
  %(prog)s --allow-read /usr --allow-read-write /tmp --allow-execute /usr \\
    --allow-all-network --allow-all-scope -- python script.py

  # Run curl with network access to port 443 only
  %(prog)s --allow-read /etc /usr /lib --allow-execute /usr \\
    --allow-connect 443 --allow-all-scope -- curl https://example.com
        """,
    )

    fs_group = parser.add_argument_group("filesystem options")
    fs_group.add_argument(
        "--allow-read",
        metavar="PATH",
        nargs="+",
        action="extend",
        default=[],
        help="Allow read access to PATH(s)",
    )
    fs_group.add_argument(
        "--allow-write",
        metavar="PATH",
        nargs="+",
        action="extend",
        default=[],
        help="Allow write access to PATH(s)",
    )
    fs_group.add_argument(
        "--allow-execute",
        metavar="PATH",
        nargs="+",
        action="extend",
        default=[],
        help="Allow execute access to PATH(s)",
    )
    fs_group.add_argument(
        "--allow-read-write",
        metavar="PATH",
        nargs="+",
        action="extend",
        default=[],
        help="Allow read and write access to PATH(s)",
    )

    net_group = parser.add_argument_group("network options")
    net_group.add_argument(
        "--allow-connect",
        metavar="PORT",
        type=int,
        nargs="+",
        action="extend",
        default=[],
        help="Allow TCP connect to PORT(s)",
    )
    net_group.add_argument(
        "--allow-bind",
        metavar="PORT",
        type=int,
        nargs="+",
        action="extend",
        default=[],
        help="Allow TCP bind to PORT(s)",
    )
    net_group.add_argument(
        "--allow-all-network",
        action="store_true",
        help="Disable network sandboxing (allow all TCP connections)",
    )

    scope_group = parser.add_argument_group("scope options")
    scope_group.add_argument(
        "--allow-abstract-unix",
        action="store_true",
        help="Allow abstract UNIX socket connections",
    )
    scope_group.add_argument(
        "--allow-signals",
        action="store_true",
        help="Allow signal delivery outside Landlock domain",
    )
    scope_group.add_argument(
        "--allow-all-scope",
        action="store_true",
        help="Disable scope restrictions (allow all IPC and signals)",
    )

    parser.add_argument(
        "--best-effort",
        action="store_true",
        help="Don't fail on unsupported features (non-strict mode)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print applied restrictions before executing command",
    )

    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Command to execute (after --)",
    )

    namespace = parser.parse_args()
    return Args(
        allow_read=cast("list[str]", namespace.allow_read),
        allow_write=cast("list[str]", namespace.allow_write),
        allow_execute=cast("list[str]", namespace.allow_execute),
        allow_read_write=cast("list[str]", namespace.allow_read_write),
        allow_connect=cast("list[int]", namespace.allow_connect),
        allow_bind=cast("list[int]", namespace.allow_bind),
        allow_all_network=cast("bool", namespace.allow_all_network),
        allow_abstract_unix=cast("bool", namespace.allow_abstract_unix),
        allow_signals=cast("bool", namespace.allow_signals),
        allow_all_scope=cast("bool", namespace.allow_all_scope),
        best_effort=cast("bool", namespace.best_effort),
        verbose=cast("bool", namespace.verbose),
        command=cast("list[str]", namespace.command),
    )


def build_landlock(args: Args) -> Landlock:
    """Build a Landlock instance from parsed arguments."""
    ll = Landlock(strict=not args.best_effort)

    if args.allow_read:
        ll.allow_read(*args.allow_read)
    if args.allow_write:
        ll.allow_write(*args.allow_write)
    if args.allow_execute:
        ll.allow_execute(*args.allow_execute)
    if args.allow_read_write:
        ll.allow_read_write(*args.allow_read_write)

    if args.allow_all_network:
        ll.allow_all_network()
    else:
        for port in args.allow_connect:
            ll.allow_network(port, bind=False, connect=True)
        for port in args.allow_bind:
            ll.allow_network(port, bind=True, connect=False)

    if args.allow_all_scope:
        ll.allow_all_scope()
    else:
        if args.allow_abstract_unix:
            ll.allow_scope(Scope.ABSTRACT_UNIX_SOCKET)
        if args.allow_signals:
            ll.allow_scope(Scope.SIGNAL)

    return ll


def print_verbose_info(args: Args) -> None:
    """Print verbose information about the sandbox configuration."""
    lines: list[str] = ["Landlock sandbox configuration:"]

    if args.allow_read:
        lines.append(f"  Read access: {', '.join(args.allow_read)}")
    if args.allow_write:
        lines.append(f"  Write access: {', '.join(args.allow_write)}")
    if args.allow_execute:
        lines.append(f"  Execute access: {', '.join(args.allow_execute)}")
    if args.allow_read_write:
        lines.append(f"  Read/Write access: {', '.join(args.allow_read_write)}")

    if args.allow_all_network:
        lines.append("  Network: all allowed")
    elif args.allow_connect or args.allow_bind:
        if args.allow_connect:
            lines.append(f"  TCP connect: {', '.join(map(str, args.allow_connect))}")
        if args.allow_bind:
            lines.append(f"  TCP bind: {', '.join(map(str, args.allow_bind))}")
    else:
        lines.append("  Network: blocked")

    if args.allow_all_scope:
        lines.append("  Scope: all allowed")
    else:
        scope_flags = [("abstract-unix", args.allow_abstract_unix), ("signals", args.allow_signals)]
        scope_allowed = [name for name, flag in scope_flags if flag]
        lines.append(f"  Scope allowed: {', '.join(scope_allowed)}" if scope_allowed else "  Scope: restricted")

    lines.append(f"  Command: {' '.join(args.command)}")

    for line in lines:
        print(line, file=sys.stderr)
    print(file=sys.stderr)


def main() -> NoReturn:
    """Run the CLI."""
    args = parse_args()

    command: list[str] = args.command
    if command and command[0] == "--":
        command = command[1:]

    if not command:
        print("error: no command specified", file=sys.stderr)
        print("usage: landlock_run.py [OPTIONS] -- COMMAND [ARGS...]", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        args.command = command
        print_verbose_info(args)

    try:
        ll = build_landlock(args)
        ll.apply()
    except LandlockNotAvailableError as e:
        print(f"error: {e}", file=sys.stderr)
        print("hint: Landlock requires Linux kernel 5.13+ with CONFIG_SECURITY_LANDLOCK=y", file=sys.stderr)
        sys.exit(1)
    except CompatibilityError as e:
        print(f"error: {e}", file=sys.stderr)
        print("hint: use --best-effort to ignore unsupported features", file=sys.stderr)
        sys.exit(1)
    except PathError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    except LandlockError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        os.execvp(command[0], command)
    except FileNotFoundError:
        print(f"error: command not found: {command[0]}", file=sys.stderr)
        sys.exit(127)
    except PermissionError:
        print(f"error: permission denied: {command[0]}", file=sys.stderr)
        sys.exit(126)


if __name__ == "__main__":
    main()
