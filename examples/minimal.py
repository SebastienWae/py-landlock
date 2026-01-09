#!/usr/bin/env python3
# ruff: noqa: T201
# pyright: reportUnusedCallResult=false
"""Minimal py-landlock sandbox example."""

import tempfile
from pathlib import Path

from py_landlock import Landlock

with tempfile.NamedTemporaryFile(delete=False, dir="/tmp") as tmp_file:
    tmp_path = Path(tmp_file.name)
    tmp_path.write_text("text data")

    (Landlock(strict=False).allow_read(tmp_path.parent).allow_execute("/usr").apply())

    print("Sandbox active!")

    print(f"Read OK: {tmp_path.read_text()}")

    try:
        tmp_path.write_text("blocked!")
    except PermissionError:
        print("Write blocked by sandbox!")
