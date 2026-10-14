"""The Happy command-line interface (Step 6).

    python -m happy.cli <command> [args]

See :mod:`happy.cli.main` for the full command list.
"""

from .main import build_parser, main

__all__ = ["main", "build_parser"]
