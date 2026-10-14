"""Allow ``python -m happy`` to behave exactly like the ``happy`` CLI.

This makes the toolchain runnable both as an installed console script
(``happy ...``) and directly from a source checkout (``python -m happy ...``)
without any wrapper.
"""

from __future__ import annotations

from .cli.main import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
