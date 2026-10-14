"""The Happy standard library (Step 4).

Available modules (all importable as ``std.<name>`` from Happy source):

* ``std.core``        — builtins: print, len, str, int, float, abs, panic, …
* ``std.io``          — console + capability-gated file / network IO
* ``std.collections`` — list / map / set helpers
* ``std.json``        — secret-aware JSON encode / decode
* ``std.async``       — Task / Channel / spawn / gather / sleep
* ``std.crypto``      — hashing, HMAC, tokens, base64 / hex
* ``std.net``         — capability-gated sockets / HTTP client
* ``std.fs``          — capability-gated filesystem operations
* ``std.time``        — clocks, timestamps, sleeping, formatting
* ``std.process``     — capability-gated subprocess execution
* ``std.env``         — environment variables and process arguments
* ``std.random``      — random numbers, choices, shuffling
* ``std.math``        — mathematical functions and constants
* ``std.regex``       — regular-expression helpers
* ``std.encoding``    — base64 / hex / url / utf8 / json codecs
* ``std.logging``     — structured, secret-redacting logging

The runtime context installs these functions into each generated module's
globals according to the program's ``import`` statements.
"""

__all__ = [
    "core",
    "io",
    "collections",
    "json",
    "async",
    "crypto",
    "net",
    "fs",
    "time",
    "process",
    "env",
    "random",
    "math",
    "regex",
    "encoding",
    "logging",
]
