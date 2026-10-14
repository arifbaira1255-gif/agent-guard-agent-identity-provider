"""The Happy Python backend (Step 4).

Lowers typed Happy IR to executable Python 3 and carries the source map that
ties generated lines back to ``.hpy`` source.

    from happy.backend import generate, compile_source, PythonGenerator

    program = compile_source(source, filename="demo.hpy")
    print(program.source)          # executable Python 3
    print(program.sourcemap.to_json())
"""

from .sourcemap import SourceMap, SourceMapBuilder, SourceMapEntry
from .python_gen import (
    GENERATED_FILENAME,
    GeneratedProgram,
    PythonBackendError,
    PythonGenerator,
    compile_project,
    compile_source,
    generate,
)

__all__ = [
    "SourceMap",
    "SourceMapBuilder",
    "SourceMapEntry",
    "GeneratedProgram",
    "PythonBackendError",
    "PythonGenerator",
    "generate",
    "compile_source",
    "compile_project",
    "GENERATED_FILENAME",
]
