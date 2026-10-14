"""The Happy (``.hpy``) language toolchain.

``happy.compiler`` implements the front end (lexer through typed IR), the
contract / permission / effect engines, and (Step 4) the Python code generator.
``happy.runtime`` is the execution layer, and ``happy.std`` the standard
library.

Quick start::

    from happy.compiler import analyze, parse, lower
    from happy.backend import generate
    from happy.runtime import RuntimeContext

    analysis = analyze(source, filename="demo.hpy")
    module = lower(analysis)
    program = generate(module, source=source, filename="demo.hpy")
    ctx = RuntimeContext(filename="demo.hpy", source=source, module=module,
                         sourcemap=program.sourcemap)
    result = program.run(ctx)
    print(result.output)
"""

__version__ = "1.0.0"
