"""The Happy Python backend — lowers Happy IR to executable Python 3.

This is the Step-4 code generator.  It consumes the typed
:class:`~happy.compiler.ir.IRModule` produced by :func:`happy.compiler.ir.lower`
and emits ordinary, readable Python 3 source that runs inside the Happy Runtime
(:mod:`happy.runtime`).

Design
------
* **Direct, faithful lowering.**  Every IR node maps to a small, obvious piece
  of Python: structs become classes deriving from
  :class:`happy.runtime.values.HappyStruct`, enums become
  :class:`~happy.runtime.values.VariantCtor` bindings, functions become Python
  functions, and contracts become calls against the runtime's
  :class:`~happy.runtime.contracts.ContractChecker`.
* **Source maps.**  Every emitted statement is anchored to the ``.hpy`` line and
  column it came from (see :mod:`happy.backend.sourcemap`).  Because the module
  is compiled with the file name ``<happy-generated>``, a Python traceback frame
  can be resolved back to a Happy location, so a runtime error points at the
  Happy line the programmer wrote.
* **Runtime hooks.**  Contracts, capabilities and secret wrapping are not baked
  into ad-hoc Python — they are delegated to the runtime services installed by
  :class:`happy.runtime.context.RuntimeContext` into the module globals
  (``__happy_contracts__``, ``__happy_caps__``).

Entry points::

    from happy.compiler import parse, analyze, lower
    from happy.backend import PythonGenerator
    from happy.runtime import RuntimeContext

    module = lower(analyze(parse(source), filename="demo.hpy"))
    program = PythonGenerator(module, source=source, filename="demo.hpy").generate()

    ctx = RuntimeContext(filename="demo.hpy", source=source, module=module,
                         sourcemap=program.sourcemap)
    result = program.run(ctx)
    print(result.output)
"""

from __future__ import annotations

import json
import keyword
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..compiler import ir
from ..compiler.permissions import ENFORCEMENT_MAP
from .sourcemap import SourceMap, SourceMapBuilder

__all__ = [
    "PythonBackendError",
    "GeneratedProgram",
    "PythonGenerator",
    "generate",
    "compile_source",
]

#: The synthetic filename the generated module is compiled under.  The runtime
#: context recognises it and consults the source map.
GENERATED_FILENAME = "<happy-generated>"


class PythonBackendError(Exception):
    """Raised when the IR cannot be lowered to Python (a genuine bug)."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


@dataclass
class GeneratedProgram:
    """The result of code generation: real Python source plus its source map."""

    source: str
    sourcemap: SourceMap
    filename: Optional[str] = None
    module_name: Optional[str] = None
    module: Any = None
    #: Names bound at module scope in the generated program (in order).
    top_level_names: List[str] = field(default_factory=list)

    # -- execution ------------------------------------------------------
    def compile(self):
        """Compile the generated source to a Python code object."""
        return compile(self.source, GENERATED_FILENAME, "exec")

    def execute(self, ctx: Any, entry: str = "main") -> Any:
        """Compile + exec the program under ``ctx`` and invoke ``entry``.

        Returns the :class:`~happy.runtime.context.RunResult` produced by
        :meth:`happy.runtime.context.RuntimeContext.run`.
        """
        globals_dict: Dict[str, Any] = {"__name__": "__happy_main__"}
        ctx.prepare(globals_dict, getattr(self.module, "imports", []))
        code = self.compile()
        exec(code, globals_dict)  # noqa: S102 - trusted, self-generated code
        target = globals_dict.get(entry) or globals_dict.get("__happy_main__")
        if target is None:
            from ..runtime.errors import HappyRuntimeError

            raise HappyRuntimeError(
                message="generated program has no 'main' entry point",
                code="R8001",
            )
        return ctx.run(target)

    def run(self, ctx: Any, entry: str = "main") -> Any:
        """Alias of :meth:`execute`."""
        return self.execute(ctx, entry=entry)


# ---------------------------------------------------------------------------
# Location helpers
# ---------------------------------------------------------------------------
def _loc_pair(loc: Any) -> Tuple[Optional[int], Optional[int]]:
    if loc is None:
        return None, None
    if hasattr(loc, "line"):
        return int(getattr(loc, "line", 0) or 0), int(getattr(loc, "column", 0) or 0)
    if isinstance(loc, (tuple, list)) and len(loc) >= 2:
        return int(loc[-2]), int(loc[-1])
    return None, None


def _loc_tuple(loc: Any, filename: Optional[str]) -> str:
    """Render an IR location as a Python literal ``(filename, line, column)``."""
    line, col = _loc_pair(loc)
    if line is None:
        return "None"
    return f"({filename!r}, {line}, {col})"


#: Identifiers that cannot be used verbatim as Python local names.
_PY_RESERVED = frozenset(keyword.kwlist) | {"None", "True", "False"}


def _is_float_type(ty: Any) -> bool:
    """True when ``ty`` is Happy's ``Float`` primitive."""
    if ty is None:
        return False
    display = getattr(ty, "display", None)
    try:
        return callable(display) and display() == "Float"
    except Exception:  # pragma: no cover - defensive
        return False


def _runtime_global_names() -> frozenset:
    """Names the runtime installs into every generated module's globals."""
    names = {
        "spawn", "gather", "await_all", "sleep", "Task", "Channel", "Some",
        "Ok", "Err", "None", "Unit", "secret", "reveal", "read_file",
        "write_file", "append_file", "file_exists", "http_get", "http_post",
    }
    try:
        from ..std import core as _core

        names.update(_core.BUILTINS.keys())
    except Exception:  # pragma: no cover - defensive
        pass
    return frozenset(names)


_RUNTIME_GLOBALS = _runtime_global_names()


def _is_unit(returns: Any) -> bool:
    if returns is None:
        return True
    display = getattr(returns, "display", None)
    if callable(display):
        return display() in ("Unit",)
    return False


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------
class _Writer:
    """Accumulates generated lines and records sourcemap anchors."""

    INDENT = "    "

    def __init__(self, filename: Optional[str] = None) -> None:
        self.filename = filename
        self.lines: List[str] = []
        self.map = SourceMap(filename=filename)
        self.level = 0

    def _pad(self) -> str:
        return self.INDENT * self.level

    def emit(self, text: str, loc: Any = None, node_id: str = "", symbol: str = "") -> int:
        gen_line = len(self.lines) + 1
        self.lines.append(self._pad() + text)
        line, col = _loc_pair(loc)
        if line:
            self.map.add(gen_line, line, col or 0, node_id, symbol)
        return gen_line

    def emit_all(self, text: str, loc: Any = None) -> None:
        """Emit a (possibly multi-line) block, indenting continuation lines."""
        parts = text.split("\n")
        for i, part in enumerate(parts):
            self.emit(part, loc=loc if i == 0 else None)

    def blank(self) -> None:
        self.lines.append("")

    def push(self) -> None:
        self.level += 1

    def pop(self) -> None:
        self.level = max(0, self.level - 1)

    def source(self) -> str:
        return "\n".join(self.lines) + "\n"


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------
class PythonGenerator:
    """Lowers an :class:`~happy.compiler.ir.IRModule` to Python source."""

    def __init__(
        self,
        module: ir.IRModule,
        source: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> None:
        self.module = module
        self.source = source
        self.filename = filename
        self.w = _Writer(filename=filename)
        self._names: Dict[str, Any] = {}
        self._structs: Dict[str, ir.IRTypeDecl] = {t.name: t for t in module.types}
        self._enums: Dict[str, ir.IREnumDecl] = {e.name: e for e in module.enums}
        self._variant_names: Dict[str, str] = {}  # variant -> enum
        self._nullary_variants: set = set()
        for e in module.enums:
            for v in e.variants:
                self._variant_names.setdefault(v.name, e.name)
                if not v.payload:
                    self._nullary_variants.add(v.name)
        self._trait_classes: set = set()
        for tr in module.traits:
            self._trait_classes.add(tr.name)
        self._agent: Optional[str] = None
        self._top_level: List[str] = []
        # Lexical scopes of *Happy* names -> the Python names they compile to.
        # Python has function scope only, so block-level ``let`` / ``for`` /
        # ``match`` bindings that shadow an outer name are renamed instead of
        # overwriting it.
        self._scopes: List[Dict[str, str]] = []
        self._fresh_counter = 0
        self._global_names: set = set(_RUNTIME_GLOBALS)
        for coll in (
            module.types, module.enums, module.traits, module.constants,
            module.functions, module.rules, module.agents,
        ):
            for item in coll:
                self._global_names.add(item.name)
        for e in module.enums:
            for v in e.variants:
                self._global_names.add(v.name)

    # -- scopes ---------------------------------------------------------
    def _push_scope(self) -> None:
        self._scopes.append({})

    def _pop_scope(self) -> None:
        if self._scopes:
            self._scopes.pop()

    def _lookup(self, name: str) -> Optional[str]:
        for scope in reversed(self._scopes):
            if name in scope:
                return scope[name]
        return None

    def _declare(self, name: str) -> str:
        """Bind ``name`` in the innermost scope and return its Python name."""
        if not self._scopes:
            self._push_scope()
        cur = self._scopes[-1]
        if name in cur:
            return cur[name]
        shadows = self._lookup(name) is not None or name in self._global_names
        py = name
        if shadows or name in _PY_RESERVED:
            self._fresh_counter += 1
            py = f"{name}__{self._fresh_counter}"
        cur[name] = py
        return py

    def _declare_param(self, name: str) -> str:
        """Parameters shadow naturally in Python; only reserved words change."""
        if not self._scopes:
            self._push_scope()
        py = f"{name}__p" if name in _PY_RESERVED else name
        self._scopes[-1][name] = py
        return py

    # -- top level ------------------------------------------------------
    def generate(self) -> GeneratedProgram:
        self._emit_preamble()
        self._emit_enums()
        self._emit_traits()
        self._emit_structs()
        self._emit_impls()
        self._emit_constants()
        self._emit_functions()
        self._emit_rules()
        self._emit_agents()
        self._emit_ai_blocks()
        self._emit_main()
        self.w.map.finalize(len(self.w.lines))
        return GeneratedProgram(
            source=self.w.source(),
            sourcemap=self.w.map,
            filename=self.filename,
            module_name=self.module.name,
            module=self.module,
            top_level_names=list(self._top_level),
        )

    # -- preamble -------------------------------------------------------
    def _emit_preamble(self) -> None:
        self.w.emit(
            "# Generated by the Happy compiler (Step 4) — Python backend."
        )
        self.w.emit(f"# Source: {self.filename or '<memory>'}")
        self.w.emit(
            "from happy.runtime.values import ("
            "UNIT, HappyStruct, HappyEnumValue, VariantCtor, Option, Result, "
            "Ok, Err, Some, NONE, to_display, Trait, TraitNotImplemented, "
            "Display, Debug, Eq, Ord, Hash, Iterator, match_or, "
            "match_variant_ctor, match_payload, match_field)"
        )
        self.w.emit("from happy.runtime.values import to_float as __happy_float__")
        self.w.emit("from happy.runtime.secrets import Secret, reveal, secret")
        self.w.emit(
            "from happy.runtime.errors import ("
            "HappyRuntimeError, HappyTypeError, HappyNameError)"
        )
        self.w.emit(
            "from happy.runtime.async_runtime import ("
            "Task, Channel, spawn, gather, await_all, sleep)"
        )
        self.w.emit(
            "from happy.runtime.context import "
            "_bind_secret_guard as __happy_secret_guard__"
        )
        self.w.blank()
        self.w.emit("HAPPY_MISSING = object()")
        self.w.blank()
        self.w.emit("def __happy_ai__(prompt):")
        self.w.push()
        self.w.emit(
            'return __happy_ctx__.ai_complete(prompt)'
            " if '__happy_ctx__' in globals() else '<ai:' + to_display(prompt) + '>'"
        )
        self.w.pop()
        self.w.blank()

    # -- enums ----------------------------------------------------------
    def _emit_enums(self) -> None:
        for e in self.module.enums:
            self.w.emit(f"# enum {e.name}", loc=e.loc, symbol=e.name)
            for v in e.variants:
                arity = len(v.payload)
                self.w.emit(
                    f"{v.name} = VariantCtor({e.name!r}, {v.name!r}, {arity})",
                    loc=v.loc,
                    node_id=v.id,
                    symbol=v.name,
                )
                self._top_level.append(v.name)
            self.w.blank()

    # -- structs --------------------------------------------------------
    def _emit_structs(self) -> None:
        for t in self.module.types:
            self._emit_struct(t)

    def _emit_struct(self, t: ir.IRTypeDecl) -> None:
        order = tuple(f.name for f in t.fields)
        secret_fields = tuple(f.name for f in t.fields if f.secret)
        runtime_traits = {
            "Display",
            "Debug",
            "Eq",
            "Ord",
            "Hash",
            "Iterator",
        }
        bases = ["HappyStruct"]
        for trait in getattr(t, "implements", []) or []:
            if trait in self._trait_classes or trait in runtime_traits:
                bases.append(trait)
        base_list = ", ".join(bases)
        self.w.emit(f"class {t.name}({base_list}):", loc=t.loc, symbol=t.name)
        self.w.push()
        self.w.emit(f"_happy_type_name = {t.name!r}")
        self.w.emit(f"_happy_field_order = {order!r}")
        self.w.emit(f"_happy_secret_fields = {secret_fields!r}")
        float_fields = tuple(f.name for f in t.fields if _is_float_type(f.type))
        self.w.emit(f"_happy_float_fields = {float_fields!r}")
        # declared defaults become class attributes
        for f in t.fields:
            if f.default is not None:
                self.w.emit(
                    f"{f.name} = {self._expr(f.default)}",
                    loc=f.loc,
                    node_id=f.id,
                )
        params = []
        for f in t.fields:
            if f.default is not None:
                default = self._expr(f.default)
            else:
                default = "HAPPY_MISSING"
            params.append(f"{f.name}={default}")
        sig = ", ".join(["self"] + params)
        self.w.emit(f"def __init__({sig}):", loc=t.loc)
        self.w.push()
        for f in t.fields:
            if f.secret:
                self.w.emit(
                    f"self.{f.name} = {f.name} if isinstance({f.name}, Secret) "
                    f"else Secret({f.name}, label={f.name!r}, "
                    f"guard=__happy_secret_guard__())",
                    loc=f.loc,
                    node_id=f.id,
                )
            else:
                self.w.emit(
                    f"if {f.name} is HAPPY_MISSING:",
                    loc=f.loc,
                    node_id=f.id,
                )
                self.w.push()
                self.w.emit(
                    f"raise HappyTypeError(message=\"missing required field "
                    f"'{f.name}' for type '{t.name}'\")"
                )
                self.w.pop()
                self.w.emit(f"self.{f.name} = {f.name}", loc=f.loc)
        if t.invariants:
            self.w.emit("self.__happy_invariant__()", loc=t.loc)
        self.w.emit("self.__dict__['_happy_ready'] = True")
        self.w.pop()
        # invariant method
        if t.invariants:
            self.w.emit("def __happy_invariant__(self):", loc=t.loc)
            self.w.push()
            field_map = {f.name: f"self.{f.name}" for f in t.fields}
            field_map["self"] = "self"
            for inv in t.invariants:
                predicate = self._expr(inv.condition, name_map=field_map)
                text = self._expr_display(inv.condition)
                self.w.emit(
                    f"__happy_contracts__.check_invariant("
                    f"{t.name!r}, ({predicate}), {text!r}, "
                    f"{inv.message!r}, {_loc_tuple(inv.loc, self.filename)})",
                    loc=inv.loc,
                    node_id=inv.id,
                )
            self.w.pop()
        self.w.pop()
        self.w.blank()
        self._top_level.append(t.name)

    # -- functions ------------------------------------------------------
    def _emit_functions(self) -> None:
        for f in self.module.functions:
            self._emit_function(f)

    def _emit_function(self, f: ir.IRFunction, name: Optional[str] = None) -> None:
        fname = name or f.name
        self._push_scope()
        py_params = [self._declare_param(p.name) for p in f.params]
        params = ", ".join(
            f"{py}={self._expr(p.default)}" if p.default is not None else py
            for p, py in zip(f.params, py_params)
        )
        keyword = "async def" if f.is_async else "def"
        self.w.emit(f"{keyword} {fname}({params}):", loc=f.loc, symbol=fname)
        self.w.push()
        for p, pyname in zip(f.params, py_params):
            if _is_float_type(p.type):
                self.w.emit(f"{pyname} = __happy_float__({pyname})")
        # Agent methods run inside an agent scope so nested std calls are
        # capability-checked against the owning agent.
        in_agent = self._agent is not None
        if in_agent:
            self.w.emit(f"__happy_caps__.enter_agent({self._agent!r})")
            self.w.emit("try:")
            self.w.push()
        self._emit_requires(f, fname)
        if f.body is None or not f.body.statements:
            if self._needs_ensures(f):
                self.w.emit("__happy_result__ = None")
                self._emit_ensures(f, fname)
            self.w.emit("return None")
        else:
            self._emit_block(f.body, return_contract=(f, fname))
            # implicit return
            if self._needs_ensures(f):
                self.w.emit("__happy_result__ = None")
                self._emit_ensures(f, fname)
            self.w.emit("return None")
        if in_agent:
            self.w.pop()
            self.w.emit("finally:")
            self.w.push()
            self.w.emit("__happy_caps__.exit_agent()")
            self.w.pop()
        self.w.pop()
        self._pop_scope()
        self.w.blank()
        self._top_level.append(fname)

    def _emit_requires(self, f: ir.IRFunction, fname: str) -> None:
        for c in f.contracts:
            if c.kind != "requires" or c.condition is None:
                continue
            predicate = self._expr(c.condition)
            text = self._expr_display(c.condition)
            self.w.emit(
                f"__happy_contracts__.check_requires("
                f"{fname!r}, ({predicate}), {text!r}, "
                f"{c.message!r}, {_loc_tuple(c.loc, self.filename)})",
                loc=c.loc,
                node_id=c.id,
            )

    def _needs_ensures(self, f: ir.IRFunction) -> bool:
        return any(
            c.kind == "ensures" and c.condition is not None for c in f.contracts
        )

    def _emit_ensures(self, f: ir.IRFunction, fname: str) -> None:
        for c in f.contracts:
            if c.kind != "ensures" or c.condition is None:
                continue
            predicate = self._expr(c.condition, name_map={"result": "__happy_result__"})
            text = self._expr_display(c.condition)
            self.w.emit(
                f"__happy_contracts__.check_ensures("
                f"{fname!r}, ({predicate}), {text!r}, "
                f"{c.message!r}, {_loc_tuple(c.loc, self.filename)})",
                loc=c.loc,
                node_id=c.id,
            )

    # -- rules ----------------------------------------------------------
    def _emit_rules(self) -> None:
        for r in self.module.rules:
            if r.condition is None:
                continue
            params = ", ".join(p.name for p in r.params)
            self.w.emit(
                f"def {r.name}({params}):", loc=r.loc, symbol=r.name
            )
            self.w.push()
            predicate = self._expr(r.condition)
            text = self._expr_display(r.condition)
            args = "{" + ", ".join(f"{p.name!r}: {p.name}" for p in r.params) + "}"
            self.w.emit(
                f"__happy_contracts__.check_rule("
                f"{r.name!r}, ({predicate}), {text!r}, {None!r}, "
                f"{_loc_tuple(r.loc, self.filename)}, {args})",
                loc=r.loc,
                node_id=r.id,
            )
            self.w.emit("return True")
            self.w.pop()
            self.w.blank()
            self._top_level.append(r.name)

    # -- agents ---------------------------------------------------------
    def _emit_agents(self) -> None:
        for a in self.module.agents:
            self.w.emit(f"# agent {a.name}", loc=a.loc, symbol=a.name)
            method_names: List[str] = []
            for fn in a.functions:
                impl = f"_{a.name}_{fn.name}"
                self._agent = a.name
                self._emit_function(fn, name=impl)
                self._agent = None
                method_names.append((fn.name, impl))
            self.w.emit(f"class {a.name}:", loc=a.loc)
            self.w.push()
            self.w.emit(f"__capabilities__ = {list(a.capabilities)!r}")
            self.w.emit(f"__permissions__ = {list(a.permissions)!r}")
            for public, impl in method_names:
                self.w.emit(f"{public} = staticmethod({impl})")
            if not method_names:
                self.w.emit("pass")
            self.w.pop()
            self.w.blank()
            self._top_level.append(a.name)

    # -- ai blocks ------------------------------------------------------
    def _emit_ai_blocks(self) -> None:
        for ai in self.module.ai_blocks:
            fname = f"__happy_ai_block_{ai.name}"
            self.w.emit(f"def {fname}():", loc=ai.loc, symbol=ai.name)
            self.w.push()
            prompt = self._expr(ai.prompt) if ai.prompt is not None else "''"
            self.w.emit(f"return __happy_ai__({prompt})", loc=ai.loc)
            self.w.pop()
            self.w.blank()
            self._top_level.append(fname)

    # -- main -----------------------------------------------------------
    def _emit_main(self) -> None:
        app = self.module.apps[0] if self.module.apps else None
        # An ``app`` always yields an entry point, even when its body is empty
        # (``app A {}``) or the optimizer removed every statement (for example
        # a body that only contains ``if false { ... }``).  Only a module with
        # no ``app`` at all is a library without an entry point.
        has_app_body = app is not None
        # A user-defined `main` function takes precedence.  Previously the
        # backend always emitted an ``async def main()`` wrapper, which
        # overrode any user `main` (a real bug: a program defining
        # ``function main()`` never ran its own body).
        has_user_main = "main" in self._top_level
        if has_app_body and not has_user_main:
            self.w.emit("async def main():", loc=app.loc)
            self.w.push()
            if app.body is not None:
                self._emit_block(app.body)
            self.w.emit("return None")
            self.w.pop()
            self.w.blank()
            self._top_level.append("main")
            return
        if has_app_body and has_user_main:
            # Keep the app body callable under a private name without
            # clobbering the user's entry point.
            self.w.emit("async def __happy_app_main__():", loc=app.loc)
            self.w.push()
            if app.body is not None:
                self._emit_block(app.body)
            self.w.emit("return None")
            self.w.pop()
            self.w.blank()
            self._top_level.append("__happy_app_main__")
        # No app body: a user-defined `main` is already emitted and is the
        # entry point; if neither exists the runtime reports R8001.

    # -- statements -----------------------------------------------------
    def _emit_block(
        self, block: ir.IRBlock, return_contract: Optional[Tuple[ir.IRFunction, str]] = None
    ) -> None:
        self._push_scope()
        try:
            for stmt in block.statements:
                if isinstance(stmt, ir.IRFunction):
                    py = self._declare(stmt.name)
                    self._emit_function(stmt, name=py)
                    continue
                self._emit_stmt(stmt, return_contract)
        finally:
            self._pop_scope()

    def _emit_stmt(
        self, stmt: ir.IRStmt, return_contract: Optional[Tuple[ir.IRFunction, str]]
    ) -> None:
        if isinstance(stmt, ir.IRLet):
            value = self._expr(stmt.value) if stmt.value is not None else "None"
            if stmt.value is not None and _is_float_type(stmt.type):
                value = f"__happy_float__({value})"
            # The initialiser is evaluated against the *outer* binding.
            py = self._declare(stmt.name)
            self.w.emit(f"{py} = {value}", loc=stmt.loc, node_id=stmt.id)
            return
        if isinstance(stmt, ir.IRAssign):
            target = self._expr(stmt.target)
            value = self._expr(stmt.value)
            op = stmt.op if stmt.op in ("=", "+=", "-=", "*=", "/=", "%=") else "="
            if op == "=" and _is_float_type(getattr(stmt.target, "type", None)):
                value = f"__happy_float__({value})"
            self.w.emit(f"{target} {op} {value}", loc=stmt.loc, node_id=stmt.id)
            return
        if isinstance(stmt, ir.IRExprStmt):
            self.w.emit(self._expr(stmt.expr), loc=stmt.loc, node_id=stmt.id)
            return
        if isinstance(stmt, ir.IRIf):
            self._emit_if_chain(stmt, return_contract)
            return
        if isinstance(stmt, ir.IRWhile):
            self.w.emit(f"while {self._expr(stmt.condition)}:", loc=stmt.loc, node_id=stmt.id)
            self.w.push()
            self._emit_block(stmt.body, return_contract)
            if not (stmt.body and stmt.body.statements):
                self.w.emit("pass")
            self.w.pop()
            return
        if isinstance(stmt, ir.IRFor):
            iterable = self._expr(stmt.iterable)
            self._push_scope()
            try:
                var = self._declare(stmt.variable)
                self.w.emit(
                    f"for {var} in {iterable}:", loc=stmt.loc, node_id=stmt.id
                )
                self.w.push()
                self._emit_block(stmt.body, return_contract)
                if not (stmt.body and stmt.body.statements):
                    self.w.emit("pass")
                self.w.pop()
            finally:
                self._pop_scope()
            return
        if isinstance(stmt, ir.IRReturn):
            self._emit_return(stmt, return_contract)
            return
        if isinstance(stmt, ir.IRBreak):
            self.w.emit("break", loc=stmt.loc, node_id=stmt.id)
            return
        if isinstance(stmt, ir.IRContinue):
            self.w.emit("continue", loc=stmt.loc, node_id=stmt.id)
            return
        if isinstance(stmt, ir.IRMatch):
            self._emit_match(stmt, return_contract)
            return
        if isinstance(stmt, ir.IRAssert):
            self.w.emit(self._assert_call(stmt), loc=stmt.loc, node_id=stmt.id)
            return
        raise PythonBackendError(
            f"cannot emit statement of type {type(stmt).__name__}"
        )

    # -- traits & impls (Step 7) -------------------------------------
    def _emit_traits(self) -> None:
        for tr in self.module.traits:
            self.w.emit(f"class {tr.name}(Trait):", loc=tr.loc, symbol=tr.name)
            self.w.push()
            self.w.emit(f"__happy_trait_name__ = {tr.name!r}")
            if not tr.methods:
                self.w.emit("pass")
            for m in tr.methods:
                names = [p.name for p in m.params]
                if not names or names[0] != "self":
                    names = ["self"] + names
                params = ", ".join(names)
                self.w.emit(f"def {m.name}({params}):", loc=m.loc)
                self.w.push()
                if m.body is not None and m.body.statements:
                    self._emit_block(m.body)
                    self.w.emit("return None")
                else:
                    self.w.emit(
                        f"raise TraitNotImplemented({tr.name!r}, {m.name!r})"
                    )
                self.w.pop()
                self.w.blank()
            self.w.pop()
            self.w.blank()
            self._top_level.append(tr.name)

    # -- module constants (Step 7) -----------------------------------
    def _emit_constants(self) -> None:
        for c in self.module.constants:
            value = self._expr(c.value) if c.value is not None else "None"
            self.w.emit(f"{c.name} = {value}", loc=c.loc, node_id=c.id, symbol=c.name)
            self._top_level.append(c.name)
        if self.module.constants:
            self.w.blank()

    def _emit_impls(self) -> None:
        for impl in self.module.impls:
            for fn in impl.methods:
                impl_name = f"__impl_{impl.for_type}_{fn.name}"
                self._agent = None
                self._emit_function(fn, name=impl_name)
                self.w.emit(
                    f"setattr({impl.for_type}, {fn.name!r}, {impl_name})",
                    loc=impl.loc,
                )

    # -- pattern matching (Step 7) ------------------------------------
    def _emit_match(
        self, stmt: ir.IRMatch, return_contract: Optional[Tuple[ir.IRFunction, str]]
    ) -> None:
        subject = f"__happy_match_{stmt.id}"
        self.w.emit(
            f"{subject} = {self._expr(stmt.subject)}", loc=stmt.loc, node_id=stmt.id
        )
        emitted = 0
        has_unconditional = False
        for arm in stmt.arms:
            pat = arm.pattern
            if pat is not None and pat.kind in ("wildcard", "binding"):
                has_unconditional = True
            cond = self._pattern_condition(pat, subject)
            keyword = "if" if emitted == 0 else "elif"
            self.w.emit(f"{keyword} {cond}:", loc=arm.loc, node_id=arm.id)
            self.w.push()
            self._push_scope()
            self._emit_pattern_bindings(pat, subject)
            tail_returned = False
            if arm.body is not None and arm.body.statements:
                stmts = arm.body.statements
                if (
                    getattr(arm, "bare_expr", False)
                    and len(stmts) == 1
                    and isinstance(stmts[0], ir.IRExprStmt)
                    and self._match_arm_returns(return_contract)
                ):
                    # `pattern -> expr` — the arm's value is the function result.
                    synthetic = ir.IRReturn(loc=stmts[0].loc, value=stmts[0].expr)
                    self._emit_return(synthetic, return_contract)
                    tail_returned = True
                else:
                    self._emit_block(arm.body, return_contract)
            if not tail_returned:
                self.w.emit("pass")
            self._pop_scope()
            self.w.pop()
            emitted += 1
        if emitted > 0 and not has_unconditional:
            self.w.emit("else:")
            self.w.push()
            self.w.emit(
                "raise HappyRuntimeError(message=\"non-exhaustive match: no arm "
                "matched\", code=\"R4201\")"
            )
            self.w.pop()

    def _match_arm_returns(
        self, return_contract: Optional[Tuple[ir.IRFunction, str]]
    ) -> bool:
        """True when a single-expression match arm should become a ``return``.

        Arms whose value type is not ``Unit`` produce the enclosing function's
        result; ``Unit``-returning functions keep the expression as a statement.
        """
        if return_contract is None:
            return True
        fn, _ = return_contract
        ret = getattr(fn, "returns", None)
        if ret is None:
            return True
        return not _is_unit(ret)

    def _pattern_condition(self, pat: Optional[ir.IRPattern], subject: str) -> str:
        if pat is None:
            return "True"
        if pat.kind in ("wildcard", "binding"):
            return "True"
        if pat.kind == "literal":
            return f"match_or({self._expr(pat.value)}, {subject})"
        if pat.kind == "variant":
            return f"match_variant_ctor({subject}, {pat.name})"
        if pat.kind == "struct":
            return f"isinstance({subject}, {pat.name})"
        if pat.kind == "or":
            parts = [
                f"({self._pattern_condition(sub, subject)})"
                for sub in pat.patterns
            ]
            return " or ".join(parts) if parts else "True"
        return "True"

    def _emit_pattern_bindings(self, pat: Optional[ir.IRPattern], subject: str) -> None:
        if pat is None:
            return
        if pat.kind == "binding" and pat.name and pat.name != "_":
            self.w.emit(f"{self._declare(pat.name)} = {subject}")
        elif pat.kind == "variant":
            for i, b in enumerate(pat.bindings):
                if b and b != "_":
                    self.w.emit(f"{self._declare(b)} = match_payload({subject}, {i})")
        elif pat.kind == "struct":
            for b in pat.bindings:
                if b and b != "_":
                    self.w.emit(f"{self._declare(b)} = match_field({subject}, {b!r})")

    def _emit_if_chain(
        self, node: ir.IRIf, return_contract: Optional[Tuple[ir.IRFunction, str]]
    ) -> None:
        """Emit an ``if`` / ``elif`` / ``else`` chain at the current indent.

        IR represents ``else if`` as a nested :class:`IRIf` in ``else_branch``;
        this flattens the chain into idiomatic Python ``elif`` arms.
        """
        self.w.emit(f"if {self._expr(node.condition)}:", loc=node.loc, node_id=node.id)
        self.w.push()
        self._emit_block(node.then_branch, return_contract)
        if not (node.then_branch and node.then_branch.statements):
            self.w.emit("pass")
        self.w.pop()

        else_branch: Any = node.else_branch
        while isinstance(else_branch, ir.IRIf):
            self.w.emit(
                f"elif {self._expr(else_branch.condition)}:", loc=else_branch.loc
            )
            self.w.push()
            self._emit_block(else_branch.then_branch, return_contract)
            if not (else_branch.then_branch and else_branch.then_branch.statements):
                self.w.emit("pass")
            self.w.pop()
            else_branch = else_branch.else_branch

        if isinstance(else_branch, ir.IRBlock):
            self.w.emit("else:")
            self.w.push()
            self._emit_block(else_branch, return_contract)
            if not else_branch.statements:
                self.w.emit("pass")
            self.w.pop()

    def _emit_return(
        self, stmt: ir.IRReturn, return_contract: Optional[Tuple[ir.IRFunction, str]]
    ) -> None:
        ret_float = (
            return_contract is not None
            and stmt.value is not None
            and _is_float_type(getattr(return_contract[0], "returns", None))
        )
        if return_contract is not None and self._needs_ensures(return_contract[0]):
            f, fname = return_contract
            value = self._expr(stmt.value) if stmt.value is not None else "None"
            if ret_float:
                value = f"__happy_float__({value})"
            self.w.emit(f"__happy_result__ = {value}", loc=stmt.loc, node_id=stmt.id)
            self._emit_ensures(f, fname)
            self.w.emit("return __happy_result__", loc=stmt.loc)
        elif stmt.value is None:
            self.w.emit("return None", loc=stmt.loc, node_id=stmt.id)
        else:
            value = self._expr(stmt.value)
            if ret_float:
                value = f"__happy_float__({value})"
            self.w.emit(f"return {value}", loc=stmt.loc, node_id=stmt.id)

    def _assert_call(self, stmt: ir.IRAssert) -> str:
        predicate = self._expr(stmt.predicate)
        text = self._expr_display(stmt.predicate)
        loc = _loc_tuple(stmt.loc, self.filename)
        owner = stmt.owner or "?"
        if stmt.kind == "ensures":
            return (
                f"__happy_contracts__.check_ensures({owner!r}, ({predicate}), "
                f"{text!r}, {stmt.message!r}, {loc})"
            )
        if stmt.kind == "invariant":
            return (
                f"__happy_contracts__.check_invariant({owner!r}, ({predicate}), "
                f"{text!r}, {stmt.message!r}, {loc})"
            )
        if stmt.kind == "rule":
            return (
                f"__happy_contracts__.check_rule({owner!r}, ({predicate}), "
                f"{text!r}, {stmt.message!r}, {loc})"
            )
        return (
            f"__happy_contracts__.check_requires({owner!r}, ({predicate}), "
            f"{text!r}, {stmt.message!r}, {loc})"
        )

    # -- expressions ----------------------------------------------------
    def _expr(self, expr: Optional[ir.IRExpr], name_map: Optional[Dict[str, str]] = None) -> str:
        if expr is None:
            return "None"
        name_map = name_map or {}

        if isinstance(expr, ir.IRLiteral):
            return self._literal(expr)
        if isinstance(expr, ir.IRName):
            mapped = name_map.get(expr.name)
            if mapped is not None:
                return mapped
            local = self._lookup(expr.name)
            if local is not None:
                return local
            if expr.name in self._nullary_variants:
                # A nullary variant used as a value is its constructed form.
                return f"{expr.name}()"
            return expr.name
        if isinstance(expr, ir.IRUnary):
            operand = self._expr(expr.operand, name_map)
            if expr.op in ("!", "not"):
                return f"(not ({operand}))"
            return f"({expr.op}{operand})"
        if isinstance(expr, ir.IRBinary):
            left = self._expr(expr.left, name_map)
            right = self._expr(expr.right, name_map)
            op = expr.op
            if op == "&&":
                op = "and"
            elif op == "||":
                op = "or"
            return f"(({left}) {op} ({right}))"
        if isinstance(expr, ir.IRCall):
            if (
                isinstance(expr.callee, ir.IRName)
                and expr.callee.name in self._nullary_variants
                and not expr.args
            ):
                return f"{expr.callee.name}()"
            callee = self._expr(expr.callee, name_map)
            args = ", ".join(self._expr(a, name_map) for a in expr.args)
            callee_name = self._callee_name(expr)
            if self._agent is not None and callee_name in ENFORCEMENT_MAP:
                # Route the call through the runtime's capability gate.  The
                # gate checks the operation and then invokes the callee, so the
                # call is never skipped (a bare ``check(...); call()`` prefix
                # would be dropped by an enclosing ``return``).
                loc = _loc_tuple(expr.loc, self.filename)
                prefix = (
                    f"__happy_call__({callee}, {callee_name!r}, "
                    f"{self._agent!r}, {loc}"
                )
                return f"{prefix}, {args})" if args else f"{prefix})"
            return f"{callee}({args})"
        if isinstance(expr, ir.IRMember):
            return f"{self._expr(expr.obj, name_map)}.{expr.name}"
        if isinstance(expr, ir.IRIndex):
            return f"{self._expr(expr.obj, name_map)}[{self._expr(expr.index, name_map)}]"
        if isinstance(expr, ir.IRList):
            return "[" + ", ".join(self._expr(e, name_map) for e in expr.elements) + "]"
        if isinstance(expr, ir.IRStruct):
            fields = ", ".join(
                f"{n}={self._expr(v, name_map)}" for n, v in expr.fields
            )
            return f"{expr.type_name}({fields})"
        if isinstance(expr, ir.IRAwait):
            return f"(await {self._expr(expr.operand, name_map)})"
        if isinstance(expr, ir.IRAiExpr):
            if expr.prompt is not None:
                return f"__happy_ai__({self._expr(expr.prompt, name_map)})"
            return "__happy_ai__(\"\")"
        raise PythonBackendError(f"cannot emit expression of type {type(expr).__name__}")

    def _expr_display(self, expr: Optional[ir.IRExpr]) -> str:
        """A human-readable rendering of a predicate for diagnostics."""
        if expr is None:
            return ""
        if isinstance(expr, ir.IRLiteral):
            return self._literal(expr)
        if isinstance(expr, ir.IRName):
            return expr.name
        if isinstance(expr, ir.IRUnary):
            return f"{expr.op}{self._expr_display(expr.operand)}"
        if isinstance(expr, ir.IRBinary):
            return f"{self._expr_display(expr.left)} {expr.op} {self._expr_display(expr.right)}"
        if isinstance(expr, ir.IRCall):
            args = ", ".join(self._expr_display(a) for a in expr.args)
            return f"{self._expr_display(expr.callee)}({args})"
        if isinstance(expr, ir.IRMember):
            return f"{self._expr_display(expr.obj)}.{expr.name}"
        if isinstance(expr, ir.IRIndex):
            return f"{self._expr_display(expr.obj)}[{self._expr_display(expr.index)}]"
        return self._expr(expr)

    def _literal(self, expr: ir.IRLiteral) -> str:
        kind = expr.literal_kind
        value = expr.value
        if kind == "bool":
            return "True" if value else "False"
        if kind == "int":
            return repr(int(value))
        if kind == "float":
            fv = float(value)
            if fv != fv or fv in (float("inf"), float("-inf")):
                return f"float({str(fv)!r})"
            return repr(fv)
        if kind == "string":
            return json.dumps(value, ensure_ascii=False)
        if kind == "char":
            return json.dumps(value, ensure_ascii=False)
        if kind == "null":
            return "None"
        return json.dumps(value, ensure_ascii=False)

    @staticmethod
    def _callee_name(call: ir.IRCall) -> Optional[str]:
        callee = call.callee
        if isinstance(callee, ir.IRName):
            return callee.name
        if isinstance(callee, ir.IRMember):
            return callee.name
        return None


# ---------------------------------------------------------------------------
# Convenience API
# ---------------------------------------------------------------------------
def generate(module: ir.IRModule, source: Optional[str] = None, filename: Optional[str] = None) -> GeneratedProgram:
    """Lower ``module`` to a :class:`GeneratedProgram`."""
    return PythonGenerator(module, source=source, filename=filename).generate()


def _raise_on_errors(analysis: Any, source: Optional[str], filename: Optional[str]) -> None:
    """Refuse to generate code for a program that failed semantic analysis.

    Without this gate the REPL, ``happy debug`` and any other caller of the
    backend would run programs the checker had rejected, including the
    sandbox blocks (E4020) and unknown-function errors (E3001).
    """
    errors = getattr(analysis, "errors", None) or []
    if not errors:
        return
    from ..compiler.errors import HappyError

    first = errors[0]
    rendered = "\n".join(d.render() for d in errors)
    exc = HappyError(
        f"[{first.code}] {first.message}",
        location=first.location,
        source=source,
        suggestion=first.suggestion,
        filename=filename,
    )
    exc.diagnostics = list(errors)
    exc.rendered = rendered
    raise exc


def compile_source(
    source: str,
    filename: Optional[str] = None,
    optimize: bool = True,
    strict: bool = False,
) -> GeneratedProgram:
    """Full backend pipeline: Happy source -> analyzed -> IR -> opt -> Python.

    With ``strict=True`` the program is analysed with the security-strict
    options (unknown functions are hard errors) and a program that has any
    semantic error is *refused* with a :class:`HappyError` instead of being
    generated.  Use it for every entry point that executes untrusted source
    (the REPL, the debugger).  The default keeps the historical lenient
    behaviour that the runtime-fallback tests rely on.
    """
    from ..compiler import analyze
    from ..compiler.ir import lower

    if strict:
        from ..compiler.semantic import SemanticOptions

        analysis = analyze(
            source,
            filename=filename,
            options=SemanticOptions(semantic_security_strict=True),
        )
        _raise_on_errors(analysis, source, filename)
    else:
        analysis = analyze(source, filename=filename)
    module = lower(analysis)
    if optimize:
        from ..compiler.optimizer import optimize as _optimize

        _optimize(module)
    return generate(module, source=source, filename=filename)


def compile_project(
    entry_path: str,
    search_paths: Optional[List[str]] = None,
    optimize: bool = True,
) -> GeneratedProgram:
    """Compile a whole multi-module project from its entry ``.hpy`` file.

    The module loader resolves every ``import`` to a file, orders the modules
    dependencies-first and type-checks them with real interfaces; the merged
    program is then lowered, optimised and generated exactly like a single
    file.
    """
    from ..compiler import analyze
    from ..compiler.ir import lower
    from ..compiler.modules import ModuleLoader

    loader = ModuleLoader(search_paths=search_paths)
    project = loader.load_project(entry_path)
    merged = project.merged_program()
    analysis = analyze(merged, filename=project.entry_path)
    module = lower(analysis)
    if optimize:
        from ..compiler.optimizer import optimize as _optimize

        _optimize(module)
    return generate(module, source=None, filename=project.entry_path)
