"""Semantic analysis and static type checking for the Happy language.

This stage consumes the AST produced by :mod:`happy.compiler.parser` and:

* builds a lexical :class:`~happy.compiler.symbol_table.SymbolTable`;
* infers and checks types for every expression and statement (see
  :mod:`happy.compiler.types`);
* validates **enum exhaustiveness** for match-like ``if`` chains;
* resolves module **imports / exports**;
* statically detects **unused variables**, **unreachable code** and
  **type mismatches**;
* checks **contracts** (``requires`` / ``ensures`` / ``invariant`` are ``Bool``),
  **effects**, **permissions** and **capabilities**.

Diagnostics
-----------
Errors are *collected*, not thrown, so a single run reports as many problems as
possible.  Every :class:`Diagnostic` renders in the same style as the lexer and
parser::

    demo.hpy:12:9: error: [E4002] type mismatch: expected Float, found String
      12 |     let x: Float = "hi"
         |                  ^
      help: change the value or the declared type

Use :func:`analyze` for the common one-call workflow.
"""

from __future__ import annotations

import keyword as _pykeyword
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from . import ast
from .errors import HappyError, SourceLocation, format_diagnostic
from .symbol_table import (
    ImmutableBindingError,
    ImportedSymbol,
    ScopeError,
    ScopeKind,
    Symbol,
    SymbolKind,
    SymbolTable,
)
from .types import (
    ANY,
    NEVER,
    UNIT,
    UNKNOWN,
    AnyType,
    EnumType,
    FunctionType,
    GenericInstance,
    ListType,
    MapType,
    NeverType,
    OptionType,
    PrimitiveType,
    ResultType,
    SetType,
    StructType,
    Substitution,
    TupleType,
    Type,
    TypeVar,
    UnknownType,
    apply_substitution,
    assignable,
    common_supertype,
)

__all__ = [
    "Severity",
    "Diagnostic",
    "SemanticOptions",
    "AnalysisResult",
    "SemanticAnalyzer",
    "Pattern",
    "ExhaustivenessResult",
    "check_exhaustive",
    "analyze",
    "BUILTIN_FUNCTIONS",
    "KNOWN_EFFECTS",
]


# ---------------------------------------------------------------------------
# Severity & diagnostics
# ---------------------------------------------------------------------------
class Severity:
    """Diagnostic severities (string constants for easy comparison)."""

    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"


#: Effects the runtime understands.  Unknown effects are reported as warnings.
KNOWN_EFFECTS: Set[str] = {
    "io",
    "net",
    "fs",
    "db",
    "log",
    "time",
    "rand",
    "state",
    "ai",
    "gpu",
    "env",
    "proc",
}

#: Signatures of built-in functions available in every module.
BUILTIN_FUNCTIONS: Dict[str, FunctionType] = {
    "print": FunctionType([ANY], UNIT),
    "println": FunctionType([ANY], UNIT),
    "len": FunctionType([ANY], PrimitiveType("Int")),
    "str": FunctionType([ANY], PrimitiveType("String")),
    "int": FunctionType([ANY], PrimitiveType("Int")),
    "float": FunctionType([ANY], PrimitiveType("Float")),
    "http_get": FunctionType([PrimitiveType("String")], ANY),
    "http_post": FunctionType([PrimitiveType("String"), ANY], ANY),
    "json_parse": FunctionType([PrimitiveType("String")], ANY),
    "read_file": FunctionType([PrimitiveType("String")], PrimitiveType("String")),
    "write_file": FunctionType(
        [PrimitiveType("String"), PrimitiveType("String")], UNIT
    ),
    "now": FunctionType([], PrimitiveType("Int")),
    "rand": FunctionType([], PrimitiveType("Float")),
    "range": FunctionType([PrimitiveType("Int"), PrimitiveType("Int")], ANY),
    "pay": FunctionType([PrimitiveType("Float")], PrimitiveType("Float")),
    "stringify": FunctionType([ANY], PrimitiveType("String")),
    "abort": FunctionType([PrimitiveType("String")], UNIT),
    "assert": FunctionType([PrimitiveType("Bool"), PrimitiveType("String")], UNIT),
    # Secret handling is a language builtin: ``reveal`` / ``secret`` are always
    # in scope, so they resolve without an explicit import.
    "reveal": FunctionType([ANY], ANY),
    "secret": FunctionType([ANY], ANY),
}


@dataclass
class Diagnostic:
    """A single semantic message with an error code and precise location."""

    code: str
    message: str
    location: Optional[SourceLocation] = None
    suggestion: Optional[str] = None
    severity: str = Severity.ERROR
    filename: Optional[str] = None
    source: Optional[str] = None

    def render(self) -> str:
        return format_diagnostic(
            f"[{self.code}] {self.message}",
            location=self.location,
            source=self.source,
            suggestion=self.suggestion,
            filename=self.filename,
            severity=self.severity,
        )

    @property
    def line(self) -> int:
        return self.location.line if self.location else 0

    @property
    def column(self) -> int:
        return self.location.column if self.location else 0

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.render()


# Error-code catalogue (documented for users).
CODE_UNKNOWN_NAME = "E3001"
CODE_DUPLICATE = "E3002"
CODE_UNKNOWN_TYPE = "E3003"
CODE_UNKNOWN_FIELD = "E3004"
CODE_IMMUTABLE = "E3006"
CODE_INVALID_DECL = "E4001"
CODE_TYPE_MISMATCH = "E4002"
CODE_NOT_BOOL = "E4003"
CODE_ARITY = "E4004"
CODE_INVALID_EXPR = "E4005"
CODE_MISSING_FIELD = "E4006"
CODE_DUPLICATE_FIELD_INIT = "E4007"
CODE_INVALID_TARGET = "E4009"
CODE_PERMISSION_CONFLICT = "E4010"
CODE_UNKNOWN_REF = "E4011"
CODE_W_UNREACHABLE = "W3100"
CODE_W_UNUSED = "W3101"
CODE_W_NONEXHAUSTIVE = "W3108"
CODE_NONEXHAUSTIVE_MATCH = "E4012"
CODE_UNREACHABLE_MATCH_ARM = "E4013"
CODE_W_UNKNOWN_EFFECT = "W3109"
CODE_W_SECRET = "W3120"
CODE_W_UNKNOWN_FUNC = "W3111"
CODE_UNKNOWN_STD_MODULE = "E3007"
CODE_MISSING_RETURN = "E4021"
CODE_DUPLICATE_APP = "E4022"
CODE_RESERVED_NAME = "E4023"
CODE_MEMBER_ACCESS = "E4020"

#: Standard-library modules that actually exist (``import std.<name>``).
KNOWN_STD_MODULES = frozenset(
    {
        "async", "collections", "core", "crypto", "encoding", "env", "fs",
        "io", "json", "logging", "math", "net", "process", "random", "regex",
        "time",
    }
)

#: Host-runtime attributes that must never be reachable from Happy code.  The
#: dunder prefix check alone is not enough: coroutine / generator / function /
#: frame objects expose ``f_builtins`` and friends without any underscore, and
#: ``str.format`` can traverse attributes (``"{0.__globals__}"``).
_BLOCKED_MEMBERS = frozenset(
    {
        "format", "format_map", "mro", "cr_frame", "cr_code", "cr_await",
        "gi_frame", "gi_code", "gi_yieldfrom", "ag_frame", "ag_code",
        "f_builtins", "f_globals", "f_locals", "f_back", "f_code",
        "tb_frame", "tb_next", "func_globals", "func_code", "co_code",
        "co_consts", "co_names", "mro",
    }
)

#: Builtins that genuinely accept any number of arguments.
_VARIADIC_BUILTINS = frozenset({"print", "println"})
#: Builtins with optional trailing arguments: name -> maximum argument count.
_OPTIONAL_ARG_BUILTINS = {"secret": 2}

#: Names that are reserved words of the Python target and therefore cannot be
#: used for top-level declarations (locals and parameters are renamed instead).
_PY_RESERVED_TOP_LEVEL = frozenset(_pykeyword.kwlist) | {"None", "True", "False"}

#: Maximum expression nesting depth the type checker will descend into before
#: reporting a clean diagnostic (guards against RecursionError on hostile input).
_MAX_EXPR_DEPTH = 100
CODE_N_UNUSED_IMPORT = "N3200"


@dataclass
class SemanticOptions:
    """Tunable behaviour of the analyzer."""

    #: When True, calling a function that is neither declared, imported nor a
    #: builtin is a hard ERROR (``E3001``).  ``semantic_security_strict`` is the
    #: same switch under the name the pipeline uses; either one arms it.
    strict_unknown_functions: bool = False
    #: Compiler-level sandbox enforcement.  Set by the CLI/pipeline so that an
    #: “unlisted” call such as ``open(...)`` or ``__import__("os")`` fails the
    #: build instead of executing verbatim in Python.
    semantic_security_strict: bool = False
    unused_variable_severity: str = Severity.WARNING
    unused_import_severity: str = Severity.NOTE
    unknown_effect_severity: str = Severity.WARNING
    report_secret_access: bool = True
    check_unreachable: bool = True
    #: Severity of a contract the static prover shows is *definitely* violated
    #: (a call that breaks a ``requires``, an ``ensures`` no path can satisfy,
    #: contradictory preconditions, an invariant-violating literal).  The
    #: default is a warning, because a program may deliberately demonstrate the
    #: run-time failure (``R1003``); set ``Severity.ERROR`` to reject at
    #: compile time (the codes then read ``E4030`` ... instead of ``W4030``).
    contract_proof_severity: str = Severity.WARNING


@dataclass
class AnalysisResult:
    """The outcome of a semantic-analysis run."""

    program: Optional[ast.Program] = None
    diagnostics: List[Diagnostic] = field(default_factory=list)
    symbol_table: Optional[SymbolTable] = None
    types: Dict[str, Type] = field(default_factory=dict)
    functions: Dict[str, FunctionType] = field(default_factory=dict)
    module_name: Optional[str] = None
    exports: Set[str] = field(default_factory=set)
    #: Outcome of the static contract prover (``None`` if it did not run, for
    #: example because the program already had errors).
    contract_proofs: Optional[object] = None

    # -- queries -------------------------------------------------------
    @property
    def errors(self) -> List[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == Severity.ERROR]

    @property
    def warnings(self) -> List[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == Severity.WARNING]

    @property
    def notes(self) -> List[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == Severity.NOTE]

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def has_errors(self) -> bool:
        return bool(self.errors)

    # -- rendering -----------------------------------------------------
    def format(self) -> str:
        return "\n\n".join(d.render() for d in self.sorted())

    def sorted(self) -> List[Diagnostic]:
        return sorted(
            self.diagnostics,
            key=lambda d: (d.line, d.column, d.code),
        )

    def summary(self) -> str:
        return (
            f"{len(self.errors)} error(s), "
            f"{len(self.warnings)} warning(s), "
            f"{len(self.notes)} note(s)"
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "module": self.module_name,
            "ok": self.ok,
            "summary": self.summary(),
            "diagnostics": [
                {
                    "code": d.code,
                    "severity": d.severity,
                    "message": d.message,
                    "line": d.line,
                    "column": d.column,
                    "suggestion": d.suggestion,
                }
                for d in self.sorted()
            ],
        }


# ---------------------------------------------------------------------------
# Exhaustiveness (enum pattern matching)
# ---------------------------------------------------------------------------
@dataclass
class Pattern:
    """A simplified match pattern used by the exhaustiveness engine.

    ``kind`` is one of ``"variant"``, ``"wildcard"`` or ``"binding"``.
    """

    kind: str
    variant_name: Optional[str] = None
    loc: Optional[SourceLocation] = None


@dataclass
class ExhaustivenessResult:
    ok: bool
    missing: List[str] = field(default_factory=list)
    redundant: List[str] = field(default_factory=list)
    unreachable_patterns: List[int] = field(default_factory=list)


def check_exhaustive(
    enum: EnumType, patterns: Sequence[Pattern]
) -> ExhaustivenessResult:
    """Return whether ``patterns`` cover every variant of ``enum``.

    A ``wildcard``/``binding`` pattern makes the match exhaustive; variant
    patterns that appear after a wildcard are reported as unreachable, and
    repeated variants as redundant.
    """
    all_variants = enum.variant_names()
    covered: List[str] = []
    missing: List[str] = []
    redundant: List[str] = []
    unreachable: List[int] = []
    has_wildcard = False

    for i, pat in enumerate(patterns):
        if pat.kind in ("wildcard", "binding"):
            if has_wildcard:
                unreachable.append(i)
            has_wildcard = True
            continue
        if has_wildcard:
            unreachable.append(i)
            continue
        name = pat.variant_name
        if name not in all_variants:
            redundant.append(name or "<unknown>")
            continue
        if name in covered:
            redundant.append(name)
        else:
            covered.append(name)

    if not has_wildcard:
        missing = [v for v in all_variants if v not in covered]

    return ExhaustivenessResult(
        ok=not missing,
        missing=missing,
        redundant=redundant,
        unreachable_patterns=unreachable,
    )


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------
class SemanticAnalyzer:
    """Walks the AST, building scopes and checking types + contracts."""

    def __init__(
        self,
        source: Optional[str] = None,
        filename: Optional[str] = None,
        options: Optional[SemanticOptions] = None,
        module_interfaces: Optional[Dict[str, "ModuleInterface"]] = None,
    ) -> None:
        self.source = source
        self.filename = filename
        self.options = options or SemanticOptions()
        self.table = SymbolTable()
        self.types: Dict[str, Type] = {}
        self.functions: Dict[str, FunctionType] = {}
        #: Number of leading *required* parameters per user function (the rest
        #: have defaults and may be omitted at the call site).
        self._min_args: Dict[str, int] = {}
        self.permissions: Dict[str, ast.PermissionDecl] = {}
        self.capabilities: Dict[str, ast.CapabilityDecl] = {}
        self.rules: Dict[str, ast.RuleDecl] = {}
        self.agents: Dict[str, ast.AgentDecl] = {}
        self.ai_blocks: Dict[str, ast.AiDecl] = {}
        self.traits: Dict[str, ast.TraitDecl] = {}
        self.trait_methods: Dict[str, Dict[str, FunctionType]] = {}
        self.impls: List[ast.ImplDecl] = []
        self.type_methods: Dict[str, Dict[str, FunctionType]] = {}
        self.variant_index: Dict[str, List[Tuple[str, Tuple[Type, ...]]]] = {}
        self._decl_symbols: Dict[int, Symbol] = {}
        self.diagnostics: List[Diagnostic] = []

        # analysis context
        self._func_stack: List[FunctionType] = []
        self._return_type: Type = UNIT
        self._loop_depth = 0
        self._type_params: Set[str] = set()
        self._impl_self_type: Optional[str] = None
        self._permissive = False
        self._expr_depth = 0
        self._module_interfaces = module_interfaces or {}
        self.module_name: Optional[str] = None

    # ------------------------------------------------------------------
    # Diagnostic helpers
    # ------------------------------------------------------------------
    def _emit(
        self,
        code: str,
        message: str,
        loc: Optional[SourceLocation],
        suggestion: Optional[str] = None,
        severity: str = Severity.ERROR,
    ) -> None:
        self.diagnostics.append(
            Diagnostic(
                code=code,
                message=message,
                location=loc,
                suggestion=suggestion,
                severity=severity,
                filename=self.filename,
                source=self.source,
            )
        )

    def _error(self, code, message, loc, suggestion=None):
        self._emit(code, message, loc, suggestion, Severity.ERROR)

    def _warn(self, code, message, loc, suggestion=None):
        self._emit(code, message, loc, suggestion, Severity.WARNING)

    def _note(self, code, message, loc, suggestion=None):
        self._emit(code, message, loc, suggestion, Severity.NOTE)

    @staticmethod
    def _type_name(t: Type) -> str:
        return apply_substitution(t, Substitution()).display()

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------
    def analyze(self, program: ast.Program) -> AnalysisResult:
        """Run all semantic passes over ``program`` and return the result."""
        self.program_ref = program
        self._declare_module(program)
        # An `export a, b` declaration marks names as this module's public API.
        for decl in program.declarations:
            if isinstance(decl, ast.ExportDecl):
                for export_name in decl.names:
                    self.table.module_scope.exports.add(export_name)
        self._analyze_declarations(program)
        self._report_unused()
        self._report_unused_imports()

        return AnalysisResult(
            program=program,
            diagnostics=sorted(
                self.diagnostics, key=lambda d: (d.line, d.column, d.code)
            ),
            symbol_table=self.table,
            types=self.types,
            functions=self.functions,
            module_name=self.module_name,
            contract_proofs=getattr(self, "contract_proofs", None),
            exports=set(self.table.module_scope.exports),
        )

    # ------------------------------------------------------------------
    # Pass 1 — declaration (hoisting)
    # ------------------------------------------------------------------
    def _declare_module(self, program: ast.Program) -> None:
        if program.module is not None:
            self.module_name = program.module.name
            self.table.module_scope.name = program.module.name or "<module>"

        for imp in program.imports:
            self._declare_import(imp)
            self._resolve_import(imp)

        for decl in program.declarations:
            if isinstance(decl, ast.ModuleDecl):
                continue
            if isinstance(decl, (ast.ImportDecl, ast.ExportDecl)):
                if isinstance(decl, ast.ImportDecl):
                    self._declare_import(decl)
                    self._resolve_import(decl)
                continue
            self._declare_top_level(decl)

    def _declare_import(self, imp: ast.ImportDecl) -> None:
        mod = imp.name or ""
        if mod == "std" or mod.startswith("std."):
            short = mod.split(".", 1)[1].split(".")[0] if "." in mod else ""
            if short not in KNOWN_STD_MODULES:
                self._error(
                    CODE_UNKNOWN_STD_MODULE,
                    f"unknown standard-library module '{mod}'",
                    imp.loc,
                    "available: " + ", ".join(f"std.{m}" for m in sorted(KNOWN_STD_MODULES)),
                )
        if imp.symbols:
            module_path = imp.name
            for sym_name in imp.symbols:
                self._add_import_symbol(sym_name, module_path, sym_name, imp.loc)
        else:
            module_path = imp.name
            local = imp.alias or module_path.split(".")[0]
            self._add_import_symbol(local, module_path, None, imp.loc)

    def _add_import_symbol(
        self,
        local: str,
        module_path: str,
        original: Optional[str],
        loc: Optional[SourceLocation],
    ) -> None:
        existing = self.table.module_scope.lookup_local(local)
        if existing is not None:
            # Re-importing the same module root (e.g. ``import std.io`` then
            # ``import std.json``) rebinds the same name to the same root, so
            # it is harmless rather than a collision.
            if existing.kind == SymbolKind.IMPORT and original is None:
                if (existing.origin or "").split(".")[0] == module_path.split(".")[0]:
                    return
            self._error(
                CODE_DUPLICATE,
                f"'{local}' is already defined",
                loc,
                "an import name collides with an existing declaration; use 'as' to rename it",
            )
            return
        sym = self.table.define(
            local,
            SymbolKind.IMPORT,
            type=ANY,
            loc=loc,
            origin=module_path,
            exported=False,
        )
        self.table.add_import(
            ImportedSymbol(local, module_path, original, loc)
        )
        _ = sym

    def _declare_top_level(self, decl: ast.Decl) -> None:
        name = getattr(decl, "name", "")
        loc = getattr(decl, "loc", None)
        if not name:
            return
        if name in _PY_RESERVED_TOP_LEVEL and not isinstance(decl, ast.ImplDecl):
            self._error(
                CODE_RESERVED_NAME,
                f"'{name}' is a reserved word of the compilation target and "
                f"cannot name a top-level declaration",
                loc,
                "rename the declaration",
            )
            return

        sym: Optional[Symbol] = None
        if isinstance(decl, ast.StructDecl):
            # Announce the name immediately so forward references resolve; the
            # full structure is filled in during pass 2.
            placeholder = StructType(name, generics=decl.generics)
            self.types[name] = placeholder
            sym = self._register_named(name, SymbolKind.TYPE, loc, type=placeholder)
        elif isinstance(decl, ast.EnumDecl):
            placeholder = EnumType(name)
            self.types[name] = placeholder
            sym = self._register_named(name, SymbolKind.ENUM, loc, type=placeholder)
        elif isinstance(decl, ast.FunctionDecl):
            sig = self._signature_of(decl)
            self.functions[name] = sig
            sym = self._register_named(name, SymbolKind.FUNCTION, loc, type=sig)
        elif isinstance(decl, ast.RuleDecl):
            self.rules[name] = decl
            sym = self._register_named(name, SymbolKind.RULE, loc)
        elif isinstance(decl, ast.PermissionDecl):
            self.permissions[name] = decl
            sym = self._register_named(name, SymbolKind.PERMISSION, loc)
        elif isinstance(decl, ast.CapabilityDecl):
            self.capabilities[name] = decl
            sym = self._register_named(name, SymbolKind.CAPABILITY, loc)
        elif isinstance(decl, ast.AgentDecl):
            self.agents[name] = decl
            sym = self._register_named(name, SymbolKind.AGENT, loc)
        elif isinstance(decl, ast.AiDecl):
            self.ai_blocks[name] = decl
            sym = self._register_named(name, SymbolKind.AI, loc)
        elif isinstance(decl, ast.TraitDecl):
            self.traits[name] = decl
            sym = self._register_named(name, SymbolKind.TYPE, loc)
        elif isinstance(decl, ast.ImplDecl):
            # An ``impl`` block introduces no new top-level name (its ``name``
            # is the trait it implements), so it is deliberately not declared.
            return
        elif isinstance(decl, ast.ConstDecl):
            declared = (
                self._resolve_type(decl.type_annotation, loc)
                if decl.type_annotation is not None
                else None
            )
            sym = self._register_named(
                name,
                SymbolKind.VARIABLE,
                loc,
                mutable=decl.mutable,
                type=declared or UNKNOWN,
            )
        elif isinstance(decl, ast.AppDecl):
            sym = self._register_named(name, SymbolKind.VARIABLE, loc, mutable=True)
        if sym is not None:
            self._decl_symbols[id(decl)] = sym

    def _register_named(
        self,
        name: str,
        kind: SymbolKind,
        loc: Optional[SourceLocation],
        mutable: bool = False,
        type: object = None,
    ) -> Optional[Symbol]:
        if self.table.module_scope.lookup_local(name) is not None:
            existing = self.table.module_scope.lookup_local(name)
            self._error(
                CODE_DUPLICATE,
                f"'{name}' is already defined in this module "
                f"(as a {existing.kind.value})",
                loc,
                "rename one of the declarations",
            )
            return None
        sym = self.table.define(
            name,
            kind,
            type=type,
            loc=loc,
            mutable=mutable,
            exported=True,
            ignore_unused=True,
        )
        self.table.mark_export(name)
        return sym

    # ------------------------------------------------------------------
    # Pass 2 — analysis
    # ------------------------------------------------------------------
    def _analyze_declarations(self, program: ast.Program) -> None:
        # Phase A: fill in the real structure of user-defined types now that
        # every placeholder name is known (declaration order does not matter).
        for decl in program.declarations:
            if isinstance(decl, ast.StructDecl):
                saved = self._type_params
                self._type_params = set(decl.generics)
                self.types[decl.name] = self._build_struct_type(decl)
                self._type_params = saved
            elif isinstance(decl, ast.EnumDecl):
                enum_t = self._build_enum_type(decl)
                self.types[decl.name] = enum_t
                for vname, payload in enum_t.variants:
                    self.variant_index.setdefault(vname, []).append(
                        (decl.name, payload)
                    )

        # Phase A2: collect trait method signatures up front so that `impl`
        # conformance can be checked regardless of declaration order.
        for decl in program.declarations:
            if isinstance(decl, ast.TraitDecl):
                self._collect_trait(decl)

        # Phase B: analyze every declaration's body, contracts and effects.
        seen_app = False
        for decl in program.declarations:
            if isinstance(decl, (ast.ModuleDecl, ast.ImportDecl)):
                continue
            if isinstance(decl, ast.AppDecl):
                if seen_app:
                    self._error(
                        CODE_DUPLICATE_APP,
                        "a program may contain only one 'app' block",
                        getattr(decl, "loc", None),
                        "merge the bodies of the 'app' blocks into one",
                    )
                    continue
                seen_app = True
            self._analyze_decl(decl)

        # Phase C: static contract proofs (interval analysis).  Only on a
        # program that is otherwise error-free, and never allowed to crash
        # the compiler: a bug in the prover must not reject valid code.
        self.contract_proofs = None
        if not any(d.severity == Severity.ERROR for d in self.diagnostics):
            try:
                from .contract_proofs import verify_program

                as_error = self.options.contract_proof_severity == Severity.ERROR

                def _report(sev, code, msg, loc, hint):
                    if sev == "error" and not as_error:
                        sev, code = Severity.WARNING, "W" + code[1:]
                    self._emit(code, msg, loc, hint, sev)

                self.contract_proofs = verify_program(program, _report)
            except Exception:  # noqa: BLE001 - defensive, see above
                self.contract_proofs = None

    def _resolve_import(self, imp: ast.ImportDecl) -> None:
        """Resolve an import against a supplied module interface, if any."""
        interface = self._module_interfaces.get(imp.name)
        if interface is None:
            # Unknown module: keep the permissive 'Any' binding so that
            # cross-module code type-checks until interfaces are supplied.
            return
        if not imp.symbols:
            local = imp.alias or imp.name.split(".")[0]
            sym = self.table.module_scope.lookup_local(local)
            if sym is not None:
                sym.detail = "module"
            return
        for sname in imp.symbols:
            sym = self.table.module_scope.lookup_local(sname)
            if sname in interface.types:
                if sym is not None:
                    sym.type = interface.types[sname]
                self.types[sname] = interface.types[sname]
            elif sname in interface.functions:
                if sym is not None:
                    sym.type = interface.functions[sname]
                self.functions.setdefault(sname, interface.functions[sname])
            elif sname in interface.values:
                if sym is not None:
                    sym.type = interface.values[sname]
            else:
                self._error(
                    "E3005",
                    f"module '{imp.name}' does not export '{sname}'",
                    imp.loc,
                    "check the module's public interface",
                )

    def _analyze_decl(self, decl: ast.Decl) -> None:
        if isinstance(decl, ast.StructDecl):
            self._check_struct(decl)
        elif isinstance(decl, ast.EnumDecl):
            self._check_enum(decl)
        elif isinstance(decl, ast.FunctionDecl):
            self._check_function(decl)
        elif isinstance(decl, ast.RuleDecl):
            self._check_rule(decl)
        elif isinstance(decl, ast.PermissionDecl):
            self._check_permission(decl)
        elif isinstance(decl, ast.CapabilityDecl):
            self._check_capability(decl)
        elif isinstance(decl, ast.AgentDecl):
            self._check_agent(decl)
        elif isinstance(decl, ast.AiDecl):
            self._check_ai(decl)
        elif isinstance(decl, ast.AppDecl):
            self._check_app(decl)
        elif isinstance(decl, ast.TraitDecl):
            self._check_trait(decl)
        elif isinstance(decl, ast.ImplDecl):
            self._check_impl(decl)
        elif isinstance(decl, ast.ConstDecl):
            self._check_const(decl)

    # -- traits & impls (Step 7) --------------------------------------
    #: Method signatures of the traits provided by the standard library.
    def _check_const(self, decl: ast.ConstDecl) -> None:
        """Type-check a module-level ``let``/``var`` binding."""
        declared = None
        if decl.type_annotation is not None:
            declared = self._resolve_type(decl.type_annotation, decl.loc) or UNKNOWN
        inferred = declared
        if decl.value is not None:
            inferred = self._type_expr(decl.value)
            if declared is not None:
                self._check_assignable(
                    inferred,
                    declared,
                    decl.value.loc,
                    f"initializer of '{decl.name}'",
                    source_expr=decl.value,
                )
                inferred = declared
        elif declared is None:
            self._error(
                CODE_INVALID_DECL,
                f"'{decl.name}' must have either a type annotation or a value",
                decl.loc,
                f"write 'let {decl.name}: <Type>' or 'let {decl.name} = <value>'",
            )
            inferred = UNKNOWN
        sym = self._decl_symbols.get(id(decl))
        if sym is not None:
            sym.type = inferred

    BUILTIN_TRAITS: Dict[str, Dict[str, int]] = {
        "Display": {"show": 1},
        "Debug": {"debug": 1},
        "Eq": {"eq": 2},
        "Ord": {"compare": 2},
        "Hash": {"hash": 1},
        "Iterator": {"next": 1},
    }

    def _collect_trait(self, decl: ast.TraitDecl) -> None:
        methods: Dict[str, FunctionType] = {}
        saved_self = self._impl_self_type
        self._impl_self_type = decl.name
        for m in decl.methods:
            if m.name in methods:
                self._error(
                    CODE_DUPLICATE,
                    f"duplicate method '{m.name}' in trait '{decl.name}'",
                    m.loc,
                    "remove one of the duplicated methods",
                )
            saved = self._type_params
            self._type_params = set()
            params = [
                self._resolve_type(p.type_annotation, p.loc) or UNKNOWN
                for p in m.params
            ]
            ret = self._resolve_type(m.returns, m.loc) or UNIT
            self._type_params = saved
            methods[m.name] = FunctionType(params, ret, is_async=m.is_async)
        self._impl_self_type = saved_self
        self.trait_methods[decl.name] = methods

    def _check_trait(self, decl: ast.TraitDecl) -> None:
        if decl.name not in self.trait_methods:
            self._collect_trait(decl)
        for m in decl.methods:
            if m.body is None:
                continue
            # A default method body is type-checked like a standalone function.
            synthetic = ast.FunctionDecl(
                name=m.name,
                params=m.params,
                returns=m.returns,
                body=m.body,
                contracts=m.contracts,
                generics=list(getattr(m, "generics", []) or []),
                is_async=m.is_async,
                loc=m.loc,
            )
            self._check_function(synthetic)

    def _check_impl(self, decl: ast.ImplDecl) -> None:
        self.impls.append(decl)
        saved_self = self._impl_self_type
        self._impl_self_type = decl.for_type
        if decl.for_type not in self.types:
            self._error(
                CODE_UNKNOWN_TYPE,
                f"'impl {decl.name} for {decl.for_type}' references an unknown type '{decl.for_type}'",
                decl.loc,
                "declare the type with 'type <Name> { ... }'",
            )
        is_builtin = decl.name in self.BUILTIN_TRAITS
        if decl.name not in self.traits and not is_builtin:
            self._error(
                CODE_UNKNOWN_REF,
                f"impl for unknown trait '{decl.name}'",
                decl.loc,
                "declare the trait with 'trait <Name> { ... }' first",
            )

        provided: Dict[str, int] = {}
        impl_methods = self.type_methods.setdefault(decl.for_type, {})
        for m in decl.methods:
            if m.name in provided:
                self._error(
                    CODE_DUPLICATE,
                    f"duplicate method '{m.name}' in impl of '{decl.name}' for '{decl.for_type}'",
                    m.loc,
                    "remove one of the duplicated methods",
                )
            provided[m.name] = len(m.params)
            self._check_function(m)
            impl_methods[m.name] = self.functions.get(m.name, FunctionType([], UNKNOWN))

        # Conformance: every trait method must be implemented (unless it comes
        # with a default body).
        if decl.name in self.traits:
            trait = self.traits[decl.name]
            impl_by_name = {m.name: m for m in decl.methods}
            for tm in trait.methods:
                if tm.name in provided:
                    self._check_impl_signature(decl, tm, impl_by_name[tm.name])
                    continue
                if tm.body is not None:
                    continue  # default implementation is inherited
                self._error(
                    "E4012",
                    f"impl of '{decl.name}' for '{decl.for_type}' is missing "
                    f"required method '{tm.name}'",
                    decl.loc,
                    f"implement '{tm.name}(...)' or give the trait a default body",
                )
        elif is_builtin:
            for mname in self.BUILTIN_TRAITS[decl.name]:
                if mname not in provided:
                    self._error(
                        "E4012",
                        f"impl of '{decl.name}' for '{decl.for_type}' is missing "
                        f"required method '{mname}'",
                        decl.loc,
                        f"implement '{mname}(...)'",
                    )
        self._impl_self_type = saved_self

    def _check_impl_signature(self, decl, trait_method, impl_method) -> None:
        """An impl method must match the trait's declared signature (E4014)."""
        problems: List[str] = []
        tp, ip = list(trait_method.params), list(impl_method.params)
        if len(tp) != len(ip):
            problems.append(
                f"expects {len(tp)} parameter(s), found {len(ip)}"
            )
        else:
            for i, (a, b) in enumerate(zip(tp, ip)):
                if a.type_annotation is None or b.type_annotation is None:
                    continue  # `self` (or an unannotated parameter)
                ta = self._resolve_type(a.type_annotation, a.loc)
                tb = self._resolve_type(b.type_annotation, b.loc)
                if ta is None or tb is None or _is_soft(ta) or _is_soft(tb):
                    continue
                if ta != tb:
                    problems.append(
                        f"parameter {i + 1} should be {self._type_name(ta)}, "
                        f"found {self._type_name(tb)}"
                    )
        ra = self._resolve_type(trait_method.returns, trait_method.loc) or UNIT
        rb = self._resolve_type(impl_method.returns, impl_method.loc) or UNIT
        if not (_is_soft(ra) or _is_soft(rb)) and ra != rb:
            problems.append(
                f"return type should be {self._type_name(ra)}, found {self._type_name(rb)}"
            )
        if problems:
            self._error(
                "E4014",
                f"method '{impl_method.name}' in 'impl {decl.name} for "
                f"{decl.for_type}' does not match the trait: " + "; ".join(problems),
                impl_method.loc,
                "make the signature identical to the one declared in the trait",
            )

    # -- types ---------------------------------------------------------
    def _build_struct_type(self, decl: ast.StructDecl) -> StructType:
        fields: List[Tuple[str, Type]] = []
        secret_fields: List[str] = []
        seen: Set[str] = set()
        for f in decl.fields:
            if f.name in seen:
                self._error(
                    CODE_DUPLICATE,
                    f"duplicate field '{f.name}' in type '{decl.name}'",
                    f.loc,
                    "remove or rename the duplicate field",
                )
                continue
            seen.add(f.name)
            ftype = self._resolve_type(f.type_annotation, f.loc)
            if ftype is None:
                if f.default is not None:
                    ftype = UNKNOWN
                else:
                    self._error(
                        CODE_INVALID_DECL,
                        f"field '{f.name}' needs a type annotation",
                        f.loc,
                        f"declare it as '{f.name}: <Type>'",
                    )
                    ftype = UNKNOWN
            fields.append((f.name, ftype))
            if f.secret:
                secret_fields.append(f.name)
        return StructType(
            decl.name,
            fields=fields,
            generics=decl.generics,
            secret_fields=secret_fields,
        )

    def _build_enum_type(self, decl: ast.EnumDecl) -> EnumType:
        variants: List[Tuple[str, Tuple[Type, ...]]] = []
        seen: Set[str] = set()
        for v in decl.variants:
            if v.name in seen:
                self._error(
                    CODE_DUPLICATE,
                    f"duplicate variant '{v.name}' in enum '{decl.name}'",
                    v.loc,
                    "remove or rename the duplicate variant",
                )
                continue
            seen.add(v.name)
            payload = [self._resolve_type(p, v.loc) or UNKNOWN for p in v.payload]
            variants.append((v.name, tuple(payload)))
        return EnumType(decl.name, variants=variants)

    def _resolve_type(
        self, node: Optional[ast.TypeNode], loc: Optional[SourceLocation]
    ) -> Optional[Type]:
        """Resolve an AST type node into a semantic :class:`Type`."""
        if node is None:
            return None
        if isinstance(node, ast.PrimitiveType):
            if node.name not in ("Int", "Float", "String", "Bool", "Byte", "Char", "Unit"):
                self._error(
                    CODE_UNKNOWN_TYPE,
                    f"unknown primitive type '{node.name}'",
                    node.loc or loc,
                )
                return UNKNOWN
            return PrimitiveType(node.name)
        if isinstance(node, ast.OptionalType):
            inner = self._resolve_type(node.inner, node.loc) or UNKNOWN
            return OptionType(inner)
        if isinstance(node, ast.NamedType):
            return self._resolve_named_type(node.name, node.loc or loc)
        if isinstance(node, ast.GenericType):
            return self._resolve_generic_type(node)
        if isinstance(node, ast.FunctionType):
            params = [self._resolve_type(p, node.loc) or UNKNOWN for p in node.params]
            ret = self._resolve_type(node.returns, node.loc) or UNIT
            return FunctionType(params, ret)
        if isinstance(node, ast.TupleType):
            return TupleType(
                [self._resolve_type(e, node.loc) or UNKNOWN for e in node.elements]
            )
        return UNKNOWN

    def _resolve_named_type(self, name: str, loc: Optional[SourceLocation]) -> Type:
        if name in self._type_params:
            return TypeVar(name)
        if name == "Self" and self._impl_self_type is not None:
            # `Self` inside an `impl` block means the implementing type.
            return self.types.get(self._impl_self_type, UNKNOWN)
        if name in self.types:
            return self.types[name]
        self._error(
            CODE_UNKNOWN_TYPE,
            f"unknown type '{name}'",
            loc,
            "check the spelling, or declare the type with 'type name { ... }'",
        )
        return UNKNOWN

    def _resolve_generic_type(self, node: ast.GenericType) -> Type:
        name = node.name
        args = [self._resolve_type(a, node.loc) or UNKNOWN for a in node.args]
        builtin = {
            "List": (1, lambda a: ListType(a[0])),
            "Set": (1, lambda a: SetType(a[0])),
            "Option": (1, lambda a: OptionType(a[0])),
            "Future": (1, lambda a: _future(a[0])),
            "Map": (2, lambda a: MapType(a[0], a[1])),
            "Result": (2, lambda a: ResultType(a[0], a[1])),
        }
        if name in builtin:
            arity, build = builtin[name]
            if len(args) != arity:
                self._error(
                    CODE_ARITY,
                    f"'{name}' expects {arity} type argument(s), got {len(args)}",
                    node.loc,
                )
                return UNKNOWN
            return build(args)
        # user-declared generic
        if name in self.types:
            base = self.types[name]
            if isinstance(base, (StructType, EnumType)):
                expected = len(base.generics)
                if expected and len(args) != expected:
                    self._error(
                        CODE_ARITY,
                        f"'{name}' expects {expected} type argument(s), got {len(args)}",
                        node.loc,
                    )
                    return UNKNOWN
                return GenericInstance(name, args)
            return base
        self._error(
            CODE_UNKNOWN_TYPE,
            f"unknown type '{name}'",
            node.loc,
            "check the spelling, or declare the type",
        )
        return UNKNOWN

    # -- structs & enums ----------------------------------------------
    def _check_struct(self, decl: ast.StructDecl) -> None:
        saved = self._type_params
        self._type_params = set(decl.generics)
        struct_t = self.types.get(decl.name)
        if not isinstance(struct_t, StructType):
            struct_t = self._build_struct_type(decl)
        scope = self.table.push_scope(ScopeKind.STRUCT, name=decl.name)
        for f in decl.fields:
            if scope.lookup_local(f.name) is not None:
                continue
            ftype = struct_t.field_type(f.name) or UNKNOWN
            scope.define(
                f.name,
                SymbolKind.FIELD,
                type=ftype,
                loc=f.loc,
                secret=f.secret,
                ignore_unused=True,
            )
            if f.default is not None:
                dt = self._type_expr(f.default)
                self._check_assignable(
                    dt, ftype, f.default.loc, "field default", source_expr=f.default
                )
        # invariants are Bool-typed predicates over the fields
        for inv in decl.invariants:
            self._check_contract_clause(inv, expected=PrimitiveType("Bool"))
        self.table.pop_scope()
        self._type_params = saved

    def _check_enum(self, decl: ast.EnumDecl) -> None:
        # Variants are in scope as bare identifiers so pattern tests such as
        # `kind == Deposit` resolve without a `::` qualifier.
        enum_t = self.types.get(decl.name)
        variant_type: Type = enum_t if isinstance(enum_t, EnumType) else UNKNOWN
        for variant in decl.variants:
            if self.table.module_scope.lookup_local(variant.name) is not None:
                continue
            self.table.define(
                variant.name,
                SymbolKind.ENUM_VARIANT,
                type=variant_type,
                loc=variant.loc,
                ignore_unused=True,
            )

    # -- functions -----------------------------------------------------
    def _signature_of(self, decl: ast.FunctionDecl) -> FunctionType:
        saved = self._type_params
        self._type_params = set(decl.generics)
        params = []
        for p in decl.params:
            params.append(self._resolve_type(p.type_annotation, p.loc) or UNKNOWN)
        ret = self._resolve_type(decl.returns, decl.loc) or UNIT
        self._type_params = saved
        required = len(decl.params)
        while required > 0 and decl.params[required - 1].default is not None:
            required -= 1
        self._min_args[decl.name] = required
        return FunctionType(params, ret, is_async=decl.is_async)

    def _check_function(self, decl: ast.FunctionDecl) -> None:
        saved_params = self._type_params
        self._type_params = set(decl.generics)

        ret = self._resolve_type(decl.returns, decl.loc) or UNIT
        is_async = decl.is_async
        param_types: List[Type] = [
            self._resolve_type(p.type_annotation, p.loc) or UNKNOWN for p in decl.params
        ]
        signature = FunctionType(param_types, ret, is_async=is_async)
        self.functions[decl.name] = signature
        if self.table.module_scope.lookup_local(decl.name) is None:
            # nested function (inside agent/ai) — register in the current scope
            self.table.define(
                decl.name,
                SymbolKind.FUNCTION,
                type=signature,
                loc=decl.loc,
                ignore_unused=True,
            )
        else:
            sym = self.table.module_scope.lookup_local(decl.name)
            if sym is not None:
                sym.type = signature

        self._check_effect_spec(decl.effects)

        # --- contracts & body share a function scope -------------------
        scope = self.table.push_scope(ScopeKind.FUNCTION, name=decl.name)
        seen_params: Set[str] = set()
        for p, pt in zip(decl.params, param_types):
            if p.name in seen_params:
                self._error(
                    CODE_DUPLICATE,
                    f"duplicate parameter '{p.name}' in function '{decl.name}'",
                    p.loc,
                )
                continue
            seen_params.add(p.name)
            scope.define(
                p.name,
                SymbolKind.PARAMETER,
                type=pt,
                loc=p.loc,
                mutable=False,
                ignore_unused=True,
            )
            if p.default is not None:
                dt = self._type_expr(p.default)
                self._check_assignable(
                    dt, pt, p.default.loc, "parameter default", source_expr=p.default
                )

        # requires clauses (with parameters in scope)
        for c in decl.contracts:
            if c.kind == "requires":
                self._check_contract_clause(c)

        # ensures clauses see a `result` pseudo-variable of the return type
        result_sym = scope.define(
            "result",
            SymbolKind.VARIABLE,
            type=ret,
            loc=decl.loc,
            mutable=False,
            ignore_unused=True,
        )
        _ = result_sym
        for c in decl.contracts:
            if c.kind in ("ensures", "invariant"):
                self._check_contract_clause(c)

        # body
        self._func_stack.append(signature)
        self._return_type = ret
        outer_ret = self._return_type
        if decl.body is not None:
            self._check_block(decl.body, new_scope=False)
        self._return_type = outer_ret
        self._func_stack.pop()

        if (
            decl.body is not None
            and decl.returns is not None
            and not is_async_unit(ret)
            and not self._block_always_returns(decl.body)
        ):
            self._error(
                CODE_MISSING_RETURN,
                f"function '{decl.name}' declares a return type of "
                f"{ret.display()} but not every path returns a value",
                decl.loc,
                "add a 'return' on every path, including after 'if' / 'match'",
            )

        self.table.pop_scope()
        self._type_params = saved_params

    # -- definite-return analysis ---------------------------------------
    def _block_always_returns(self, block: Optional[ast.Block]) -> bool:
        if block is None:
            return False
        return any(self._stmt_always_returns(st) for st in block.statements)

    def _stmt_always_returns(self, stmt: ast.Stmt) -> bool:
        if isinstance(stmt, ast.ReturnStmt):
            return True
        if isinstance(stmt, ast.IfStmt):
            if stmt.else_branch is None:
                return False
            eb = stmt.else_branch
            else_ok = (
                self._stmt_always_returns(eb)
                if isinstance(eb, ast.IfStmt)
                else self._block_always_returns(eb)
            )
            return self._block_always_returns(stmt.then_branch) and else_ok
        if isinstance(stmt, ast.MatchStmt):
            if not stmt.arms:
                return False
            for arm in stmt.arms:
                body = arm.body
                if getattr(arm, "bare_expr", False) and body is not None:
                    inner = body.statements
                    if len(inner) == 1 and isinstance(inner[0], ast.ExprStmt):
                        continue  # `pattern -> expr` yields the result
                if not self._block_always_returns(body):
                    return False
            return True
        if isinstance(stmt, ast.WhileStmt):
            cond = stmt.condition
            if isinstance(cond, ast.BoolLiteral) and cond.value:
                return not self._contains_break(stmt.body)
            return False
        return False

    def _contains_break(self, block: Optional[ast.Block]) -> bool:
        if block is None:
            return False
        for st in block.statements:
            if isinstance(st, ast.BreakStmt):
                return True
            if isinstance(st, ast.IfStmt):
                if self._contains_break(st.then_branch):
                    return True
                eb = st.else_branch
                if isinstance(eb, ast.Block) and self._contains_break(eb):
                    return True
                if isinstance(eb, ast.IfStmt) and self._contains_break(
                    ast.Block(statements=[eb])
                ):
                    return True
            elif isinstance(st, ast.MatchStmt):
                if any(self._contains_break(a.body) for a in st.arms):
                    return True
        return False

    # -- rule / permission / capability --------------------------------
    def _check_rule(self, decl: ast.RuleDecl) -> None:
        scope = self.table.push_scope(ScopeKind.FUNCTION, name=decl.name)
        for p in decl.params:
            scope.define(
                p.name,
                SymbolKind.PARAMETER,
                type=self._resolve_type(p.type_annotation, p.loc) or UNKNOWN,
                loc=p.loc,
                ignore_unused=True,
            )
        for c in decl.contracts:
            self._check_contract_clause(c, permissive=True)
        if decl.condition is not None:
            saved = self._permissive
            self._permissive = True
            ctype = self._type_expr(decl.condition)
            self._permissive = saved
            self._require_bool(ctype, decl.condition.loc, "rule condition")
        if decl.body is not None:
            self._check_block(decl.body, new_scope=False)
        self.table.pop_scope()

    def _check_permission(self, decl: ast.PermissionDecl) -> None:
        overlap = set(decl.can) & set(decl.cannot)
        for action in sorted(overlap):
            self._error(
                CODE_PERMISSION_CONFLICT,
                f"action '{action}' is both allowed ('can') and denied "
                f"('cannot') in permission '{decl.name}'",
                decl.loc,
                "an action cannot be simultaneously granted and revoked",
            )

    def _check_capability(self, decl: ast.CapabilityDecl) -> None:
        if not decl.grants:
            self._warn(
                "W3110",
                f"capability '{decl.name}' grants nothing",
                decl.loc,
                "add 'grants <name>' entries or remove the capability",
            )

    # -- agents / ai / app --------------------------------------------
    def _check_agent(self, decl: ast.AgentDecl) -> None:
        for pname in decl.permissions:
            if pname not in self.permissions and not self._is_imported(pname):
                self._error(
                    CODE_UNKNOWN_REF,
                    f"agent '{decl.name}' references unknown permission '{pname}'",
                    decl.loc,
                    "declare it with 'permission <name> { ... }'",
                )
        for cname in decl.capabilities:
            if cname not in self.capabilities and not self._is_imported(cname):
                self._error(
                    CODE_UNKNOWN_REF,
                    f"agent '{decl.name}' references unknown capability '{cname}'",
                    decl.loc,
                    "declare it with 'capability <name> { ... }'",
                )
        self._check_effect_spec(decl.effects)
        for c in decl.contracts:
            self._check_contract_clause(c, permissive=True)
        if decl.goal is not None:
            self._type_expr(decl.goal, permissive=True)
        if decl.body is not None:
            self._check_block(decl.body, new_scope=True)

    def _check_ai(self, decl: ast.AiDecl) -> None:
        for c in decl.contracts:
            self._check_contract_clause(c, permissive=True)
        if decl.prompt is not None:
            self._type_expr(decl.prompt, permissive=True)
        if decl.goal is not None:
            self._type_expr(decl.goal, permissive=True)
        if decl.body is not None:
            self._check_block(decl.body, new_scope=True)

    def _check_app(self, decl: ast.AppDecl) -> None:
        for c in decl.contracts:
            self._check_contract_clause(c, permissive=True)
        if decl.body is not None:
            self._check_block(decl.body, new_scope=True)

    def _is_imported(self, name: str) -> bool:
        return self.table.lookup_import(name) is not None

    # -- effects -------------------------------------------------------
    def _check_effect_spec(self, spec: Optional[ast.EffectSpec]) -> None:
        if spec is None:
            return
        seen: Set[str] = set()
        for eff in spec.effects:
            if eff in seen:
                self._warn(
                    CODE_DUPLICATE,
                    f"duplicate effect '{eff}'",
                    spec.loc,
                    "remove the repeated effect",
                )
                continue
            seen.add(eff)
            if eff not in KNOWN_EFFECTS:
                self._warn(
                    CODE_W_UNKNOWN_EFFECT,
                    f"unknown effect '{eff}'",
                    spec.loc,
                    f"known effects are: {', '.join(sorted(KNOWN_EFFECTS))}",
                )

    # -- contracts -----------------------------------------------------
    def _check_contract_clause(
        self,
        clause: ast.ContractClause,
        expected: Optional[Type] = None,
        permissive: bool = False,
    ) -> None:
        if clause.condition is None:
            return
        saved = self._permissive
        self._permissive = self._permissive or permissive
        ctype = self._type_expr(clause.condition)
        self._permissive = saved
        self._require_bool(
            ctype,
            clause.condition.loc or clause.loc,
            f"'{clause.kind}' condition",
            suggestion=(
                "contract predicates must be Bool expressions "
                "(comparisons, logical operators, or a Bool value)"
            ),
        )

    def _require_bool(
        self,
        t: Type,
        loc: Optional[SourceLocation],
        what: str,
        suggestion: Optional[str] = None,
    ) -> None:
        if _is_soft(t) or isinstance(t, PrimitiveType) and t.name == "Bool":
            return
        self._error(
            CODE_NOT_BOOL,
            f"{what} must be Bool, found {self._type_name(t)}",
            loc,
            suggestion or "use a comparison or logical expression",
        )

    # ------------------------------------------------------------------
    # Statements
    # ------------------------------------------------------------------
    def _check_block(
        self,
        block: ast.Block,
        *,
        new_scope: bool = True,
        scope_kind: ScopeKind = ScopeKind.BLOCK,
        name: str = "",
    ) -> Type:
        if new_scope:
            self.table.push_scope(scope_kind, name=name)
        terminated = False
        for stmt in block.statements:
            if isinstance(stmt, ast.FunctionDecl):
                self._check_function(stmt)
                continue
            if terminated and self.options.check_unreachable:
                self._warn(
                    CODE_W_UNREACHABLE,
                    "unreachable code",
                    stmt.loc,
                    "this statement can never run because control flow has already left the block",
                )
                terminated = False  # report once per region
            st = self._check_stmt(stmt)
            if isinstance(st, NeverType):
                terminated = True
        self._check_enum_match_chains(block.statements)
        if new_scope:
            self.table.pop_scope()
        return UNIT

    def _check_stmt(self, stmt: ast.Stmt) -> Type:
        if isinstance(stmt, ast.LetStmt):
            return self._check_let(stmt)
        if isinstance(stmt, ast.AssignStmt):
            return self._check_assign(stmt)
        if isinstance(stmt, ast.ExprStmt):
            if stmt.expr is not None:
                self._type_expr(stmt.expr)
            return UNIT
        if isinstance(stmt, ast.IfStmt):
            return self._check_if(stmt)
        if isinstance(stmt, ast.WhileStmt):
            return self._check_while(stmt)
        if isinstance(stmt, ast.ForStmt):
            return self._check_for(stmt)
        if isinstance(stmt, ast.ReturnStmt):
            return self._check_return(stmt)
        if isinstance(stmt, ast.BreakStmt):
            if self._loop_depth == 0:
                self._error(
                    CODE_INVALID_EXPR,
                    "'break' used outside of a loop",
                    stmt.loc,
                    "break may only appear inside a 'while' or 'for' loop",
                )
            return NEVER
        if isinstance(stmt, ast.ContinueStmt):
            if self._loop_depth == 0:
                self._error(
                    CODE_INVALID_EXPR,
                    "'continue' used outside of a loop",
                    stmt.loc,
                    "continue may only appear inside a 'while' or 'for' loop",
                )
            return NEVER
        if isinstance(stmt, ast.Block):
            return self._check_block(stmt)
        if isinstance(stmt, ast.MatchStmt):
            return self._check_match(stmt)
        return UNIT

    # -- pattern matching (Step 7) ------------------------------------
    def _check_match(self, stmt: ast.MatchStmt) -> Type:
        subject_t = self._type_expr(stmt.subject) if stmt.subject else UNKNOWN
        enum_t = subject_t if isinstance(subject_t, EnumType) else None
        seen_variants: Set[str] = set()
        seen_literals: Set[str] = set()
        has_catchall = False
        catchall_seen = False

        for arm in stmt.arms:
            self.table.push_scope(ScopeKind.BLOCK, name="match")
            pat = arm.pattern
            if catchall_seen:
                # An arm after a wildcard/binding arm can never be reached.
                self._error(
                    CODE_UNREACHABLE_MATCH_ARM,
                    "unreachable match arm: a previous arm already matches "
                    "every value",
                    getattr(pat, "loc", None) or stmt.loc,
                    "remove this arm, or move it above the wildcard arm",
                )
            if pat is not None and pat.kind in ("wildcard", "binding"):
                has_catchall = True
                catchall_seen = True
            elif pat is not None and pat.kind == "variant" and pat.name:
                if pat.name in seen_variants:
                    self._error(
                        CODE_UNREACHABLE_MATCH_ARM,
                        f"unreachable match arm: variant '{pat.name}' is "
                        "already covered",
                        getattr(pat, "loc", None) or stmt.loc,
                        "remove the duplicate arm",
                    )
            elif pat is not None and pat.kind == "literal":
                key = self._literal_key(pat.value)
                if key is not None:
                    if key in seen_literals:
                        self._error(
                            CODE_UNREACHABLE_MATCH_ARM,
                            "unreachable match arm: this literal is already "
                            "covered",
                            getattr(pat, "loc", None) or stmt.loc,
                            "remove the duplicate arm",
                        )
                    seen_literals.add(key)
            self._bind_pattern(pat, subject_t, seen_variants)
            if arm.body is not None:
                self._check_block(arm.body, new_scope=False)
            self.table.pop_scope()

        if enum_t is not None and not has_catchall:
            missing = [v for v in enum_t.variant_names() if v not in seen_variants]
            if missing:
                # A non-exhaustive ``match`` is a *compile-time* error: the
                # language guarantees a match either covers every variant or
                # has a wildcard/binding arm, so an uncovered variant can never
                # reach the runtime (where it used to fail with a raw error).
                self._error(
                    CODE_NONEXHAUSTIVE_MATCH,
                    "non-exhaustive match: "
                    + ", ".join(missing)
                    + " not covered",
                    stmt.loc,
                    "add the missing variant arms, or a '_' wildcard arm",
                )
        return UNIT

    def _literal_key(self, expr: Optional[ast.Expr]) -> Optional[str]:
        """Return a stable key for a literal pattern value, or None."""
        if expr is None:
            return None
        name = type(expr).__name__
        if name in ("IntLiteral", "FloatLiteral", "StringLiteral", "CharLiteral", "BoolLiteral"):
            return f"{name}:{getattr(expr, 'value', None)!r}"
        return None

    def _bind_pattern(
        self,
        pattern: Optional[ast.MatchPattern],
        subject_t: Type,
        seen_variants: Set[str],
    ) -> None:
        if pattern is None:
            return
        kind = pattern.kind
        if kind == "wildcard":
            return
        if kind == "literal":
            return
        if kind == "binding":
            if pattern.name and pattern.name != "_":
                self.table.define(
                    pattern.name,
                    SymbolKind.VARIABLE,
                    type=subject_t,
                    loc=pattern.loc,
                )
            return
        if kind == "or":
            for sub in pattern.patterns:
                self._bind_pattern(sub, subject_t, seen_variants)
            return
        if kind == "variant":
            if pattern.name:
                seen_variants.add(pattern.name)
            payloads: Tuple[Type, ...] = ()
            if isinstance(subject_t, EnumType):
                payloads = dict(subject_t.variants).get(pattern.name or "", ())
            for i, b in enumerate(pattern.bindings):
                if b == "_":
                    continue
                bt = payloads[i] if i < len(payloads) else UNKNOWN
                self.table.define(b, SymbolKind.VARIABLE, type=bt, loc=pattern.loc)
            return
        if kind == "struct":
            for b in pattern.bindings:
                ft: Type = UNKNOWN
                if isinstance(subject_t, StructType):
                    ft = subject_t.field_type(b) or UNKNOWN
                if b and b != "_":
                    self.table.define(b, SymbolKind.VARIABLE, type=ft, loc=pattern.loc)
            return

    def _check_let(self, stmt: ast.LetStmt) -> Type:
        declared: Optional[Type] = None
        if stmt.type_annotation is not None:
            declared = self._resolve_type(stmt.type_annotation, stmt.loc) or UNKNOWN

        if stmt.value is None:
            if declared is None:
                self._error(
                    CODE_INVALID_DECL,
                    f"'{stmt.name}' must have either a type annotation or an initializer",
                    stmt.loc,
                    f"write 'let {stmt.name}: <Type>' or 'let {stmt.name} = <value>'",
                )
                declared = UNKNOWN
            inferred = declared
        else:
            inferred = self._type_expr(stmt.value)
            if declared is not None:
                self._check_assignable(
                    inferred,
                    declared,
                    stmt.value.loc,
                    f"initializer of '{stmt.name}'",
                    source_expr=stmt.value,
                )
                inferred = declared

        sym = self.table.define(
            stmt.name,
            SymbolKind.VARIABLE,
            type=inferred,
            loc=stmt.loc,
            mutable=stmt.mutable,
            exported=self.table.at_module_scope(),
        )
        _ = sym
        return UNIT

    def _check_assign(self, stmt: ast.AssignStmt) -> Type:
        target_type = self._check_lvalue(stmt.target)
        if stmt.value is not None:
            value_type = self._type_expr(stmt.value)
            if target_type is not None:
                if stmt.op != "=":
                    # compound assignment: `x += y`
                    target_type = self._compound_result(
                        stmt.op[:-1], target_type, value_type, stmt.loc
                    )
                else:
                    self._check_assignable(
                        value_type, target_type, stmt.value.loc, "assignment",
                        source_expr=stmt.value,
                    )
        return UNIT

    def _check_lvalue(self, target: Optional[ast.Expr]) -> Optional[Type]:
        if target is None:
            return None
        if isinstance(target, ast.Identifier):
            sym = self.table.lookup(target.name)
            if sym is None:
                if not self._permissive:
                    self._error(
                        CODE_UNKNOWN_NAME,
                        f"unknown name '{target.name}'",
                        target.loc,
                        "declare it before assigning",
                    )
                return UNKNOWN
            sym.mark_used()
            try:
                self.table.check_assignment(sym, target.loc)
            except ImmutableBindingError as exc:
                self._error(exc.code, exc.message, exc.location, exc.suggestion)
            return sym.type or UNKNOWN
        if isinstance(target, ast.MemberExpr):
            return self._type_member(target)
        if isinstance(target, ast.IndexExpr):
            return self._type_expr(target)
        self._error(
            CODE_INVALID_TARGET,
            "invalid assignment target",
            target.loc,
            "the left-hand side of '=' must be a variable, field or index",
        )
        return None

    def _check_if(self, stmt: ast.IfStmt) -> Type:
        if stmt.condition is not None:
            ct = self._type_expr(stmt.condition)
            self._require_bool(ct, stmt.condition.loc, "'if' condition")
        if stmt.then_branch is not None:
            self._check_block(stmt.then_branch)
        if stmt.else_branch is not None:
            if isinstance(stmt.else_branch, ast.IfStmt):
                self._check_if(stmt.else_branch)
            else:
                self._check_block(stmt.else_branch)
        return UNIT

    def _check_while(self, stmt: ast.WhileStmt) -> Type:
        if stmt.condition is not None:
            ct = self._type_expr(stmt.condition)
            self._require_bool(ct, stmt.condition.loc, "'while' condition")
        self._loop_depth += 1
        if stmt.body is not None:
            self._check_block(stmt.body)
        self._loop_depth -= 1
        return UNIT

    def _check_for(self, stmt: ast.ForStmt) -> Type:
        elem_type: Type = UNKNOWN
        if stmt.iterable is not None:
            it = self._type_expr(stmt.iterable)
            elem_type = self._iter_element(it, stmt.iterable.loc)
        self.table.push_scope(ScopeKind.LOOP, name=stmt.variable)
        self.table.define(
            stmt.variable,
            SymbolKind.VARIABLE,
            type=elem_type,
            loc=stmt.loc,
            mutable=False,
        )
        self._loop_depth += 1
        if stmt.body is not None:
            self._check_block(stmt.body, new_scope=False)
        self._loop_depth -= 1
        self.table.pop_scope()
        return UNIT

    def _iter_element(self, t: Type, loc: Optional[SourceLocation]) -> Type:
        if isinstance(t, ListType):
            return t.element
        if isinstance(t, SetType):
            return t.element
        if isinstance(t, MapType):
            return t.key
        if isinstance(t, PrimitiveType) and t.name == "String":
            return PrimitiveType("Char")
        if _is_soft(t):
            return UNKNOWN
        self._error(
            CODE_TYPE_MISMATCH,
            f"cannot iterate over value of type {self._type_name(t)}",
            loc,
            "only List<T>, Set<T>, Map<K, V> and String are iterable",
        )
        return UNKNOWN

    def _check_return(self, stmt: ast.ReturnStmt) -> Type:
        expected = self._return_type
        if stmt.value is None:
            if not isinstance(expected, (AnyType, UnknownType)) and expected != UNIT:
                self._error(
                    CODE_TYPE_MISMATCH,
                    f"missing return value: function returns {self._type_name(expected)}",
                    stmt.loc,
                    "return a value of the declared type",
                )
            return NEVER
        vt = self._type_expr(stmt.value)
        self._check_assignable(
            vt, expected, stmt.value.loc, "return value", source_expr=stmt.value
        )
        return NEVER

    # ------------------------------------------------------------------
    # Expressions
    # ------------------------------------------------------------------
    def _type_expr(self, expr: Optional[ast.Expr], permissive: bool = False) -> Type:
        if expr is None:
            return UNIT
        saved = self._permissive
        self._permissive = self._permissive or permissive
        self._expr_depth += 1
        try:
            if self._expr_depth > _MAX_EXPR_DEPTH:
                self._error(
                    CODE_INVALID_EXPR,
                    "expression is too deeply nested to analyse",
                    getattr(expr, "loc", None),
                    "split the expression into smaller steps",
                )
                return UNKNOWN
            return self._type_expr_inner(expr)
        finally:
            self._expr_depth -= 1
            self._permissive = saved

    def _type_expr_inner(self, expr: ast.Expr) -> Type:
        if isinstance(expr, ast.IntLiteral):
            return PrimitiveType("Int")
        if isinstance(expr, ast.FloatLiteral):
            return PrimitiveType("Float")
        if isinstance(expr, ast.StringLiteral):
            return PrimitiveType("String")
        if isinstance(expr, ast.CharLiteral):
            return PrimitiveType("Char")
        if isinstance(expr, ast.BoolLiteral):
            return PrimitiveType("Bool")
        if isinstance(expr, ast.NullLiteral):
            return OptionType(NEVER)
        if isinstance(expr, ast.Identifier):
            return self._type_identifier(expr)
        if isinstance(expr, ast.BinaryOp):
            return self._type_binary(expr)
        if isinstance(expr, ast.UnaryOp):
            return self._type_unary(expr)
        if isinstance(expr, ast.CallExpr):
            return self._type_call(expr)
        if isinstance(expr, ast.MemberExpr):
            return self._type_member(expr)
        if isinstance(expr, ast.IndexExpr):
            return self._type_index(expr)
        if isinstance(expr, ast.ListLiteral):
            return self._type_list(expr)
        if isinstance(expr, ast.StructLiteral):
            return self._type_struct_literal(expr)
        if isinstance(expr, ast.AwaitExpr):
            return self._type_await(expr)
        if isinstance(expr, ast.AiExpr):
            return self._type_ai_expr(expr)
        return UNKNOWN

    def _type_identifier(self, expr: ast.Identifier) -> Type:
        sym = self.table.lookup(expr.name)
        if sym is None:
            enum_variant = self._enum_of_variant(expr.name)
            if enum_variant is not None:
                return enum_variant
            if self._permissive:
                return UNKNOWN
            self._error(
                CODE_UNKNOWN_NAME,
                f"unknown name '{expr.name}'",
                expr.loc,
                self._suggest_name(expr.name),
            )
            return UNKNOWN
        sym.mark_used()
        if sym.type is not None:
            return sym.type
        if sym.kind in (SymbolKind.TYPE, SymbolKind.ENUM):
            return self.types.get(expr.name, UNKNOWN)
        return UNKNOWN

    def _enum_of_variant(self, name: str) -> Optional[Type]:
        """Return the enum type owning the bare variant ``name`` (if any)."""
        candidates = self.variant_index.get(name)
        if not candidates:
            return None
        return self.types.get(candidates[0][0])

    def _type_binary(self, expr: ast.BinaryOp) -> Type:
        lt = self._type_expr(expr.left)
        rt = self._type_expr(expr.right)
        op = expr.op
        loc = expr.loc

        if op in ("&&", "||"):
            self._require_bool(lt, expr.left.loc if expr.left else loc, f"'{op}' operand")
            self._require_bool(rt, expr.right.loc if expr.right else loc, f"'{op}' operand")
            return PrimitiveType("Bool")

        if op in ("==", "!="):
            if (
                isinstance(lt, PrimitiveType)
                and isinstance(rt, PrimitiveType)
                and not _is_soft(lt)
                and not _is_soft(rt)
                and lt.name != rt.name
                and not _both_numeric(lt, rt)
            ):
                self._error(
                    CODE_TYPE_MISMATCH,
                    f"cannot compare {self._type_name(lt)} with "
                    f"{self._type_name(rt)} using '{op}'",
                    loc,
                    "both operands must have the same type",
                )
            return PrimitiveType("Bool")

        if op in ("<", "<=", ">", ">="):
            if _both_numeric(lt, rt) or _both_string(lt, rt) or _is_soft(lt) or _is_soft(rt):
                return PrimitiveType("Bool")
            if lt == rt and isinstance(lt, (PrimitiveType,)):
                return PrimitiveType("Bool")
            self._error(
                CODE_TYPE_MISMATCH,
                f"cannot compare {self._type_name(lt)} with {self._type_name(rt)} using '{op}'",
                loc,
                "both operands must be numbers or both strings",
            )
            return PrimitiveType("Bool")

        if op == "+" and _both_string(lt, rt):
            return PrimitiveType("String")

        if op in ("+", "-", "*", "/", "%", "**"):
            return self._arith_result(op, lt, rt, loc)

        if op in ("&", "|", "^", "<<", ">>"):
            if _is_soft(lt) or _is_soft(rt) or _is_int_like(lt) and _is_int_like(rt):
                return PrimitiveType("Int")
            self._error(
                CODE_TYPE_MISMATCH,
                f"bitwise '{op}' requires Int operands, found "
                f"{self._type_name(lt)} and {self._type_name(rt)}",
                loc,
            )
            return PrimitiveType("Int")

        return UNKNOWN

    def _arith_result(self, op: str, lt: Type, rt: Type, loc) -> Type:
        if _is_soft(lt) or _is_soft(rt):
            return PrimitiveType("Float") if (op == "/") else UNKNOWN
        if not _is_numeric(lt) or not _is_numeric(rt):
            self._error(
                CODE_TYPE_MISMATCH,
                f"operator '{op}' requires numeric operands, found "
                f"{self._type_name(lt)} and {self._type_name(rt)}",
                loc,
                "use arithmetic only on Int, Float or Byte values",
            )
            return UNKNOWN
        if op == "/":
            return PrimitiveType("Float")
        return PrimitiveType(_numeric_join(lt, rt))

    def _compound_result(self, op: str, lt: Type, rt: Type, loc) -> Type:
        if _is_soft(lt):
            return lt
        return self._arith_result(op, lt, rt, loc)

    def _type_unary(self, expr: ast.UnaryOp) -> Type:
        ot = self._type_expr(expr.operand)
        if expr.op == "!":
            self._require_bool(ot, expr.operand.loc if expr.operand else expr.loc, "'!' operand")
            return PrimitiveType("Bool")
        if expr.op in ("-", "+"):
            if _is_soft(ot) or _is_numeric(ot):
                return ot if _is_numeric(ot) else PrimitiveType("Int")
            self._error(
                CODE_TYPE_MISMATCH,
                f"unary '{expr.op}' requires a numeric operand, found "
                f"{self._type_name(ot)}",
                expr.loc,
            )
            return UNKNOWN
        if expr.op == "~":
            return PrimitiveType("Int")
        return UNKNOWN

    def _type_member(self, expr: ast.MemberExpr) -> Type:
        obj_t = self._type_expr(expr.obj)
        own_field = isinstance(obj_t, StructType) and obj_t.field_type(expr.name) is not None
        if expr.name.startswith("__") or (expr.name in _BLOCKED_MEMBERS and not own_field):
            self._error(
                CODE_MEMBER_ACCESS,
                f"access to member '{expr.name}' is not allowed",
                expr.loc,
                "dunder, frame and format-string members expose the host runtime",
            )
            return UNKNOWN
        if expr.name.startswith("_") and not (
            isinstance(obj_t, StructType) and obj_t.field_type(expr.name) is not None
        ):
            self._error(
                CODE_MEMBER_ACCESS,
                f"access to private member '{expr.name}' is not allowed",
                expr.loc,
                "names starting with '_' are reserved for the runtime",
            )
            return UNKNOWN
        if isinstance(obj_t, StructType):
            ftype = obj_t.field_type(expr.name)
            if ftype is None:
                # A method provided by an `impl` block is accessed the same way
                # as a field; resolve it to its function type instead of
                # reporting a missing field.
                method = self.type_methods.get(obj_t.name, {}).get(expr.name)
                if method is not None:
                    return method
                self._error(
                    CODE_UNKNOWN_FIELD,
                    f"type '{obj_t.name}' has no field '{expr.name}'",
                    expr.loc,
                    self._suggest_field(obj_t, expr.name),
                )
                return UNKNOWN
            if expr.name in obj_t.secret_fields and self.options.report_secret_access:
                self._warn(
                    CODE_W_SECRET,
                    f"access to secret field '{expr.name}' of '{obj_t.name}'",
                    expr.loc,
                    "secret fields should only be read inside a permitted capability scope",
                )
            return ftype
        if _is_soft(obj_t):
            return UNKNOWN
        # member access on non-structs (methods, module qualifiers) is dynamic
        return ANY

    def _type_index(self, expr: ast.IndexExpr) -> Type:
        obj_t = self._type_expr(expr.obj)
        if expr.index is not None:
            self._type_expr(expr.index)
        if isinstance(obj_t, ListType):
            return obj_t.element
        if isinstance(obj_t, SetType):
            return obj_t.element
        if isinstance(obj_t, MapType):
            return obj_t.value
        if isinstance(obj_t, TupleType) and isinstance(expr.index, ast.IntLiteral):
            idx = expr.index.value
            if 0 <= idx < len(obj_t.elements):
                return obj_t.elements[idx]
            self._error(
                CODE_TYPE_MISMATCH,
                f"tuple index {idx} out of range (tuple has {len(obj_t.elements)} elements)",
                expr.loc,
            )
            return UNKNOWN
        if isinstance(obj_t, PrimitiveType) and obj_t.name == "String":
            return PrimitiveType("Char")
        if _is_soft(obj_t):
            return UNKNOWN
        self._error(
            CODE_TYPE_MISMATCH,
            f"type {self._type_name(obj_t)} is not indexable",
            expr.loc,
            "only List, Set, Map, tuple and String support indexing",
        )
        return UNKNOWN

    def _type_list(self, expr: ast.ListLiteral) -> Type:
        if not expr.elements:
            return ListType(UNKNOWN)
        elem = self._type_expr(expr.elements[0])
        for e in expr.elements[1:]:
            et = self._type_expr(e)
            joined = common_supertype(elem, et)
            if joined is None:
                self._error(
                    CODE_TYPE_MISMATCH,
                    f"list elements have incompatible types "
                    f"{self._type_name(elem)} and {self._type_name(et)}",
                    e.loc,
                )
                return ListType(UNKNOWN)
            elem = joined
        return ListType(elem)

    def _type_struct_literal(self, expr: ast.StructLiteral) -> Type:
        base = self.types.get(expr.type_name)
        if base is None:
            self._error(
                CODE_UNKNOWN_TYPE,
                f"unknown type '{expr.type_name}' in struct literal",
                expr.loc,
                "declare the type before constructing it",
            )
            return UNKNOWN
        if isinstance(base, EnumType):
            self._error(
                CODE_INVALID_EXPR,
                f"'{expr.type_name}' is an enum; construct it with "
                f"'{expr.type_name}::Variant(...)'",
                expr.loc,
            )
            return base
        if not isinstance(base, StructType):
            return UNKNOWN

        provided: Dict[str, ast.FieldInit] = {}
        for fi in expr.fields:
            if fi.name in provided:
                self._error(
                    CODE_DUPLICATE_FIELD_INIT,
                    f"field '{fi.name}' initialized more than once",
                    fi.loc,
                )
                continue
            provided[fi.name] = fi

        field_map = base.field_map()
        for fi in expr.fields:
            ftype = field_map.get(fi.name)
            if ftype is None:
                self._error(
                    CODE_UNKNOWN_FIELD,
                    f"type '{base.name}' has no field '{fi.name}'",
                    fi.loc,
                    self._suggest_field(base, fi.name),
                )
                continue
            vt = self._type_expr(fi.value) if fi.value is not None else UNKNOWN
            self._check_assignable(
                vt, ftype, fi.loc, f"field '{fi.name}'", source_expr=fi.value
            )

        # missing required fields (those without a default) are an error
        for fname, _ftype in base.fields:
            if fname in provided:
                continue
            if not self._struct_field_has_default(base.name, fname):
                self._error(
                    CODE_MISSING_FIELD,
                    f"missing field '{fname}' in literal for '{base.name}'",
                    expr.loc,
                    f"add '{fname}: <value>' to the struct literal",
                )
        return base

    def _struct_field_has_default(self, type_name: str, field_name: str) -> bool:
        decl = self._lookup_struct_decl(type_name)
        if decl is None:
            return True
        for f in decl.fields:
            if f.name == field_name:
                return f.default is not None
        return True

    def _lookup_struct_decl(self, type_name: str) -> Optional[ast.StructDecl]:
        if self.program_ref is None:
            return None
        for d in self.program_ref.declarations:
            if isinstance(d, ast.StructDecl) and d.name == type_name:
                return d
        return None

    def _type_await(self, expr: ast.AwaitExpr) -> Type:
        ot = self._type_expr(expr.operand)
        if isinstance(ot, GenericInstance) and ot.name == "Future":
            return ot.args[0]
        if _is_soft(ot):
            return UNKNOWN
        self._error(
            CODE_INVALID_EXPR,
            f"'await' expects a Future value, found {self._type_name(ot)}",
            expr.loc,
            "await may only be applied to the result of an async function",
        )
        return UNKNOWN

    def _type_ai_expr(self, expr: ast.AiExpr) -> Type:
        if expr.prompt is not None:
            self._type_expr(expr.prompt, permissive=True)
        if expr.body is not None:
            self._check_block(expr.body)
        # Model output is dynamically typed at the boundary.
        return ANY

    def _type_call(self, expr: ast.CallExpr) -> Type:
        args = [self._type_expr(a) for a in expr.args]
        callee = expr.callee

        if isinstance(callee, ast.Identifier):
            name = callee.name
            local_sym = self.table.lookup(name)
            if local_sym is not None and local_sym.kind in (
                SymbolKind.VARIABLE,
                SymbolKind.PARAMETER,
            ):
                # A local value shadows any function / builtin of that name.
                local_sym.mark_used()
                if isinstance(local_sym.type, FunctionType):
                    self._check_call_args(name, local_sym.type, expr, args)
                    return local_sym.type.returns
                if _is_soft(local_sym.type):
                    return ANY
                self._error(
                    CODE_INVALID_EXPR,
                    f"'{name}' is not callable (it is a {local_sym.kind.value})",
                    callee.loc,
                    "a local variable shadows the function of the same name",
                )
                return UNKNOWN
            # user function?
            sig = self.functions.get(name)
            if sig is not None:
                self._mark_used_name(name)
                self._check_call_args(name, sig, expr, args)
                return _future(sig.returns) if sig.is_async else sig.returns
            # builtin?
            if name in BUILTIN_FUNCTIONS:
                sig = BUILTIN_FUNCTIONS[name]
                self._check_call_args(name, sig, expr, args)
                return sig.returns
            # enum variant constructor, e.g. Deposit(50.0)?
            if name in self.variant_index:
                return self._type_variant_call(name, expr, args)
            # a value of function type?
            sym = self.table.lookup(name)
            if sym is not None:
                sym.mark_used()
                if isinstance(sym.type, FunctionType):
                    self._check_call_args(name, sym.type, expr, args)
                    return sym.type.returns
                if _is_soft(sym.type):
                    return ANY
                self._error(
                    CODE_INVALID_EXPR,
                    f"'{name}' is not callable (it is a {sym.kind.value})",
                    callee.loc,
                )
                return UNKNOWN
            if self.options.strict_unknown_functions or self.options.semantic_security_strict:
                self._error(
                    CODE_UNKNOWN_NAME,
                    f"unknown function '{name}'",
                    callee.loc,
                    "declare it before calling",
                )
            else:
                self._warn(
                    CODE_W_UNKNOWN_FUNC,
                    f"unknown function '{name}'; assuming it returns Any",
                    callee.loc,
                    "declare the function or import it",
                )
            return ANY

        # method / complex callee: dynamic
        self._type_expr(callee)
        return ANY

    def _type_variant_call(self, name: str, expr: ast.CallExpr, args: List[Type]) -> Type:
        candidates = self.variant_index[name]
        for enum_name, payload in candidates:
            if len(payload) == len(args):
                for i, (pt, at) in enumerate(zip(payload, args)):
                    self._check_assignable(
                        at, pt, expr.args[i].loc, f"variant '{name}' argument {i + 1}",
                        source_expr=expr.args[i],
                    )
                base = self.types.get(enum_name)
                return base if isinstance(base, EnumType) else UNKNOWN
        # arity mismatch: report against the first candidate
        enum_name, payload = candidates[0]
        self._error(
            CODE_ARITY,
            f"variant '{name}' expects {len(payload)} argument(s), got {len(args)}",
            expr.loc,
        )
        base = self.types.get(enum_name)
        return base if isinstance(base, EnumType) else UNKNOWN

    def _check_call_args(
        self, name: str, sig: FunctionType, expr: ast.CallExpr, args: List[Type]
    ) -> None:
        # Only genuinely variadic builtins (print/println) accept extra
        # arguments; every other builtin checks its full arity.
        if (
            name in BUILTIN_FUNCTIONS
            and sig is BUILTIN_FUNCTIONS[name]
            and name in _VARIADIC_BUILTINS
            and args
        ):
            self._check_assignable(
                args[0], sig.params[0], expr.loc, f"argument to '{name}'",
                source_expr=expr.args[0],
            )
            return
        if (
            name in BUILTIN_FUNCTIONS
            and sig is BUILTIN_FUNCTIONS[name]
            and name in _OPTIONAL_ARG_BUILTINS
            and len(sig.params) <= len(args) <= _OPTIONAL_ARG_BUILTINS[name]
        ):
            for i, (arg_t, param_t) in enumerate(zip(args, sig.params)):
                self._check_assignable(
                    arg_t, param_t, expr.args[i].loc,
                    f"argument {i + 1} to '{name}'", source_expr=expr.args[i],
                )
            return
        min_args = self._min_args.get(name, len(sig.params))
        if sig is not BUILTIN_FUNCTIONS.get(name) and min_args <= len(args) <= len(sig.params):
            pass  # omitted trailing arguments use their declared defaults
        elif len(args) != len(sig.params):
            expected = (
                f"{min_args} to {len(sig.params)}"
                if min_args != len(sig.params)
                else f"{len(sig.params)}"
            )
            self._error(
                CODE_ARITY,
                f"'{name}' expects {expected} argument(s), got {len(args)}",
                expr.loc,
                "check the call site against the function's parameters",
            )
            return
        bindings: Dict[str, Type] = {}
        for i, (arg_t, param_t) in enumerate(zip(args, sig.params)):
            if not self._bind_type_params(
                name, param_t, arg_t, bindings, expr.args[i].loc
            ):
                continue
            self._check_assignable(
                arg_t, param_t, expr.args[i].loc, f"argument {i + 1} to '{name}'",
                source_expr=expr.args[i],
            )

    def _bind_type_params(
        self, fname: str, param_t: Type, arg_t: Type, bindings: Dict[str, Type], loc
    ) -> bool:
        """Unify generic parameters across one call; report disagreements.

        Returns ``False`` when an error was reported (skip the plain check).
        """
        if isinstance(param_t, TypeVar):
            if _is_soft(arg_t):
                return True
            bound = bindings.get(param_t.name)
            if bound is None:
                bindings[param_t.name] = arg_t
                return True
            joined = common_supertype(bound, arg_t)
            if joined is None:
                self._error(
                    CODE_TYPE_MISMATCH,
                    f"type parameter '{param_t.name}' of '{fname}' is bound to "
                    f"{self._type_name(bound)} but this argument is "
                    f"{self._type_name(arg_t)}",
                    loc,
                    "all arguments sharing a type parameter must have the same type",
                )
                return False
            bindings[param_t.name] = joined
            return True
        if (
            isinstance(param_t, GenericInstance)
            and isinstance(arg_t, GenericInstance)
            and param_t.name == arg_t.name
            and len(param_t.args) == len(arg_t.args)
        ):
            ok = True
            for pa, aa in zip(param_t.args, arg_t.args):
                ok = self._bind_type_params(fname, pa, aa, bindings, loc) and ok
            return ok
        return True

    def _mark_used_name(self, name: str) -> None:
        sym = self.table.lookup(name)
        if sym is not None:
            sym.mark_used()

    # ------------------------------------------------------------------
    # Assignability helper (with literal narrowing)
    # ------------------------------------------------------------------
    def _check_assignable(
        self,
        source: Type,
        target: Type,
        loc: Optional[SourceLocation],
        context: str,
        source_expr: Optional[ast.Expr] = None,
    ) -> None:
        if isinstance(source, UnknownType) or isinstance(target, UnknownType):
            return
        if isinstance(source, (AnyType, NeverType)):
            return
        if isinstance(target, (AnyType, TypeVar)):
            return
        if assignable(source, target):
            return
        if source_expr is not None and self._literal_assignable(source_expr, target):
            return
        self._error(
            CODE_TYPE_MISMATCH,
            f"type mismatch in {context}: expected {self._type_name(target)}, "
            f"found {self._type_name(source)}",
            loc,
            self._mismatch_hint(source, target),
        )

    def _literal_assignable(
        self, expr: Optional[ast.Expr], target: Type
    ) -> bool:
        """Allow *in-range* literal narrowing, e.g. ``pin: 7`` for a Byte field.

        An integer literal whose value fits the target's range is assignable to
        ``Byte``/``Char``; any integer literal widens to ``Int``/``Float``.
        """
        if not isinstance(target, PrimitiveType) or target.name not in (
            "Byte",
            "Char",
            "Int",
            "Float",
        ):
            return False
        if isinstance(expr, ast.IntLiteral):
            v = expr.value
            if target.name == "Byte":
                return 0 <= v <= 255
            if target.name == "Char":
                return 0 <= v <= 0x10FFFF
            return True  # Int / Float accept any integer literal
        if isinstance(expr, ast.FloatLiteral):
            return target.name == "Float"
        return False

    def _mismatch_hint(self, source: Type, target: Type) -> Optional[str]:
        if isinstance(target, PrimitiveType) and target.name == "Float" and _is_int_like(source):
            return "Int values must be widened explicitly, e.g. 'float_value'"
        if isinstance(target, PrimitiveType) and target.name == "String":
            return "convert the value with 'str(...)' if a string is intended"
        if isinstance(target, PrimitiveType) and target.name == "Bool":
            return "Bool is required; use a comparison or '!= 0' for numeric truth"
        return f"provide a value of type {self._type_name(target)}"

    # ------------------------------------------------------------------
    # Enum exhaustiveness on if-chains
    # ------------------------------------------------------------------
    def _check_enum_match_chains(self, stmts: Sequence[object]) -> None:
        # Group sibling `if` chains that test the same enum expression, so a
        # realistic match written as consecutive `if c == A { }` statements is
        # checked for exhaustiveness as a whole.
        groups: Dict[str, Dict[str, object]] = {}
        order: List[str] = []
        for stmt in stmts:
            if not isinstance(stmt, ast.IfStmt):
                continue
            test = self._enum_variant_test(stmt.condition)
            if test is None:
                continue
            et, vname, subject = test
            key = f"{et.name}:{subject}"
            if key not in groups:
                groups[key] = {"enum": et, "covered": set(), "has_else": False, "loc": stmt.loc}
                order.append(key)
            groups[key]["covered"].add(vname)  # type: ignore[union-attr]
            if stmt.else_branch is not None:
                groups[key]["has_else"] = True

        for key in order:
            info = groups[key]
            enum_type: EnumType = info["enum"]  # type: ignore[assignment]
            covered: Set[str] = info["covered"]  # type: ignore[assignment]
            if len(covered) < 2:
                continue
            missing = [v for v in enum_type.variant_names() if v not in covered]
            if missing and not info["has_else"]:
                self._warn(
                    CODE_W_NONEXHAUSTIVE,
                    f"non-exhaustive match on '{enum_type.name}': "
                    f"missing variant(s) {', '.join(missing)}",
                    info["loc"],  # type: ignore[arg-type]
                    "add the missing branches or a final 'else' catch-all",
                )

    def _collect_enum_chain(
        self, stmt: ast.IfStmt
    ) -> Optional[Tuple[EnumType, Set[str], bool]]:
        covered: Set[str] = set()
        enum_type: Optional[EnumType] = None
        node: object = stmt
        while isinstance(node, ast.IfStmt):
            test = self._enum_variant_test(node.condition)
            if test is None:
                break
            et, vname, _subject = test
            if enum_type is None:
                enum_type = et
            elif et.name != enum_type.name:
                break
            covered.add(vname)
            node = node.else_branch
        if enum_type is None or len(covered) < 2:
            return None
        has_else = node is not None  # a trailing block/if acts as a catch-all
        return enum_type, covered, has_else

    def _enum_variant_test(self, cond: Optional[ast.Expr]) -> Optional[Tuple[EnumType, str, str]]:
        """Recognise ``<subject> == <Variant>`` tests on an enum value."""
        if not isinstance(cond, ast.BinaryOp) or cond.op != "==":
            return None
        left, right = cond.left, cond.right
        for a, b in ((left, right), (right, left)):
            if not isinstance(a, ast.Identifier) or not isinstance(b, ast.Identifier):
                continue
            enum_type = self._enum_type_of_name(a.name)
            if enum_type is None:
                continue
            if b.name in enum_type.variant_names():
                return enum_type, b.name, a.name
        return None

    def _enum_type_of_name(self, name: str) -> Optional[EnumType]:
        sym = self.table.lookup(name)
        if sym is None:
            return None
        t = sym.type
        return t if isinstance(t, EnumType) else None

    # ------------------------------------------------------------------
    # Exhaustiveness public API (used by tests & future match support)
    # ------------------------------------------------------------------
    def check_exhaustiveness(
        self,
        enum: EnumType,
        patterns: Sequence[Pattern],
        loc: Optional[SourceLocation] = None,
    ) -> ExhaustivenessResult:
        result = check_exhaustive(enum, patterns)
        if not result.ok:
            self._warn(
                CODE_W_NONEXHAUSTIVE,
                f"non-exhaustive match on '{enum.name}': "
                f"missing variant(s) {', '.join(result.missing)}",
                loc,
                "add the missing branches or a wildcard '_' pattern",
            )
        for name in result.redundant:
            self._warn(
                "W3112",
                f"redundant pattern '{name}': already matched",
                loc,
            )
        return result

    # ------------------------------------------------------------------
    # Unused reporting
    # ------------------------------------------------------------------
    def _report_unused(self) -> None:
        for sym in self.table.unused_symbols():
            if sym.kind is SymbolKind.IMPORT:
                continue
            self._emit(
                CODE_W_UNUSED,
                f"unused variable '{sym.name}'",
                sym.declared_at,
                "remove it, or prefix the name with '_' to silence this warning",
                self.options.unused_variable_severity,
            )

    def _report_unused_imports(self) -> None:
        for name, _imp in list(self.table.module_scope.imports.items()):
            sym = self.table.module_scope.lookup_local(name)
            if sym is not None and not sym.used:
                self._emit(
                    CODE_N_UNUSED_IMPORT,
                    f"imported name '{name}' is never used",
                    sym.declared_at,
                    "remove the import or use the symbol",
                    self.options.unused_import_severity,
                )

    # ------------------------------------------------------------------
    # Name suggestions
    # ------------------------------------------------------------------
    def _suggest_name(self, name: str) -> str:
        candidates = [
            s.name for s in self.table.all_symbols() if s.name != name
        ]
        best = _closest(name, candidates)
        if best:
            return f"did you mean '{best}'?"
        return "declare it before use, or check the spelling"

    def _suggest_field(self, struct: StructType, name: str) -> str:
        candidates = [fname for fname, _ in struct.fields]
        best = _closest(name, candidates)
        if best:
            return f"did you mean '{best}'?"
        if candidates:
            return f"available fields are: {', '.join(candidates)}"
        return "this type has no fields"

    # ------------------------------------------------------------------
    # program reference (for default lookups)
    # ------------------------------------------------------------------
    program_ref: Optional[ast.Program] = None

    def set_program(self, program: ast.Program) -> None:
        self.program_ref = program


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _future(inner: Type) -> GenericInstance:
    from .types import FutureType

    return FutureType(inner)


def _is_numeric(t: Type) -> bool:
    return isinstance(t, PrimitiveType) and t.name in ("Int", "Float", "Byte")


def _is_int_like(t: Type) -> bool:
    return isinstance(t, PrimitiveType) and t.name in ("Int", "Byte")


def _both_numeric(a: Type, b: Type) -> bool:
    return _is_numeric(a) and _is_numeric(b)


def _both_string(a: Type, b: Type) -> bool:
    return (
        isinstance(a, PrimitiveType)
        and a.name == "String"
        and isinstance(b, PrimitiveType)
        and b.name == "String"
    )


def _is_soft(t: Type) -> bool:
    """Soft types are compatible with everything (Any/Unknown/Never/TypeVar)."""
    return isinstance(t, (AnyType, UnknownType, NeverType, TypeVar))


def _numeric_join(a: Type, b: Type) -> str:
    assert isinstance(a, PrimitiveType) and isinstance(b, PrimitiveType)
    names = {a.name, b.name}
    if "Float" in names:
        return "Float"
    if "Int" in names:
        return "Int"
    return "Byte"


def _closest(name: str, candidates: Sequence[str]) -> Optional[str]:
    """Return the closest candidate by edit distance, if close enough."""
    best: Optional[str] = None
    best_dist = max(2, len(name) // 2)
    for cand in candidates:
        d = _levenshtein(name, cand)
        if d < best_dist or (d == best_dist and best is None):
            if d <= max(2, len(name) // 2):
                best = cand
                best_dist = d
    return best


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


# ---------------------------------------------------------------------------
# Convenience API
# ---------------------------------------------------------------------------
@dataclass
class ModuleInterface:
    """A resolved view of another module's public surface (for imports)."""

    name: str
    types: Dict[str, Type] = field(default_factory=dict)
    functions: Dict[str, FunctionType] = field(default_factory=dict)
    values: Dict[str, Type] = field(default_factory=dict)


def is_async_unit(ret: Type) -> bool:
    """True for return types that need no ``return`` (Unit / Never / Any)."""
    try:
        return ret.display() in ("Unit", "Never", "Any", "Unknown")
    except Exception:  # pragma: no cover - defensive
        return True


def analyze(
    source_or_program,
    filename: Optional[str] = None,
    options: Optional[SemanticOptions] = None,
) -> AnalysisResult:
    """Parse (if given source) and semantically analyze a Happy program.

    ``source_or_program`` may be a ``str`` of Happy source or an already-parsed
    :class:`~happy.compiler.ast.Program`.
    """
    from .parser import parse

    if isinstance(source_or_program, ast.Program):
        program = source_or_program
        source = None
    else:
        source = source_or_program
        program = parse(source, filename=filename)

    analyzer = SemanticAnalyzer(
        source=source, filename=filename, options=options
    )
    analyzer.set_program(program)
    return analyzer.analyze(program)
