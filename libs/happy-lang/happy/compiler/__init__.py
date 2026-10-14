"""Happy language compiler (bootstrap implementation in Python).

This package implements the Happy (``.hpy``) toolchain front end:

* :mod:`happy.compiler.lexer`    — hand-written scanner with exact positions.
* :mod:`happy.compiler.parser`   — deterministic recursive-descent parser.
* :mod:`happy.compiler.ast`      — AST node definitions.
* :mod:`happy.compiler.types`    — the static type system.
* :mod:`happy.compiler.symbol_table` — lexical scoping and bindings.
* :mod:`happy.compiler.semantic` — semantic analysis, type checking and
  contract / permission / capability / effect validation.

Public API::

    from happy.compiler import tokenize, parse, analyze

    tokens = tokenize(source)
    program = parse(source)
    result = analyze(source)          # -> AnalysisResult
    if not result.ok:
        print(result.format())
"""

from .errors import HappyError, LexerError, ParseError, SourceLocation
from .lexer import Lexer, Token, TokenKind, tokenize
from .parser import Parser, parse
from . import ast
from . import types
from . import symbol_table
from . import semantic
from . import ir
from . import contracts
from . import permissions
from . import effects
from . import modules
from . import optimizer
from .types import Type, PrimitiveType, FunctionType, StructType, EnumType
from .symbol_table import (
    Scope,
    ScopeKind,
    Symbol,
    SymbolKind,
    SymbolTable,
)
from .semantic import (
    AnalysisResult,
    Diagnostic,
    ExhaustivenessResult,
    ModuleInterface,
    Pattern,
    SemanticAnalyzer,
    SemanticOptions,
    Severity,
    analyze,
    check_exhaustive,
)
from .ir import (
    IRModule,
    IRBuilder,
    IRLoweringError,
    canonical_effect,
    canonical_effects,
    lower,
)
from .contracts import (
    CheckedContract,
    ContractEngine,
    ContractInfo,
    ContractOptions,
    ContractReport,
    check_contracts,
)
from .permissions import (
    CapabilityInfo,
    EnforcementPoint,
    PermissionEngine,
    PermissionInfo,
    PermissionOptions,
    PermissionReport,
    RuleCheck,
    verify_permissions,
    check_permissions,
)
from .effects import (
    EffectKind,
    EffectOptions,
    EffectReport,
    EffectTracker,
    FunctionEffects,
    track_effects,
    check_effects,
)
from .modules import (
    LoadedModule,
    LoadedProject,
    ModuleLoader,
    ModuleResolutionError,
)
from .optimizer import OptimizationReport, Optimizer, optimize

__all__ = [
    # errors
    "HappyError",
    "LexerError",
    "ParseError",
    "SourceLocation",
    # front end
    "Lexer",
    "Token",
    "TokenKind",
    "tokenize",
    "Parser",
    "parse",
    "ast",
    # type system
    "types",
    "Type",
    "PrimitiveType",
    "FunctionType",
    "StructType",
    "EnumType",
    # scopes
    "symbol_table",
    "SymbolTable",
    "Scope",
    "ScopeKind",
    "Symbol",
    "SymbolKind",
    # semantics
    "semantic",
    "SemanticAnalyzer",
    "SemanticOptions",
    "AnalysisResult",
    "Diagnostic",
    "Severity",
    "Pattern",
    "ExhaustivenessResult",
    "ModuleInterface",
    "analyze",
    "check_exhaustive",
    # Step 3 — IR / contracts / permissions / effects
    "ir",
    "IRModule",
    "IRBuilder",
    "IRLoweringError",
    "lower",
    "canonical_effect",
    "canonical_effects",
    "contracts",
    "ContractEngine",
    "ContractOptions",
    "ContractInfo",
    "ContractReport",
    "CheckedContract",
    "check_contracts",
    "permissions",
    "PermissionEngine",
    "PermissionOptions",
    "PermissionReport",
    "PermissionInfo",
    "CapabilityInfo",
    "RuleCheck",
    "EnforcementPoint",
    "verify_permissions",
    "check_permissions",
    "effects",
    "EffectTracker",
    "EffectOptions",
    "EffectReport",
    "EffectKind",
    "FunctionEffects",
    "track_effects",
    "check_effects",
    "modules",
    "ModuleLoader",
    "LoadedModule",
    "LoadedProject",
    "ModuleResolutionError",
    "optimizer",
    "Optimizer",
    "OptimizationReport",
    "optimize",
]

# The compiler front end tracks the top-level Happy toolchain version.
__version__ = "1.0.0"
