"""Cross-file module resolution for Happy (Step 7).

Happy programs are organised into modules with ``module a.b`` headers and
``import a.b`` / ``import a.b { x, y }`` statements.  This module implements
the *module loader*: it walks a project's import graph starting from an entry
file, resolves each module to a ``.hpy`` file, orders them so that dependencies
come first, and derives a :class:`~happy.compiler.semantic.ModuleInterface` for
each one so the semantic analyzer can type-check cross-module references.

The backend then performs *whole-program* code generation: every module's
declarations are merged into one program in dependency order, so a name
imported from another module resolves exactly as if it were declared locally.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

from . import ast
from .errors import HappyError, SourceLocation
from .parser import parse
from .semantic import AnalysisResult, ModuleInterface, SemanticAnalyzer

#: Default file extension for Happy source modules.
MODULE_EXTENSION = ".hpy"

#: Environment variable with additional ``os.pathsep``-separated search paths.
SEARCH_PATH_ENV = "HAPPY_PATH"


class ModuleResolutionError(HappyError):
    """Raised when a module cannot be located or its graph is cyclic."""

    def __init__(self, message: str, location: Optional[SourceLocation] = None,
                 suggestion: Optional[str] = None) -> None:
        super().__init__(message=message, location=location, suggestion=suggestion)


@dataclass
class LoadedModule:
    """One resolved module: its name, source text and file path."""

    name: str
    path: str
    source: str
    program: ast.Program
    imports: List[str] = field(default_factory=list)

    @property
    def is_root(self) -> bool:
        return self.name == "__root__"


@dataclass
class LoadedProject:
    """A fully resolved module graph, ordered dependencies-first."""

    entry_path: str
    #: Modules in dependency order (dependencies before dependents).  The last
    #: entry is the program's entry module.
    modules: List[LoadedModule] = field(default_factory=list)
    interfaces: Dict[str, ModuleInterface] = field(default_factory=dict)
    #: Analysis result per module name (after type checking with interfaces).
    analyses: Dict[str, AnalysisResult] = field(default_factory=dict)
    #: Imported module names that could not be resolved to a project file
    #: (e.g. runtime / standard-library modules).
    unresolved: List[str] = field(default_factory=list)

    @property
    def entry(self) -> LoadedModule:
        return self.modules[-1]

    def merged_program(self) -> ast.Program:
        """Merge every module's declarations into a single program.

        Dependencies are appended first so a dependent module can reference
        anything it imported; the entry module's declarations come last and
        contribute the ``app`` entry point plus its own imports.
        """
        declarations: List[ast.Decl] = []
        for module in self.modules:
            for decl in module.program.declarations:
                if isinstance(decl, ast.ModuleDecl):
                    continue
                declarations.append(decl)
        entry = self.entry
        imports = list(entry.program.imports)
        return ast.Program(
            declarations=declarations,
            imports=imports,
            module=entry.program.module,
            loc=entry.program.loc,
        )


class ModuleLoader:
    """Resolves and loads a Happy project's module graph."""

    def __init__(self, search_paths: Optional[Sequence[str]] = None) -> None:
        self.search_paths: List[str] = list(search_paths or [])
        env = os.environ.get(SEARCH_PATH_ENV)
        if env:
            self.search_paths.extend(p for p in env.split(os.pathsep) if p)

    # -- path resolution ------------------------------------------------
    def _candidates(self, module_name: str, importer_dir: str) -> List[str]:
        """Candidate filesystem paths for ``module_name``, best first."""
        parts = module_name.split(".")
        rel = os.path.join(*parts) + MODULE_EXTENSION
        rel_pkg = os.path.join(*parts, "mod" + MODULE_EXTENSION)
        bases = [importer_dir] + list(self.search_paths)
        out: List[str] = []
        for base in bases:
            out.append(os.path.join(base, rel))
            out.append(os.path.join(base, rel_pkg))
        # Also allow the last path segment alone (e.g. `import utils`).
        for base in bases:
            out.append(os.path.join(base, parts[-1] + MODULE_EXTENSION))
        return out

    def resolve(self, module_name: str, importer_dir: str,
                location: Optional[SourceLocation] = None) -> str:
        for candidate in self._candidates(module_name, importer_dir):
            if os.path.isfile(candidate):
                return os.path.abspath(candidate)
        raise ModuleResolutionError(
            f"cannot resolve module '{module_name}'",
            location,
            f"looked for {module_name.replace('.', '/')}{MODULE_EXTENSION} "
            f"relative to {importer_dir} and HAPPY_PATH",
        )

    # -- loading --------------------------------------------------------
    def load(self, entry_path: str) -> LoadedProject:
        entry_path = os.path.abspath(entry_path)
        if not os.path.isfile(entry_path):
            raise ModuleResolutionError(f"no such file: {entry_path}")
        with open(entry_path, "r", encoding="utf-8") as fh:
            entry_source = fh.read()

        project = LoadedProject(entry_path=entry_path)
        visiting: List[str] = []
        visited: Dict[str, LoadedModule] = {}
        ordered: List[LoadedModule] = []

        def module_name_of(program: ast.Program, fallback: str) -> str:
            if program.module is not None and program.module.name:
                return program.module.name
            return fallback

        def visit(path: str, name_hint: str, importer_loc=None) -> LoadedModule:
            path = os.path.abspath(path)
            if path in visited:
                return visited[path]
            if path in visiting:
                cycle = " -> ".join(visiting + [path])
                raise ModuleResolutionError(
                    f"circular module dependency: {cycle}", importer_loc
                )
            visiting.append(path)
            with open(path, "r", encoding="utf-8") as fh:
                source = fh.read()
            program = parse(source, filename=path)
            name = module_name_of(program, name_hint)
            import_names: List[str] = []
            importer_dir = os.path.dirname(path)
            for imp in program.imports:
                if not imp.name:
                    continue
                import_names.append(imp.name)
                try:
                    dep_path = self.resolve(imp.name, importer_dir, imp.loc)
                except ModuleResolutionError:
                    # A std/built-in module that ships with the runtime rather
                    # than the project is left to the semantic layer, but it is
                    # recorded so callers can distinguish it from a real one.
                    if imp.name not in project.unresolved:
                        project.unresolved.append(imp.name)
                    continue
                visit(dep_path, imp.name, imp.loc)
            visiting.pop()
            module = LoadedModule(
                name=name, path=path, source=source, program=program,
                imports=import_names,
            )
            visited[path] = module
            ordered.append(module)
            return module

        root_name = os.path.splitext(os.path.basename(entry_path))[0]
        visit(entry_path, root_name)
        project.modules = ordered
        return project

    # -- interfaces & analysis -----------------------------------------
    def analyze_project(self, project: LoadedProject) -> LoadedProject:
        """Type-check every module in dependency order, building interfaces."""
        for module in project.modules:
            analyzer = SemanticAnalyzer(
                source=module.source,
                filename=module.path,
                module_interfaces=dict(project.interfaces),
            )
            analyzer.set_program(module.program)
            result = analyzer.analyze(module.program)
            project.analyses[module.name] = result
            explicit = {
                n
                for decl in module.program.declarations
                if isinstance(decl, ast.ExportDecl)
                for n in decl.names
            }
            project.interfaces[module.name] = _interface_for(
                module.name, result, explicit
            )
            # Also register by the bare last segment for convenience.
            short = module.name.split(".")[-1]
            project.interfaces.setdefault(short, project.interfaces[module.name])
        return project

    # -- convenience ----------------------------------------------------
    def load_project(self, entry_path: str) -> LoadedProject:
        project = self.load(entry_path)
        return self.analyze_project(project)


def _interface_for(
    name: str, result: AnalysisResult, explicit_exports: Optional[Set[str]] = None
) -> ModuleInterface:
    """Build a module's public interface from its analysis result."""
    exports = set(result.exports or set())
    types: Dict[str, object] = {}
    functions: Dict[str, object] = {}
    values: Dict[str, object] = {}

    def is_public(sym_name: str) -> bool:
        if sym_name.startswith("_"):
            return False
        if explicit_exports:
            # An `export a, b` declaration is authoritative.
            return sym_name in explicit_exports
        return (sym_name in exports) or (not exports)

    for tname, ttype in (result.types or {}).items():
        if is_public(tname):
            types[tname] = ttype
    for fname, ftype in (result.functions or {}).items():
        if is_public(fname):
            functions[fname] = ftype
    symbol_table = result.symbol_table
    if symbol_table is not None and getattr(symbol_table, "module_scope", None):
        for sym in symbol_table.module_scope.symbols.values():
            if not is_public(sym.name):
                continue
            if sym.name in types or sym.name in functions:
                continue
            values[sym.name] = sym.type
    return ModuleInterface(name=name, types=types, functions=functions, values=values)


__all__ = [
    "MODULE_EXTENSION",
    "SEARCH_PATH_ENV",
    "ModuleResolutionError",
    "LoadedModule",
    "LoadedProject",
    "ModuleLoader",
]
