"""Package manager for the Happy language (Step 6).

``happy`` projects are described by a ``happy.toml`` manifest and pinned by a
``happy.lock`` lockfile.  This module implements the whole lifecycle:

* **Manifest** — parse / render ``happy.toml`` (``[package]``, ``[dependencies]``,
  ``[dev-dependencies]``, ``[capabilities]``, ``[permissions]``).
* **Lockfile** — generate and read ``happy.lock``, recording the exact resolved
  version, source and content hash of every dependency (transitively).
* **Dependency graph** — build the graph, detect cycles, and produce a
  deterministic topological build order.
* **Project initialisation** — ``happy new <template>`` scaffolds a project
  (``app`` / ``lib`` / ``agent``) with a manifest, an entry ``.hpy`` file and a
  ``tests/`` directory.

Resolution is deterministic and offline by default: dependencies are resolved
against a :class:`Registry` (a name -> available-versions map).  A
:class:`PathRegistry` lets a project depend on a sibling directory, which is
what the tests use.  No network access is required, so builds are reproducible.

Typical use::

    from happy.package import PackageManager

    pm = PackageManager()
    pm.init_project("my_app", template="app")
    manifest = pm.load_manifest("my_app/happy.toml")
    lock = pm.resolve(manifest)
    pm.write_lockfile("my_app/happy.lock", lock)
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import tomllib
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

__all__ = [
    "PackageError",
    "ManifestError",
    "Dependency",
    "Manifest",
    "LockedPackage",
    "Lockfile",
    "DependencyGraph",
    "Registry",
    "PathRegistry",
    "PackageManager",
    "parse_manifest",
    "render_manifest",
    "parse_lockfile",
    "render_lockfile",
    "MANIFEST_NAME",
    "LOCKFILE_NAME",
    "TEMPLATES",
]

MANIFEST_NAME = "happy.toml"
LOCKFILE_NAME = "happy.lock"

#: The lockfile format version.
LOCK_VERSION = 1

#: Available project templates.
TEMPLATES = ("app", "lib", "agent")


class PackageError(Exception):
    """Raised for package-manager failures (bad manifest, unresolvable dep)."""


class ManifestError(PackageError):
    """Raised when ``happy.toml`` is malformed."""


# ---------------------------------------------------------------------------
# Version handling (a small, deterministic semver subset)
# ---------------------------------------------------------------------------
_NUM = r"(0|[1-9]\d*)"
_PRE_ID = r"(?:0|[1-9]\d*|\d*[A-Za-z\-][0-9A-Za-z\-]*)"
_BUILD_ID = r"[0-9A-Za-z\-]+"
_VERSION_RE = re.compile(
    rf"^{_NUM}\.{_NUM}\.{_NUM}"
    rf"(?:-({_PRE_ID}(?:\.{_PRE_ID})*))?"
    rf"(?:\+({_BUILD_ID}(?:\.{_BUILD_ID})*))?$"
)


def _prerelease_key(pre: str) -> Tuple:
    """Semver 2.0 precedence for a prerelease string.

    Identifiers compare left to right: numeric ones numerically, alphanumeric
    ones lexically, numeric below alphanumeric, and a shorter list below a
    longer one that shares its prefix (``alpha < alpha.1 < alpha.2 < alpha.10``).
    A version *without* a prerelease sorts above every prerelease.
    """
    if not pre:
        return (1,)
    ids = []
    for part in pre.split("."):
        ids.append((0, int(part), "") if part.isdigit() else (1, 0, part))
    return (0, tuple(ids))


@functools.total_ordering
@dataclass(frozen=True)
class Version:
    """A semantic version (``major.minor.patch[-prerelease][+build]``).

    Build metadata is accepted and preserved but ignored for precedence and
    equality, as the semver specification requires.
    """

    major: int
    minor: int
    patch: int
    prerelease: str = ""
    build: str = field(default="", compare=False)

    @classmethod
    def parse(cls, text: str) -> "Version":
        m = _VERSION_RE.match(text.strip()) if isinstance(text, str) else None
        if not m:
            raise PackageError(f"invalid version: {text!r}")
        return cls(
            int(m.group(1)), int(m.group(2)), int(m.group(3)),
            m.group(4) or "", m.group(5) or "",
        )

    def __str__(self) -> str:
        base = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            base += f"-{self.prerelease}"
        if self.build:
            base += f"+{self.build}"
        return base

    def _key(self) -> Tuple:
        return (self.major, self.minor, self.patch, _prerelease_key(self.prerelease))

    def _core(self) -> Tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() == other._key()

    def __hash__(self) -> int:
        return hash(self._key())

    def __lt__(self, other: "Version") -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return self._key() < other._key()


def _prerelease_allowed(version: Version, base: Version) -> bool:
    """A prerelease only satisfies a range that names a prerelease of the same
    ``major.minor.patch`` (the npm / Cargo rule); ranges never drift into
    unstable versions on their own."""
    if not version.prerelease:
        return True
    return bool(base.prerelease) and version._core() == base._core()


def _satisfies(version: Version, requirement: str) -> bool:
    """Return True when ``version`` satisfies a requirement.

    Supported forms: ``1.2.3`` (exact), ``^1.2.3`` (compatible), ``~1.2.3``
    (patch-level), ``>=``, ``>``, ``<=``, ``<`` and ``*`` (any *release*).
    """
    req = requirement.strip()
    if req in ("", "*"):
        return not version.prerelease
    if req.startswith("^"):
        base = Version.parse(req[1:])
        if not _prerelease_allowed(version, base):
            return False
        if base.major > 0:
            return version.major == base.major and version >= base
        if base.minor > 0:
            return version.major == 0 and version.minor == base.minor and version >= base
        return version.major == 0 and version.minor == 0 and version.patch == base.patch and version >= base
    if req.startswith("~"):
        base = Version.parse(req[1:])
        if not _prerelease_allowed(version, base):
            return False
        return (
            version.major == base.major
            and version.minor == base.minor
            and version >= base
        )
    for op, test in (
        (">=", lambda v, b: v >= b),
        ("<=", lambda v, b: v <= b),
        (">", lambda v, b: v > b),
        ("<", lambda v, b: v < b),
    ):
        if req.startswith(op):
            base = Version.parse(req[len(op):])
            return _prerelease_allowed(version, base) and test(version, base)
    return version == Version.parse(req)


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------
@dataclass
class Dependency:
    """A single declared dependency."""

    name: str
    requirement: str = "*"
    path: Optional[str] = None
    optional: bool = False

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"version": self.requirement}
        if self.path:
            out["path"] = self.path
        if self.optional:
            out["optional"] = True
        return out


@dataclass
class Manifest:
    """A parsed ``happy.toml``."""

    name: str
    version: str = "0.1.0"
    edition: str = "2026"
    description: str = ""
    authors: List[str] = field(default_factory=list)
    entry: str = "src/main.hpy"
    license: str = ""
    dependencies: Dict[str, Dependency] = field(default_factory=dict)
    dev_dependencies: Dict[str, Dependency] = field(default_factory=dict)
    capabilities: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)

    def all_dependencies(self) -> Dict[str, Dependency]:
        merged = dict(self.dependencies)
        for name, dep in self.dev_dependencies.items():
            merged.setdefault(name, dep)
        return merged

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package": {
                "name": self.name,
                "version": self.version,
                "edition": self.edition,
                "description": self.description,
                "authors": list(self.authors),
                "entry": self.entry,
                "license": self.license,
            },
            "dependencies": {n: d.to_dict() for n, d in self.dependencies.items()},
            "dev-dependencies": {n: d.to_dict() for n, d in self.dev_dependencies.items()},
            "capabilities": list(self.capabilities),
            "permissions": list(self.permissions),
        }


def parse_manifest(text: str, filename: Optional[str] = None) -> Manifest:
    """Parse ``happy.toml`` text into a :class:`Manifest`."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"{filename or MANIFEST_NAME}: {exc}") from exc

    pkg = data.get("package") or {}
    if not isinstance(pkg, dict):
        raise ManifestError("'[package]' must be a table")
    name = pkg.get("name")
    if not name:
        raise ManifestError("manifest is missing 'package.name'")

    def deps(section: str) -> Dict[str, Dependency]:
        raw = data.get(section) or {}
        if not isinstance(raw, dict):
            raise ManifestError(f"'[{section}]' must be a table")
        out: Dict[str, Dependency] = {}
        for dep_name, spec in raw.items():
            if isinstance(spec, str):
                out[dep_name] = Dependency(dep_name, spec)
            elif isinstance(spec, dict):
                out[dep_name] = Dependency(
                    dep_name,
                    str(spec.get("version", "*")),
                    path=spec.get("path"),
                    optional=bool(spec.get("optional", False)),
                )
            else:
                raise ManifestError(f"dependency '{dep_name}' has an invalid spec")
        return out

    return Manifest(
        name=str(name),
        version=str(pkg.get("version", "0.1.0")),
        edition=str(pkg.get("edition", "2026")),
        description=str(pkg.get("description", "")),
        authors=list(pkg.get("authors", []) or []),
        entry=str(pkg.get("entry", "src/main.hpy")),
        license=str(pkg.get("license", "")),
        dependencies=deps("dependencies"),
        dev_dependencies=deps("dev-dependencies"),
        capabilities=list(data.get("capabilities", []) or []),
        permissions=list(data.get("permissions", []) or []),
    )


def render_manifest(manifest: Manifest) -> str:
    """Render a :class:`Manifest` back to canonical ``happy.toml`` text."""
    lines: List[str] = ["[package]"]
    lines.append(f'name = "{manifest.name}"')
    lines.append(f'version = "{manifest.version}"')
    lines.append(f'edition = "{manifest.edition}"')
    if manifest.description:
        lines.append(f'description = "{manifest.description}"')
    if manifest.authors:
        authors = ", ".join(f'"{a}"' for a in manifest.authors)
        lines.append(f"authors = [{authors}]")
    lines.append(f'entry = "{manifest.entry}"')
    if manifest.license:
        lines.append(f'license = "{manifest.license}"')

    if manifest.dependencies:
        lines.append("")
        lines.append("[dependencies]")
        for name in sorted(manifest.dependencies):
            dep = manifest.dependencies[name]
            lines.append(_render_dep(name, dep))

    if manifest.dev_dependencies:
        lines.append("")
        lines.append("[dev-dependencies]")
        for name in sorted(manifest.dev_dependencies):
            dep = manifest.dev_dependencies[name]
            lines.append(_render_dep(name, dep))

    if manifest.capabilities:
        lines.append("")
        caps = ", ".join(f'"{c}"' for c in manifest.capabilities)
        lines.append(f"capabilities = [{caps}]")
    if manifest.permissions:
        lines.append("")
        perms = ", ".join(f'"{p}"' for p in manifest.permissions)
        lines.append(f"permissions = [{perms}]")

    return "\n".join(lines) + "\n"


def _render_dep(name: str, dep: Dependency) -> str:
    if dep.path and dep.requirement in ("", "*"):
        return f'{name} = {{ path = "{dep.path}" }}'
    if dep.path:
        return f'{name} = {{ version = "{dep.requirement}", path = "{dep.path}" }}'
    return f'{name} = "{dep.requirement}"'


# ---------------------------------------------------------------------------
# Lockfile
# ---------------------------------------------------------------------------
@dataclass
class LockedPackage:
    """One pinned dependency in ``happy.lock``."""

    name: str
    version: str
    source: str = "registry"
    checksum: str = ""
    dependencies: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "checksum": self.checksum,
            "dependencies": list(self.dependencies),
        }


@dataclass
class Lockfile:
    """A parsed ``happy.lock``."""

    version: int = LOCK_VERSION
    root: str = ""
    packages: List[LockedPackage] = field(default_factory=list)

    def by_name(self, name: str) -> Optional[LockedPackage]:
        for p in self.packages:
            if p.name == name:
                return p
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lock-version": self.version,
            "root": self.root,
            "packages": [p.to_dict() for p in self.packages],
        }


def render_lockfile(lock: Lockfile) -> str:
    """Render a :class:`Lockfile` as deterministic JSON (``happy.lock``)."""
    return json.dumps(lock.to_dict(), indent=2, sort_keys=False) + "\n"


def parse_lockfile(text: str) -> Lockfile:
    """Parse ``happy.lock`` text."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PackageError(f"invalid {LOCKFILE_NAME}: {exc}") from exc
    lock = Lockfile(
        version=int(data.get("lock-version", LOCK_VERSION)),
        root=str(data.get("root", "")),
    )
    for raw in data.get("packages", []) or []:
        lock.packages.append(
            LockedPackage(
                name=raw["name"],
                version=raw["version"],
                source=raw.get("source", "registry"),
                checksum=raw.get("checksum", ""),
                dependencies=list(raw.get("dependencies", []) or []),
            )
        )
    return lock


# ---------------------------------------------------------------------------
# Dependency graph
# ---------------------------------------------------------------------------
class DependencyGraph:
    """A directed graph of package dependencies."""

    def __init__(self) -> None:
        self._edges: Dict[str, Set[str]] = {}

    def add_node(self, name: str) -> None:
        self._edges.setdefault(name, set())

    def add_edge(self, src: str, dst: str) -> None:
        self.add_node(src)
        self.add_node(dst)
        self._edges[src].add(dst)

    @property
    def nodes(self) -> List[str]:
        return sorted(self._edges)

    def edges(self) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        for src in sorted(self._edges):
            for dst in sorted(self._edges[src]):
                out.append((src, dst))
        return out

    def dependencies_of(self, name: str) -> List[str]:
        return sorted(self._edges.get(name, set()))

    def has_cycle(self) -> bool:
        return bool(self.find_cycle())

    def find_cycle(self) -> Optional[List[str]]:
        """Return one dependency cycle as a path, or ``None`` if acyclic."""
        WHITE, GREY, BLACK = 0, 1, 2
        color: Dict[str, int] = {n: WHITE for n in self._edges}
        stack: List[str] = []

        def visit(node: str) -> Optional[List[str]]:
            color[node] = GREY
            stack.append(node)
            for nxt in sorted(self._edges.get(node, set())):
                if color.get(nxt, WHITE) == GREY:
                    idx = stack.index(nxt)
                    return stack[idx:] + [nxt]
                if color.get(nxt, WHITE) == WHITE:
                    found = visit(nxt)
                    if found:
                        return found
            stack.pop()
            color[node] = BLACK
            return None

        for node in sorted(self._edges):
            if color[node] == WHITE:
                found = visit(node)
                if found:
                    return found
        return None

    def topological_order(self) -> List[str]:
        """Return a deterministic build order (dependencies first).

        Raises :class:`PackageError` if the graph contains a cycle.
        """
        cycle = self.find_cycle()
        if cycle:
            raise PackageError("dependency cycle: " + " -> ".join(cycle))
        visited: Set[str] = set()
        order: List[str] = []

        def visit(node: str) -> None:
            if node in visited:
                return
            visited.add(node)
            for dep in sorted(self._edges.get(node, set())):
                visit(dep)
            order.append(node)

        for node in sorted(self._edges):
            visit(node)
        return order


# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------
class Registry:
    """An in-memory package registry: name -> available versions."""

    def __init__(self, packages: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        #: name -> {"versions": [str, ...], "dependencies": {ver: {name: req}}}
        self.packages: Dict[str, Dict[str, Any]] = packages or {}

    def add(self, name: str, version: str, dependencies: Optional[Dict[str, str]] = None) -> None:
        entry = self.packages.setdefault(name, {"versions": [], "dependencies": {}})
        if version not in entry["versions"]:
            entry["versions"].append(version)
        entry["dependencies"][version] = dict(dependencies or {})

    def versions(self, name: str) -> List[str]:
        entry = self.packages.get(name)
        if not entry:
            return []
        return sorted(entry["versions"], key=Version.parse)

    def dependencies(self, name: str, version: str) -> Dict[str, str]:
        entry = self.packages.get(name)
        if not entry:
            return {}
        return dict(entry["dependencies"].get(version, {}))

    def resolve(self, name: str, requirement: str) -> Optional[str]:
        """Return the highest version of ``name`` satisfying ``requirement``."""
        candidates = [v for v in self.versions(name) if _satisfies(Version.parse(v), requirement)]
        if not candidates:
            return None
        return max(candidates, key=Version.parse)


class PathRegistry(Registry):
    """A registry backed by sibling project directories.

    Each directory that contains a ``happy.toml`` is exposed as a package whose
    single version is the manifest's own version.
    """

    def __init__(self, root: str) -> None:
        super().__init__()
        self.root = root
        self._scan()

    def _scan(self) -> None:
        if not os.path.isdir(self.root):
            return
        for entry in sorted(os.listdir(self.root)):
            path = os.path.join(self.root, entry)
            manifest_path = os.path.join(path, MANIFEST_NAME)
            if not os.path.isfile(manifest_path):
                continue
            try:
                with open(manifest_path, "r", encoding="utf-8") as fh:
                    manifest = parse_manifest(fh.read(), manifest_path)
            except (OSError, PackageError):
                continue
            deps = {n: d.requirement for n, d in manifest.dependencies.items()}
            self.add(manifest.name, manifest.version, deps)


# ---------------------------------------------------------------------------
# Package manager
# ---------------------------------------------------------------------------
class PackageManager:
    """High-level package-manager operations."""

    def __init__(self, registry: Optional[Registry] = None) -> None:
        self.registry = registry or Registry()

    # -- manifest I/O ---------------------------------------------------
    def load_manifest(self, path: str) -> Manifest:
        """Load a manifest from a file path or a project directory."""
        if os.path.isdir(path):
            path = os.path.join(path, MANIFEST_NAME)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            raise PackageError(f"cannot read manifest: {exc}") from exc
        return parse_manifest(text, path)

    def write_manifest(self, path: str, manifest: Manifest) -> str:
        if os.path.isdir(path):
            path = os.path.join(path, MANIFEST_NAME)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_manifest(manifest))
        return path

    # -- lockfile I/O ---------------------------------------------------
    def load_lockfile(self, path: str) -> Lockfile:
        if os.path.isdir(path):
            path = os.path.join(path, LOCKFILE_NAME)
        with open(path, "r", encoding="utf-8") as fh:
            return parse_lockfile(fh.read())

    def write_lockfile(self, path: str, lock: Lockfile) -> str:
        if os.path.isdir(path):
            path = os.path.join(path, LOCKFILE_NAME)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(render_lockfile(lock))
        return path

    # -- resolution -----------------------------------------------------
    def resolve(self, manifest: Manifest) -> Lockfile:
        """Resolve ``manifest``'s dependencies into a :class:`Lockfile`.

        Resolution is breadth-first and deterministic: each dependency is
        pinned to the highest version satisfying its requirement, and its own
        transitive dependencies are resolved in turn.  A dependency that cannot
        be satisfied raises :class:`PackageError`.
        """
        lock = Lockfile(root=manifest.name)
        resolved: Dict[str, LockedPackage] = {}
        queue: List[Tuple[str, str]] = [
            (name, dep.requirement)
            for name, dep in sorted(manifest.all_dependencies().items())
        ]
        seen: Set[str] = set()

        while queue:
            name, requirement = queue.pop(0)
            if name in seen:
                continue
            seen.add(name)
            version = self.registry.resolve(name, requirement)
            if version is None:
                raise PackageError(
                    f"cannot resolve dependency '{name}' {requirement!r}: "
                    "no matching version in the registry"
                )
            transitive = self.registry.dependencies(name, version)
            pkg = LockedPackage(
                name=name,
                version=version,
                source="registry",
                checksum=_checksum(name, version),
                dependencies=sorted(transitive),
            )
            resolved[name] = pkg
            for dep_name, dep_req in sorted(transitive.items()):
                if dep_name not in seen:
                    queue.append((dep_name, dep_req))

        lock.packages = [resolved[n] for n in sorted(resolved)]
        return lock

    def build_graph(self, manifest: Manifest, lock: Optional[Lockfile] = None) -> DependencyGraph:
        """Build the dependency graph for ``manifest`` (using ``lock`` if given)."""
        graph = DependencyGraph()
        graph.add_node(manifest.name)
        if lock is None:
            lock = self.resolve(manifest)
        for pkg in lock.packages:
            graph.add_node(pkg.name)
            for dep in pkg.dependencies:
                graph.add_edge(pkg.name, dep)
        for name in manifest.all_dependencies():
            graph.add_edge(manifest.name, name)
        return graph

    # -- project scaffolding -------------------------------------------
    def init_project(
        self,
        directory: str,
        name: Optional[str] = None,
        template: str = "app",
        version: str = "0.1.0",
        description: str = "",
    ) -> Manifest:
        """Scaffold a new Happy project in ``directory``.

        Returns the created :class:`Manifest`.  Raises :class:`PackageError`
        when the template is unknown or the directory already has a manifest.
        """
        if template not in TEMPLATES:
            raise PackageError(
                f"unknown template {template!r}; choose one of {', '.join(TEMPLATES)}"
            )
        project_name = name or os.path.basename(os.path.abspath(directory)) or "happy_app"
        project_name = _sanitise_name(project_name)

        manifest_path = os.path.join(directory, MANIFEST_NAME)
        if os.path.exists(manifest_path):
            raise PackageError(f"{manifest_path} already exists")

        os.makedirs(directory, exist_ok=True)
        os.makedirs(os.path.join(directory, "src"), exist_ok=True)
        os.makedirs(os.path.join(directory, "tests"), exist_ok=True)

        manifest = Manifest(
            name=project_name,
            version=version,
            description=description or f"{project_name} — a Happy {template}",
            entry="src/main.hpy",
        )
        self.write_manifest(manifest_path, manifest)

        with open(os.path.join(directory, "src", "main.hpy"), "w", encoding="utf-8") as fh:
            fh.write(_template_source(project_name, template))

        with open(os.path.join(directory, "tests", "test_main.hpy"), "w", encoding="utf-8") as fh:
            fh.write(_template_test(project_name))

        with open(os.path.join(directory, ".gitignore"), "w", encoding="utf-8") as fh:
            fh.write("__pycache__/\n*.pyc\n.happy/\n")

        # An empty lockfile so the project is immediately buildable.
        self.write_lockfile(os.path.join(directory, LOCKFILE_NAME), Lockfile(root=project_name))
        return manifest

    # -- dependency editing --------------------------------------------
    def add_dependency(
        self, manifest: Manifest, name: str, requirement: str = "*", dev: bool = False
    ) -> Manifest:
        dep = Dependency(name, requirement)
        target = manifest.dev_dependencies if dev else manifest.dependencies
        target[name] = dep
        return manifest

    def remove_dependency(self, manifest: Manifest, name: str) -> Manifest:
        manifest.dependencies.pop(name, None)
        manifest.dev_dependencies.pop(name, None)
        return manifest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _checksum(name: str, version: str) -> str:
    """A deterministic content hash for a locked package."""
    digest = hashlib.sha256(f"{name}@{version}".encode("utf-8")).hexdigest()
    return "sha256:" + digest


def _sanitise_name(name: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_\-]", "_", name.lower())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned or "happy_app"


def _template_source(name: str, template: str) -> str:
    if template == "lib":
        return (
            f"// {name} — a Happy library.\n"
            "module " + name + "\n\n"
            "// A pure, contract-checked helper.\n"
            "function add(a: Int, b: Int) -> Int\n"
            "    requires a >= 0\n"
            "    requires b >= 0\n"
            "    ensures result >= a\n"
            "{\n"
            "    return a + b\n"
            "}\n"
        )
    if template == "agent":
        return (
            f"// {name} — a Happy agent application.\n"
            "module " + name + "\n\n"
            "capability Net { grants net }\n\n"
            "permission SafeNet {\n"
            "    can net\n"
            "    cannot file_write\n"
            "}\n\n"
            "agent Assistant {\n"
            '    goal "answer questions safely"\n'
            "    permission [SafeNet]\n"
            "    capability [Net]\n"
            "    effects [net]\n\n"
            "    function greet(who: String) -> String\n"
            "        requires who != \"\"\n"
            "    {\n"
            '        return "Hello, " + who\n'
            "    }\n"
            "}\n\n"
            "app " + _pascal(name) + " {\n"
            '    println(Assistant.greet("world"))\n'
            "}\n"
        )
    # default: app
    return (
        f"// {name} — a Happy application.\n"
        "module " + name + "\n\n"
        "app " + _pascal(name) + " {\n"
        '    println("Hello from ' + name + '!")\n'
        "}\n"
    )


def _template_test(name: str) -> str:
    return (
        f"// Tests for {name}.\n"
        "module " + name + ".tests\n\n"
        "// Happy test files are ordinary .hpy programs; the runner executes\n"
        "// them and checks the exit status.\n"
        "app Tests {\n"
        '    println("ok")\n'
        "}\n"
    )


def _pascal(name: str) -> str:
    parts = re.split(r"[_\-\s]+", name)
    return "".join(p[:1].upper() + p[1:] for p in parts if p) or "App"
