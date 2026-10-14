"""The Happy package manager (Step 6).

    from happy.package import PackageManager, parse_manifest, render_manifest

    pm = PackageManager()
    manifest = pm.load_manifest("happy.toml")
    lock = pm.resolve(manifest)
    pm.write_lockfile("happy.lock", lock)
"""

from .manager import (
    LOCKFILE_NAME,
    MANIFEST_NAME,
    TEMPLATES,
    Dependency,
    DependencyGraph,
    LockedPackage,
    Lockfile,
    Manifest,
    ManifestError,
    PackageError,
    PackageManager,
    PathRegistry,
    Registry,
    Version,
    parse_lockfile,
    parse_manifest,
    render_lockfile,
    render_manifest,
)

__all__ = [
    "PackageManager",
    "Manifest",
    "ManifestError",
    "PackageError",
    "Dependency",
    "DependencyGraph",
    "Lockfile",
    "LockedPackage",
    "Registry",
    "PathRegistry",
    "Version",
    "parse_manifest",
    "render_manifest",
    "parse_lockfile",
    "render_lockfile",
    "MANIFEST_NAME",
    "LOCKFILE_NAME",
    "TEMPLATES",
]
