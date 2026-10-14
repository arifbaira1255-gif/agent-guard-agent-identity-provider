"""Packaging / publishing support for Happy projects (Step 12).

``happy publish`` packages a Happy project into a single distributable ``.hpyz``
archive: a zip that contains every ``.hpy`` source file plus a generated
``happy.pkg.json`` manifest (name, version, entry point, files with checksums).

This is a self-contained format — it needs no external registry — so a project
can be built, shipped and reproduced offline.  :func:`install_package` unpacks
one back into a directory.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..package.manager import MANIFEST_NAME, Manifest, parse_manifest

__all__ = [
    "PackageInfo",
    "create_package",
    "install_package",
    "PackageInstallError",
    "read_manifest",
    "PACKAGE_MANIFEST",
]

PACKAGE_MANIFEST = "happy.pkg.json"


@dataclass
class PackageInfo:
    """Metadata describing a built package."""

    name: str
    version: str
    entry: Optional[str] = None
    files: List[str] = field(default_factory=list)
    checksums: Dict[str, str] = field(default_factory=dict)
    path: Optional[str] = None

    def as_dict(self) -> Dict[str, object]:
        return {
            "format": 1,
            "name": self.name,
            "version": self.version,
            "entry": self.entry,
            "files": self.files,
            "checksums": self.checksums,
        }


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def read_manifest(root: str) -> Optional[Manifest]:
    """Read ``happy.toml`` from ``root`` (or None)."""
    path = os.path.join(root, MANIFEST_NAME)
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return parse_manifest(fh.read(), filename=path)


def create_package(
    root: str = ".",
    output: Optional[str] = None,
    name: Optional[str] = None,
    version: Optional[str] = None,
    entry: Optional[str] = None,
) -> PackageInfo:
    """Package the project at ``root`` into a ``.hpyz`` archive."""
    manifest = read_manifest(root)
    pkg_name = name or (manifest.name if manifest else os.path.basename(
        os.path.abspath(root)
    ))
    pkg_version = version or (manifest.version if manifest else "0.1.0")

    sources: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if d not in {".git", "__pycache__", ".happy"}
        ]
        for fn in filenames:
            if fn.endswith(".hpy"):
                sources.append(os.path.join(dirpath, fn))
    sources.sort()

    entry_path = entry
    if entry_path is None and manifest is not None:
        entry_path = getattr(manifest, "entry", None)
    if entry_path is None and sources:
        # Prefer a file named main.hpy, else the first source.
        preferred = [s for s in sources if os.path.basename(s) == "main.hpy"]
        entry_path = preferred[0] if preferred else sources[0]

    if output is None:
        output = f"{pkg_name}-{pkg_version}.hpyz"

    rel_files = [os.path.relpath(s, root).replace(os.sep, "/") for s in sources]
    checksums = {
        os.path.relpath(s, root).replace(os.sep, "/"): _sha256(s) for s in sources
    }
    if entry_path:
        # ``entry`` may be given as a project-relative path (e.g. the manifest's
        # ``entry = "src/main.hpy"``).  Resolve it against ``root`` *before*
        # relativising, otherwise ``os.path.relpath`` measures it from the
        # process CWD and bakes a machine-specific path into the manifest.
        abs_entry = entry_path if os.path.isabs(entry_path) else os.path.join(root, entry_path)
        rel_entry = os.path.relpath(abs_entry, root).replace(os.sep, "/")
    else:
        rel_entry = None
    info = PackageInfo(
        name=pkg_name,
        version=pkg_version,
        entry=rel_entry,
        files=rel_files,
        checksums=checksums,
        path=output,
    )

    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            PACKAGE_MANIFEST, json.dumps(info.as_dict(), indent=2, sort_keys=True)
        )
        for src in sources:
            arc = os.path.relpath(src, root).replace(os.sep, "/")
            zf.write(src, arc)
    return info


class PackageInstallError(ValueError):
    """Raised when a ``.hpyz`` archive is malformed, tampered with or unsafe."""


#: Hard limits that keep a hostile archive from exhausting disk or memory.
MAX_PACKAGE_FILES = 10_000
MAX_PACKAGE_BYTES = 256 * 1024 * 1024


def _safe_target(dest: str, member: str) -> str:
    """Resolve ``member`` under ``dest`` or raise on any escape attempt."""
    if not member or member.startswith(("/", "\\")) or "\x00" in member:
        raise PackageInstallError(f"unsafe path in archive: {member!r}")
    parts = member.replace("\\", "/").split("/")
    if any(part == ".." for part in parts) or (len(parts[0]) == 2 and parts[0][1] == ":"):
        raise PackageInstallError(f"unsafe path in archive: {member!r}")
    root = os.path.realpath(dest)
    target = os.path.realpath(os.path.join(root, *parts))
    # ``commonpath`` (not ``startswith``) so '/tmp/a' does not admit '/tmp/ab'.
    if os.path.commonpath([root, target]) != root or target == root:
        raise PackageInstallError(f"unsafe path in archive: {member!r}")
    return target


def install_package(archive: str, dest: str) -> PackageInfo:
    """Verify and unpack a ``.hpyz`` archive into ``dest``.

    Every file is hashed and compared with the checksum recorded in the
    package manifest *before anything is written*.  The archive is rejected if
    a checksum is missing or wrong, if it contains a file the manifest does not
    list, if a listed file is absent, or if any member path escapes ``dest``.
    """
    try:
        zf = zipfile.ZipFile(archive, "r")
    except (zipfile.BadZipFile, OSError) as exc:
        raise PackageInstallError(f"cannot open package {archive!r}: {exc}") from exc
    with zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_PACKAGE_FILES:
            raise PackageInstallError("package contains too many files")
        if sum(i.file_size for i in infos) > MAX_PACKAGE_BYTES:
            raise PackageInstallError("package is too large when unpacked")
        try:
            raw = zf.read(PACKAGE_MANIFEST).decode("utf-8")
            data = json.loads(raw)
        except KeyError as exc:
            raise PackageInstallError(
                f"package has no {PACKAGE_MANIFEST}"
            ) from exc
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PackageInstallError(
                f"{PACKAGE_MANIFEST} is not valid JSON: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise PackageInstallError(f"{PACKAGE_MANIFEST} must be a JSON object")
        checksums = data.get("checksums")
        if not isinstance(checksums, dict):
            raise PackageInstallError(
                f"{PACKAGE_MANIFEST} has no 'checksums'; refusing to install"
            )

        contents: Dict[str, bytes] = {}
        for info in infos:
            name = info.filename
            if name == PACKAGE_MANIFEST:
                continue
            _safe_target(dest, name)  # path check (raises on escape)
            if name in contents:
                raise PackageInstallError(f"duplicate file in archive: {name}")
            contents[name] = zf.read(name)

        for name, blob in contents.items():
            expected = checksums.get(name)
            if expected is None:
                raise PackageInstallError(
                    f"file {name!r} is not listed in the package manifest"
                )
            actual = "sha256:" + hashlib.sha256(blob).hexdigest()
            if not hmac.compare_digest(str(expected), actual):
                raise PackageInstallError(
                    f"checksum mismatch for {name!r}: the package is corrupt or tampered with"
                )
        missing = sorted(set(checksums) - set(contents))
        if missing:
            raise PackageInstallError(
                f"package manifest lists files missing from the archive: {', '.join(missing)}"
            )

        os.makedirs(dest, exist_ok=True)
        for name, blob in contents.items():
            target = _safe_target(dest, name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(blob)
    return PackageInfo(
        name=str(data.get("name", "unknown")),
        version=str(data.get("version", "0.0.0")),
        entry=data.get("entry"),
        files=list(data.get("files", [])),
        checksums=dict(checksums),
        path=dest,
    )
