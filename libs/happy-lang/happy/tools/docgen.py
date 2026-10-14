"""Documentation generator for Happy source (Step 12).

``happy doc`` parses a ``.hpy`` file and renders a Markdown reference for every
public declaration: types, traits, enums, functions (with signatures, contracts
and effects) and agents.  Comments immediately preceding a declaration are
treated as its doc comment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ..compiler import parse
from ..compiler import ast as A

__all__ = ["DocGenerator", "generate_docs", "Declaration"]


@dataclass
class Declaration:
    """A documented declaration."""

    kind: str
    name: str
    signature: str = ""
    doc: str = ""
    contracts: List[str] = field(default_factory=list)
    details: List[str] = field(default_factory=list)


class DocGenerator:
    """Renders Markdown documentation from a Happy source file."""

    def __init__(self, source: str, filename: str = "module.hpy") -> None:
        self.source = source
        self.filename = filename
        self.comments = _comment_index(source)

    def generate(self) -> str:
        program = parse(self.source, filename=self.filename)
        module_name = program.module.name if getattr(program, "module", None) else None
        title = module_name or self.filename
        lines: List[str] = [f"# {title}", ""]
        if module_name:
            lines.append(f"*Module `{module_name}`*")
            lines.append("")

        decls: List[Declaration] = []
        for decl in program.declarations:
            d = self._describe(decl)
            if d is not None:
                decls.append(d)

        if not decls:
            lines.append("_No public declarations._")
            return "\n".join(lines).rstrip() + "\n"

        by_kind: Dict[str, List[Declaration]] = {}
        for d in decls:
            by_kind.setdefault(d.kind, []).append(d)

        for kind in [
            "Type",
            "Enum",
            "Trait",
            "Function",
            "Agent",
            "Constant",
            "Import",
        ]:
            group = by_kind.get(kind)
            if not group:
                continue
            lines.append(f"## {kind}")
            lines.append("")
            for d in group:
                lines.append(f"### `{d.name}`")
                lines.append("")
                if d.signature:
                    lines.append("```happy")
                    lines.append(d.signature)
                    lines.append("```")
                    lines.append("")
                if d.doc:
                    lines.append(d.doc)
                    lines.append("")
                for c in d.contracts:
                    lines.append(f"- {c}")
                if d.contracts:
                    lines.append("")
                for detail in d.details:
                    lines.append(f"- {detail}")
                if d.details:
                    lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    # -- helpers --------------------------------------------------------
    def _doc_for(self, decl: Any) -> str:
        line = getattr(getattr(decl, "loc", None), "line", None)
        if line is None:
            return ""
        # Comment lines immediately above the declaration.
        parts: List[str] = []
        cursor = line - 1
        while cursor in self.comments:
            parts.append(self.comments[cursor])
            cursor -= 1
        return " ".join(reversed(parts)).strip()

    def _describe(self, decl: Any) -> Optional[Declaration]:
        doc = self._doc_for(decl)
        if isinstance(decl, A.StructDecl):
            fields = [f"{f.name}: {_type(f.type_annotation)}" for f in decl.fields]
            impl = (
                f" implements {', '.join(decl.implements)}"
                if getattr(decl, "implements", None)
                else ""
            )
            return Declaration(
                kind="Type",
                name=decl.name,
                signature=f"type {decl.name}{impl} {{ ... }}",
                doc=doc,
                details=[f"field `{f}`" for f in fields] or ["(no fields)"],
            )
        if isinstance(decl, A.EnumDecl):
            variants = list(getattr(decl, "variants", []))
            return Declaration(
                kind="Enum",
                name=decl.name,
                signature=f"enum {decl.name} {{ ... }}",
                doc=doc,
                details=[f"variant `{v.name}`" for v in variants] or ["(no variants)"],
            )
        if isinstance(decl, A.TraitDecl):
            return Declaration(
                kind="Trait",
                name=decl.name,
                signature=f"trait {decl.name} {{ ... }}",
                doc=doc,
                details=[f"`{m.name}`" for m in decl.methods] or ["(no methods)"],
            )
        if isinstance(decl, A.FunctionDecl):
            return Declaration(
                kind="Function",
                name=decl.name,
                signature=_function_signature(decl),
                doc=doc,
                contracts=_contract_text(decl.contracts),
            )
        if isinstance(decl, A.ImplDecl):
            return Declaration(
                kind="Trait",
                name=f"impl {decl.name} for {decl.for_type}",
                signature=f"impl {decl.name} for {decl.for_type} {{ ... }}",
                doc=doc,
                details=[f"`{m.name}`" for m in decl.methods] or ["(no methods)"],
            )
        if isinstance(decl, A.AgentDecl):
            return Declaration(
                kind="Agent",
                name=decl.name,
                signature=f"agent {decl.name} {{ ... }}",
                doc=doc,
            )
        if isinstance(decl, A.ConstDecl):
            return Declaration(
                kind="Constant",
                name=decl.name,
                signature=(
                    f"let {decl.name}: {_type(decl.type_annotation)}"
                    if decl.type_annotation is not None
                    else f"let {decl.name} = ..."
                ),
                doc=doc,
            )
        if isinstance(decl, A.ImportDecl):
            return Declaration(
                kind="Import",
                name=decl.name,
                signature=f"import {decl.name}",
                doc=doc,
            )
        return None


def _comment_index(source: str) -> Dict[int, str]:
    """Map 1-based line numbers to their ``//`` comment text."""
    out: Dict[int, str] = {}
    for i, line in enumerate(source.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("//"):
            out[i] = stripped[2:].strip()
    return out


def _type(node: Any) -> str:
    if node is None:
        return "Unit"
    if isinstance(node, str):
        return node
    name = getattr(node, "name", None)
    if name:
        args = getattr(node, "arguments", None) or getattr(node, "args", None)
        if args:
            return f"{name}<{', '.join(_type(a) for a in args)}>"
        return str(name)
    return str(getattr(node, "kind", node))


def _function_signature(decl: Any) -> str:
    params = ", ".join(
        f"{p.name}: {_type(getattr(p, 'type_annotation', None))}"
        for p in decl.params
    )
    ret = _type(getattr(decl, "returns", None))
    prefix = "async function" if getattr(decl, "is_async", False) else "function"
    return f"{prefix} {decl.name}({params}) -> {ret}"


def _contract_text(contracts: Any) -> List[str]:
    if not contracts:
        return []
    out: List[str] = []
    for c in contracts:
        kind = getattr(c, "kind", "")
        expr = getattr(c, "expression", None)
        out.append(f"**{kind}**: `{_expr_text(expr)}`")
    return out


def _expr_text(expr: Any) -> str:
    if expr is None:
        return ""
    return str(getattr(expr, "name", None) or getattr(expr, "value", None) or expr)


def generate_docs(source: str, filename: str = "module.hpy") -> str:
    """Convenience wrapper around :class:`DocGenerator`."""
    return DocGenerator(source, filename).generate()
