"""Deterministic AST-based source formatter for the Happy language (Step 6).

``happy fmt`` re-prints a ``.hpy`` program from its **AST** rather than from its
tokens.  That makes the output canonical: two programs that parse to the same
tree format to byte-identical text, and formatting an already-formatted file is
a no-op (the formatter is *idempotent*).

Style rules (fixed, not configurable — determinism is the point)
----------------------------------------------------------------
* 4-space indentation, no tabs, no trailing whitespace, single trailing newline.
* One blank line between top-level declarations; two before a ``module`` header
  block is never needed (the header is followed by one blank line).
* Contract clauses (``requires`` / ``ensures`` / ``invariant``) are indented one
  level under the declaration they belong to, one per line.
* ``effects [...]`` is printed on its own line, after the contracts.
* Struct fields are one per line, aligned as ``name: Type`` with an optional
  ``= default``; ``secret`` fields keep their modifier.
* Enum variants are one per line, payloads in parentheses.
* Blocks use braces on the declaration line (``function f() -> Int {``) and a
  closing brace on its own line.
* Binary operators are surrounded by single spaces; unary operators bind tight;
  ``await`` is followed by a space.
* ``if`` / ``else if`` / ``else`` chains are printed as ``} else if ... {``.

The formatter never changes program meaning: it only re-orders whitespace and
re-prints the same tokens the parser saw.  Comments are not part of the AST, so
they are dropped — this is documented behaviour (use ``happy fmt --check`` in CI
to keep sources canonical).

Typical use::

    from happy.tools.fmt import format_source

    result = format_source(source, filename="demo.hpy")
    if result.changed:
        open("demo.hpy", "w").write(result.formatted)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..compiler import ast
from ..compiler.errors import HappyError
from ..compiler.parser import _BINARY_PRECEDENCE, _RIGHT_ASSOCIATIVE, parse

__all__ = [
    "FormatResult",
    "Formatter",
    "format_source",
    "format_program",
    "INDENT",
]

#: One indentation level.
INDENT = "    "


@dataclass
class FormatResult:
    """The outcome of formatting one source file."""

    original: str
    formatted: str
    filename: Optional[str] = None
    ok: bool = True
    error: Optional[HappyError] = None
    #: True when the formatter met a construct it cannot re-print faithfully.
    #: In that case ``formatted`` is the *original* text and callers must not
    #: overwrite the file.
    unformattable: bool = False

    @property
    def changed(self) -> bool:
        return self.formatted != self.original

    def diff_summary(self) -> str:
        if not self.ok:
            return f"{self.filename or '<source>'}: cannot format (parse error)"
        if self.unformattable:
            return (
                f"{self.filename or '<source>'}: left unchanged "
                "(contains a construct the formatter cannot re-print safely)"
            )
        if not self.changed:
            return f"{self.filename or '<source>'}: already formatted"
        before = len(self.original.splitlines())
        after = len(self.formatted.splitlines())
        return (
            f"{self.filename or '<source>'}: reformatted "
            f"({before} -> {after} lines)"
        )


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------
class _Writer:
    """Accumulates formatted lines with indentation control."""

    def __init__(self) -> None:
        self.lines: List[str] = []
        self.level = 0

    def line(self, text: str = "") -> None:
        if text:
            self.lines.append(INDENT * self.level + text)
        else:
            self.lines.append("")

    def push(self) -> None:
        self.level += 1

    def pop(self) -> None:
        self.level = max(0, self.level - 1)

    def blank(self) -> None:
        """Emit a blank line unless the buffer is empty or already blank."""
        if self.lines and self.lines[-1] != "":
            self.lines.append("")

    def text(self) -> str:
        # Collapse runs of blank lines to at most one, strip trailing blanks.
        out: List[str] = []
        for ln in self.lines:
            if ln == "" and out and out[-1] == "":
                continue
            out.append(ln.rstrip())
        while out and out[-1] == "":
            out.pop()
        return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Formatter
# ---------------------------------------------------------------------------
class Formatter:
    """Re-prints a Happy AST as canonical source text."""

    def __init__(self) -> None:
        self.w = _Writer()
        #: Set when a construct could not be re-printed faithfully.
        self.unformattable = False

    # -- entry points ---------------------------------------------------
    def format(self, program: ast.Program) -> str:
        self.w = _Writer()
        first = True
        if program.module is not None:
            self._module(program.module)
            first = False
        for imp in program.imports:
            if not first:
                self.w.blank()
            self._import(imp)
            first = False
        for decl in program.declarations:
            if not first:
                self.w.blank()
            self._decl(decl)
            first = False
        return self.w.text()

    # -- module / imports ----------------------------------------------
    def _module(self, decl: ast.ModuleDecl) -> None:
        self.w.line(f"module {decl.name}")

    def _import(self, imp: ast.ImportDecl) -> None:
        if imp.symbols:
            names = ", ".join(imp.symbols)
            self.w.line(f'import {{ {names} }} from "{imp.name}"')
        elif imp.alias:
            self.w.line(f"import {imp.name} as {imp.alias}")
        else:
            self.w.line(f"import {imp.name}")

    # -- declarations ---------------------------------------------------
    def _decl(self, decl: ast.Decl) -> None:
        if isinstance(decl, ast.StructDecl):
            self._struct(decl)
        elif isinstance(decl, ast.EnumDecl):
            self._enum(decl)
        elif isinstance(decl, ast.FunctionDecl):
            self._function(decl)
        elif isinstance(decl, ast.RuleDecl):
            self._rule(decl)
        elif isinstance(decl, ast.PermissionDecl):
            self._permission(decl)
        elif isinstance(decl, ast.CapabilityDecl):
            self._capability(decl)
        elif isinstance(decl, ast.AgentDecl):
            self._agent(decl)
        elif isinstance(decl, ast.AiDecl):
            self._ai(decl)
        elif isinstance(decl, ast.AppDecl):
            self._app(decl)
        elif isinstance(decl, ast.TraitDecl):
            self._trait(decl)
        elif isinstance(decl, ast.ImplDecl):
            self._impl(decl)
        else:  # pragma: no cover - unknown declaration
            self.unformattable = True
            self.w.line(f"// <unformattable {type(decl).__name__}>")

    def _trait(self, decl: ast.TraitDecl) -> None:
        self.w.line(f"trait {decl.name} {{")
        self.w.push()
        for m in decl.methods:
            self._method_header(
                m.name, m.params, m.returns, m.contracts, None, m.is_async, m.generics
            )
            if m.body is not None:
                self._block(m.body)
        self.w.pop()
        self.w.line("}")

    def _impl(self, decl: ast.ImplDecl) -> None:
        self.w.line(f"impl {decl.name} for {decl.for_type} {{")
        self.w.push()
        for m in decl.methods:
            self._method_header(
                m.name, m.params, m.returns, m.contracts, m.effects, m.is_async, m.generics
            )
            if m.body is not None:
                self._block(m.body)
        self.w.pop()
        self.w.line("}")

    def _method_header(
        self,
        name: str,
        params: List[ast.Param],
        returns: Optional[ast.TypeNode],
        contracts: List[ast.ContractClause],
        effects: Optional[ast.EffectSpec],
        is_async: bool,
        generics: List[str],
    ) -> None:
        prefix = "async " if is_async else ""
        gen = self._generics(generics)
        params_text = ", ".join(self._param(p) for p in params)
        head = f"{prefix}function {name}{gen}({params_text})"
        if returns is not None:
            head += f" -> {self._type(returns)}"
        self.w.line(head)
        self._contracts_and_effects(contracts, effects)

    def _struct(self, decl: ast.StructDecl) -> None:
        generics = self._generics(decl.generics)
        self.w.line(f"type {decl.name}{generics} {{")
        self.w.push()
        for f in decl.fields:
            self.w.line(self._field(f))
        for inv in decl.invariants:
            self.w.line(self._contract(inv))
        self.w.pop()
        self.w.line("}")

    def _field(self, f: ast.FieldDecl) -> str:
        prefix = "secret " if f.secret else ""
        text = f"{prefix}{f.name}"
        if f.type_annotation is not None:
            text += f": {self._type(f.type_annotation)}"
        if f.default is not None:
            text += f" = {self._expr(f.default)}"
        return text

    def _enum(self, decl: ast.EnumDecl) -> None:
        self.w.line(f"enum {decl.name} {{")
        self.w.push()
        for v in decl.variants:
            if v.payload:
                payload = ", ".join(self._type(t) for t in v.payload)
                self.w.line(f"{v.name}({payload})")
            else:
                self.w.line(v.name)
        self.w.pop()
        self.w.line("}")

    def _function(self, decl: ast.FunctionDecl) -> None:
        self._function_header(decl)
        if decl.body is not None:
            self._block(decl.body)
        # A body-less function is a signature only; nothing more to print.

    def _function_header(self, decl: ast.FunctionDecl) -> None:
        prefix = "async " if decl.is_async else ""
        generics = self._generics(decl.generics)
        params = ", ".join(self._param(p) for p in decl.params)
        head = f"{prefix}function {decl.name}{generics}({params})"
        if decl.returns is not None:
            head += f" -> {self._type(decl.returns)}"
        self.w.line(head)
        self._contracts_and_effects(decl.contracts, decl.effects)

    def _param(self, p: ast.Param) -> str:
        text = p.name
        if p.type_annotation is not None:
            text += f": {self._type(p.type_annotation)}"
        if p.default is not None:
            text += f" = {self._expr(p.default)}"
        return text

    def _contracts_and_effects(
        self, contracts: List[ast.ContractClause], effects: Optional[ast.EffectSpec]
    ) -> None:
        self.w.push()
        for c in contracts:
            self.w.line(self._contract(c))
        if effects is not None:
            names = ", ".join(effects.effects)
            self.w.line(f"effects [{names}]")
        self.w.pop()

    def _contract(self, c: ast.ContractClause) -> str:
        text = f"{c.kind} {self._expr(c.condition)}"
        if c.message is not None:
            text += f", {_quote(c.message)}"
        return text

    def _rule(self, decl: ast.RuleDecl) -> None:
        params = ""
        if decl.params:
            params = "(" + ", ".join(self._param(p) for p in decl.params) + ")"
        if decl.condition is not None:
            self.w.line(f"rule {decl.name}{params}: {self._expr(decl.condition)}")
            return
        self.w.line(f"rule {decl.name}{params}")
        self._contracts_and_effects(decl.contracts, None)
        if decl.body is not None:
            self._block(decl.body)

    def _permission(self, decl: ast.PermissionDecl) -> None:
        self.w.line(f"permission {decl.name} {{")
        self.w.push()
        for action in decl.can:
            self.w.line(f"can {action}")
        for action in decl.cannot:
            self.w.line(f"cannot {action}")
        self.w.pop()
        self.w.line("}")

    def _capability(self, decl: ast.CapabilityDecl) -> None:
        self.w.line(f"capability {decl.name} {{")
        self.w.push()
        for grant in decl.grants:
            self.w.line(f"grants {grant}")
        self.w.pop()
        self.w.line("}")

    def _agent(self, decl: ast.AgentDecl) -> None:
        self.w.line(f"agent {decl.name} {{")
        self.w.push()
        if decl.goal is not None:
            self.w.line(f"goal {self._expr(decl.goal)}")
        if decl.permissions:
            self.w.line(f"permission [{', '.join(decl.permissions)}]")
        if decl.capabilities:
            self.w.line(f"capability [{', '.join(decl.capabilities)}]")
        if decl.effects is not None:
            self.w.line(f"effects [{', '.join(decl.effects.effects)}]")
        for c in decl.contracts:
            self.w.line(self._contract(c))
        if decl.body is not None:
            for stmt in decl.body.statements:
                self._stmt(stmt)
        self.w.pop()
        self.w.line("}")

    def _ai(self, decl: ast.AiDecl) -> None:
        self.w.line(f"ai {decl.name} {{")
        self.w.push()
        if decl.prompt is not None:
            self.w.line(f"prompt {self._expr(decl.prompt)}")
        if decl.goal is not None:
            self.w.line(f"goal {self._expr(decl.goal)}")
        for c in decl.contracts:
            self.w.line(self._contract(c))
        if decl.body is not None:
            for stmt in decl.body.statements:
                self._stmt(stmt)
        self.w.pop()
        self.w.line("}")

    def _app(self, decl: ast.AppDecl) -> None:
        self.w.line(f"app {decl.name} {{")
        self.w.push()
        for c in decl.contracts:
            self.w.line(self._contract(c))
        if decl.body is not None:
            for stmt in decl.body.statements:
                self._stmt(stmt)
        self.w.pop()
        self.w.line("}")

    # -- statements -----------------------------------------------------
    def _block(self, block: ast.Block) -> None:
        self.w.line("{")
        self.w.push()
        for stmt in block.statements:
            self._stmt(stmt)
        self.w.pop()
        self.w.line("}")

    def _stmt(self, stmt: ast.Stmt) -> None:
        if isinstance(stmt, ast.LetStmt):
            kw = "var" if stmt.mutable else "let"
            text = f"{kw} {stmt.name}"
            if stmt.type_annotation is not None:
                text += f": {self._type(stmt.type_annotation)}"
            if stmt.value is not None:
                text += f" = {self._expr(stmt.value)}"
            self.w.line(text)
        elif isinstance(stmt, ast.AssignStmt):
            self.w.line(
                f"{self._expr(stmt.target)} {stmt.op} {self._expr(stmt.value)}"
            )
        elif isinstance(stmt, ast.ExprStmt):
            if stmt.expr is not None:
                self.w.line(self._expr(stmt.expr))
        elif isinstance(stmt, ast.IfStmt):
            self._if_chain(stmt)
        elif isinstance(stmt, ast.WhileStmt):
            self.w.line(f"while {self._expr(stmt.condition)} {{")
            self.w.push()
            if stmt.body is not None:
                for s in stmt.body.statements:
                    self._stmt(s)
            self.w.pop()
            self.w.line("}")
        elif isinstance(stmt, ast.ForStmt):
            self.w.line(
                f"for {stmt.variable} in {self._expr(stmt.iterable)} {{"
            )
            self.w.push()
            if stmt.body is not None:
                for s in stmt.body.statements:
                    self._stmt(s)
            self.w.pop()
            self.w.line("}")
        elif isinstance(stmt, ast.ReturnStmt):
            if stmt.value is not None:
                self.w.line(f"return {self._expr(stmt.value)}")
            else:
                self.w.line("return")
        elif isinstance(stmt, ast.BreakStmt):
            self.w.line("break")
        elif isinstance(stmt, ast.ContinueStmt):
            self.w.line("continue")
        elif isinstance(stmt, ast.Block):
            self._block(stmt)
        elif isinstance(stmt, ast.MatchStmt):
            self._match(stmt)
        elif isinstance(stmt, ast.FunctionDecl):
            # Nested function declaration (allowed inside agents).
            self._function(stmt)
        else:  # pragma: no cover - unknown statement
            self.unformattable = True
            self.w.line(f"// <unformattable {type(stmt).__name__}>")

    def _match(self, node: ast.MatchStmt) -> None:
        self.w.line(f"match {self._expr(node.subject)} {{")
        self.w.push()
        for arm in node.arms:
            pattern = self._pattern(arm.pattern)
            if arm.body is not None and len(arm.body.statements) == 1 and not isinstance(
                arm.body.statements[0], (ast.IfStmt, ast.WhileStmt, ast.ForStmt, ast.MatchStmt)
            ):
                self.w.line(f"{pattern} -> {self._stmt_inline(arm.body.statements[0])}")
            else:
                self.w.line(f"{pattern} -> {{")
                self.w.push()
                if arm.body is not None:
                    for s in arm.body.statements:
                        self._stmt(s)
                self.w.pop()
                self.w.line("}")
        self.w.pop()
        self.w.line("}")

    def _stmt_inline(self, stmt: ast.Stmt) -> str:
        if isinstance(stmt, ast.ReturnStmt):
            return f"return {self._expr(stmt.value)}" if stmt.value is not None else "return"
        if isinstance(stmt, ast.ExprStmt):
            return self._expr(stmt.expr)
        if isinstance(stmt, ast.BreakStmt):
            return "break"
        if isinstance(stmt, ast.ContinueStmt):
            return "continue"
        if isinstance(stmt, ast.LetStmt):
            kw = "var" if stmt.mutable else "let"
            text = f"{kw} {stmt.name}"
            if stmt.type_annotation is not None:
                text += f": {self._type(stmt.type_annotation)}"
            if stmt.value is not None:
                text += f" = {self._expr(stmt.value)}"
            return text
        # Fall back to a block for anything else.
        return "{ }"

    def _pattern(self, pat: Optional[ast.MatchPattern]) -> str:
        if pat is None:
            return "_"
        if pat.kind == "wildcard":
            return "_"
        if pat.kind == "binding":
            return pat.name or "_"
        if pat.kind == "literal":
            return self._expr(pat.value)
        if pat.kind == "variant":
            if pat.bindings:
                return f"{pat.name}({', '.join(pat.bindings)})"
            return pat.name or "_"
        if pat.kind == "struct":
            return f"{pat.name} {{ {', '.join(pat.bindings)} }}"
        if pat.kind == "or":
            return " | ".join(self._pattern(p) for p in pat.patterns)
        return "_"

    def _if_chain(self, node: ast.IfStmt) -> None:
        self.w.line(f"if {self._expr(node.condition)} {{")
        self.w.push()
        if node.then_branch is not None:
            for s in node.then_branch.statements:
                self._stmt(s)
        self.w.pop()

        else_branch = node.else_branch
        while isinstance(else_branch, ast.IfStmt):
            self.w.line(f"}} else if {self._expr(else_branch.condition)} {{")
            self.w.push()
            if else_branch.then_branch is not None:
                for s in else_branch.then_branch.statements:
                    self._stmt(s)
            self.w.pop()
            else_branch = else_branch.else_branch

        if isinstance(else_branch, ast.Block):
            self.w.line("} else {")
            self.w.push()
            for s in else_branch.statements:
                self._stmt(s)
            self.w.pop()
        self.w.line("}")

    # -- types ----------------------------------------------------------
    def _type(self, node: Optional[ast.TypeNode]) -> str:
        if node is None:
            return "Unit"
        if isinstance(node, ast.PrimitiveType):
            return node.name
        if isinstance(node, ast.NamedType):
            if node.module:
                return f"{node.module}.{node.name}"
            return node.name
        if isinstance(node, ast.GenericType):
            args = ", ".join(self._type(a) for a in node.args)
            return f"{node.name}<{args}>"
        if isinstance(node, ast.FunctionType):
            params = ", ".join(self._type(p) for p in node.params)
            ret = self._type(node.returns) if node.returns is not None else "Unit"
            return f"({params}) -> {ret}"
        if isinstance(node, ast.TupleType):
            return "(" + ", ".join(self._type(e) for e in node.elements) + ")"
        if isinstance(node, ast.OptionalType):
            return f"{self._type(node.inner)}?"
        return "Unit"  # pragma: no cover

    def _generics(self, names: List[str]) -> str:
        if not names:
            return ""
        return "<" + ", ".join(names) + ">"

    # -- expressions ----------------------------------------------------
    def _expr(self, node: Optional[ast.Expr]) -> str:
        if node is None:
            return ""
        if isinstance(node, ast.IntLiteral):
            return str(node.value)
        if isinstance(node, ast.FloatLiteral):
            return _format_float(node.value)
        if isinstance(node, ast.StringLiteral):
            return _quote(node.value)
        if isinstance(node, ast.CharLiteral):
            return "'" + _escape_char(node.value) + "'"
        if isinstance(node, ast.BoolLiteral):
            return "true" if node.value else "false"
        if isinstance(node, ast.NullLiteral):
            return "null"
        if isinstance(node, ast.Identifier):
            return node.name
        if isinstance(node, ast.BinaryOp):
            return self._binary(node)
        if isinstance(node, ast.UnaryOp):
            operand = self._expr(node.operand)
            inner = node.operand
            if isinstance(inner, ast.BinaryOp):
                # `-a ** b` is `-(a ** b)`; anything looser needs parentheses.
                keeps = node.op != "!" and inner.op == "**"
                if not keeps:
                    operand = f"({operand})"
            elif isinstance(inner, ast.UnaryOp) and (
                inner.op == node.op or {inner.op, node.op} <= {"-", "+"}
            ):
                # `-(-x)` must not print as `--x`: the lexer reads `--` as a
                # single token, so the output would not even parse.
                operand = f"({operand})"
            return f"{node.op}{operand}"
        if isinstance(node, ast.CallExpr):
            args = ", ".join(self._expr(a) for a in node.args)
            return f"{self._postfix_base(node.callee)}({args})"
        if isinstance(node, ast.MemberExpr):
            return f"{self._postfix_base(node.obj)}.{node.name}"
        if isinstance(node, ast.IndexExpr):
            return f"{self._postfix_base(node.obj)}[{self._expr(node.index)}]"
        if isinstance(node, ast.ListLiteral):
            return "[" + ", ".join(self._expr(e) for e in node.elements) + "]"
        if isinstance(node, ast.StructLiteral):
            fields = ", ".join(
                f"{f.name}: {self._expr(f.value)}" for f in node.fields
            )
            return f"{node.type_name} {{ {fields} }}"
        if isinstance(node, ast.AwaitExpr):
            inner = self._expr(node.operand)
            if isinstance(node.operand, ast.BinaryOp):
                inner = f"({inner})"
            return f"await {inner}"
        if isinstance(node, ast.AiExpr):
            if node.prompt is not None:
                prompt = self._expr(node.prompt)
                if isinstance(node.prompt, ast.BinaryOp):
                    prompt = f"({prompt})"
                return f"ai {prompt}"
            return "ai { }"
        return ""  # pragma: no cover

    # -- precedence-aware helpers ---------------------------------------
    def _postfix_base(self, node: Optional[ast.Expr]) -> str:
        """Render the object of a call / member / index, parenthesised when
        printing it bare would re-associate (``(a + b).x``, ``(await f()).x``)."""
        text = self._expr(node)
        if isinstance(node, (ast.BinaryOp, ast.UnaryOp, ast.AwaitExpr, ast.AiExpr)):
            return f"({text})"
        return text

    def _binary(self, node: ast.BinaryOp) -> str:
        prec = _BINARY_PRECEDENCE.get(node.op, 0)
        right_assoc = node.op in _RIGHT_ASSOCIATIVE

        def operand(child: Optional[ast.Expr], is_left: bool) -> str:
            text = self._expr(child)
            if isinstance(child, ast.BinaryOp):
                cprec = _BINARY_PRECEDENCE.get(child.op, 0)
                if cprec < prec:
                    return f"({text})"
                if cprec == prec and (is_left == right_assoc):
                    # same precedence on the associativity-opposing side
                    return f"({text})"
            elif (
                isinstance(child, ast.UnaryOp)
                and is_left
                and node.op == "**"
                and child.op != "!"
            ):
                return f"({text})"  # `(-2) ** 2` differs from `-2 ** 2`
            return text

        left = operand(node.left, True)
        right = operand(node.right, False)
        return f"{left} {node.op} {right}"


# ---------------------------------------------------------------------------
# Literal helpers
# ---------------------------------------------------------------------------
def _quote(value: str) -> str:
    """Render a Happy string literal (double-quoted, minimal escaping)."""
    out = ['"']
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _escape_char(value: str) -> str:
    if value == "\\":
        return "\\\\"
    if value == "'":
        return "\\'"
    if value == "\n":
        return "\\n"
    if value == "\t":
        return "\\t"
    return value


def _format_float(value: float) -> str:
    """Render a float deterministically (always with a decimal point)."""
    text = repr(float(value))
    if "e" in text or "E" in text or "." in text:
        return text
    return text + ".0"


# ---------------------------------------------------------------------------
# Convenience API
# ---------------------------------------------------------------------------
def format_program(program: ast.Program) -> str:
    """Format an already-parsed :class:`~happy.compiler.ast.Program`."""
    return Formatter().format(program)


def format_source(source: str, filename: Optional[str] = None) -> FormatResult:
    """Parse and format ``source``; never raises on a parse error.

    On a parse error the original text is returned unchanged and ``ok`` is
    ``False`` with the :class:`~happy.compiler.errors.HappyError` attached.

    If the formatter meets a construct it cannot re-print faithfully, it
    returns the *original* text with ``unformattable=True`` so callers never
    overwrite a file with lossy output.
    """
    try:
        program = parse(source, filename=filename)
    except HappyError as exc:
        return FormatResult(
            original=source, formatted=source, filename=filename, ok=False, error=exc
        )
    formatter = Formatter()
    formatted = formatter.format(program)
    if formatter.unformattable:
        # Refuse to hand back lossy output: keep the original text intact.
        return FormatResult(
            original=source,
            formatted=source,
            filename=filename,
            ok=True,
            unformattable=True,
        )
    return FormatResult(
        original=source, formatted=formatted, filename=filename, ok=True
    )
