"""Language Server Protocol implementation for the Happy language (Step 6).

``happy lsp`` speaks LSP over stdio so any editor (VS Code, Neovim, Emacs,
Zed, …) gets first-class Happy support.  The server is a thin, deterministic
adapter over the existing compiler stages — it never re-implements analysis:

======================  =====================================================
LSP feature             Backed by
======================  =====================================================
``textDocument/         ``parse`` + ``analyze`` + ``lint_source``
  publishDiagnostics``
``textDocument/         declared symbols (types, enums, functions, agents,
  completion``          rules, capabilities, permissions) + keywords + builtins
``textDocument/hover``  the declaration's signature and contract clauses
``textDocument/         the declaration site of the symbol under the cursor
  definition``
``textDocument/         the module's top-level declarations
  documentSymbol``
======================  =====================================================

The transport is JSON-RPC 2.0 with ``Content-Length`` framing, exactly as the
LSP specification requires.  :class:`HappyLanguageServer` exposes a pure
:meth:`handle` method (message in, list of messages out) so the protocol logic
is unit-testable without a socket; :func:`serve_stdio` wires it to real stdio.

Typical use::

    from happy.tools.lsp import HappyLanguageServer

    server = HappyLanguageServer()
    out = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                         "params": {}})
"""

from __future__ import annotations

import io
import json
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..compiler import ast
from ..compiler.errors import HappyError, SourceLocation
from ..compiler.parser import parse
from ..compiler.semantic import analyze
from .lint import lint_source

__all__ = [
    "HappyLanguageServer",
    "serve_stdio",
    "DocumentStore",
    "to_lsp_diagnostic",
    "KEYWORDS",
    "BUILTIN_FUNCTIONS",
]

#: Completion keywords (the language's reserved words).
KEYWORDS: List[str] = [
    "app", "let", "var", "function", "type", "enum", "module", "import",
    "requires", "ensures", "invariant", "rule", "permission", "capability",
    "agent", "ai", "can", "cannot", "goal", "effects", "secret", "async",
    "await", "if", "else", "while", "for", "in", "return", "break",
    "continue", "as", "from", "true", "false", "null",
]

#: Builtin functions available without an import.
BUILTIN_FUNCTIONS: List[str] = [
    "print", "println", "eprint", "str", "int", "float", "bool", "len",
    "abs", "min", "max", "clamp", "panic", "assert", "typeof", "range",
    "read_file", "write_file", "append_file", "file_exists", "http_get",
    "http_post", "spawn", "gather", "sleep", "reveal", "secret",
]

#: Primitive type names.
PRIMITIVE_TYPES: List[str] = [
    "Int", "Float", "String", "Bool", "Byte", "Char", "Unit",
]


# ---------------------------------------------------------------------------
# Document store
# ---------------------------------------------------------------------------
class DocumentStore:
    """In-memory store of open documents, keyed by LSP URI."""

    def __init__(self) -> None:
        self._docs: Dict[str, str] = {}
        self._versions: Dict[str, int] = {}

    def open(self, uri: str, text: str, version: int = 1) -> None:
        self._docs[uri] = text
        self._versions[uri] = version

    def change(self, uri: str, text: str, version: int = 1) -> None:
        self._docs[uri] = text
        self._versions[uri] = version

    def close(self, uri: str) -> None:
        self._docs.pop(uri, None)
        self._versions.pop(uri, None)

    def get(self, uri: str) -> Optional[str]:
        return self._docs.get(uri)

    def version(self, uri: str) -> int:
        return self._versions.get(uri, 0)

    def uris(self) -> List[str]:
        return list(self._docs.keys())


# ---------------------------------------------------------------------------
# Position helpers
# ---------------------------------------------------------------------------
def _to_lsp_position(loc: Optional[SourceLocation]) -> Dict[str, int]:
    """Convert a 1-based Happy location to a 0-based LSP position."""
    if loc is None:
        return {"line": 0, "character": 0}
    return {"line": max(loc.line - 1, 0), "character": max(loc.column - 1, 0)}


def _to_lsp_range(start: Optional[SourceLocation], end: Optional[SourceLocation]) -> Dict[str, Any]:
    return {"start": _to_lsp_position(start), "end": _to_lsp_position(end or start)}


def to_lsp_diagnostic(
    message: str,
    severity: int,
    loc: Optional[SourceLocation],
    code: str = "",
    source: str = "happy",
) -> Dict[str, Any]:
    """Build an LSP ``Diagnostic`` object.

    ``severity`` follows the LSP enum: 1=Error, 2=Warning, 3=Information,
    4=Hint.
    """
    diag: Dict[str, Any] = {
        "range": _to_lsp_range(loc, loc),
        "severity": severity,
        "source": source,
        "message": message,
    }
    if code:
        diag["code"] = code
    return diag


_SEVERITY_MAP = {"error": 1, "warning": 2, "info": 3, "note": 4, "hint": 4}


# ---------------------------------------------------------------------------
# Symbol index (for completion / hover / definition)
# ---------------------------------------------------------------------------
@dataclass
class SymbolInfo:
    """A declared symbol and where it lives."""

    name: str
    kind: str  # type | enum | function | rule | permission | capability | agent | ai | app | variant | field
    loc: Optional[SourceLocation] = None
    detail: str = ""
    documentation: str = ""


def _index_program(program: ast.Program) -> Dict[str, SymbolInfo]:
    """Build a name -> :class:`SymbolInfo` index of a program's declarations."""
    index: Dict[str, SymbolInfo] = {}

    def add(info: SymbolInfo) -> None:
        index.setdefault(info.name, info)

    for decl in program.declarations:
        if isinstance(decl, ast.StructDecl):
            add(SymbolInfo(decl.name, "type", decl.loc, _struct_detail(decl)))
            for f in decl.fields:
                add(SymbolInfo(f.name, "field", f.loc, _field_detail(f)))
        elif isinstance(decl, ast.EnumDecl):
            add(SymbolInfo(decl.name, "enum", decl.loc, f"enum {decl.name}"))
            for v in decl.variants:
                add(SymbolInfo(v.name, "variant", v.loc, f"variant {v.name}"))
        elif isinstance(decl, ast.FunctionDecl):
            add(SymbolInfo(decl.name, "function", decl.loc, _function_detail(decl)))
        elif isinstance(decl, ast.RuleDecl):
            add(SymbolInfo(decl.name, "rule", decl.loc, f"rule {decl.name}"))
        elif isinstance(decl, ast.PermissionDecl):
            add(SymbolInfo(decl.name, "permission", decl.loc, f"permission {decl.name}"))
        elif isinstance(decl, ast.CapabilityDecl):
            add(SymbolInfo(decl.name, "capability", decl.loc, f"capability {decl.name}"))
        elif isinstance(decl, ast.AgentDecl):
            add(SymbolInfo(decl.name, "agent", decl.loc, f"agent {decl.name}"))
            if decl.body is not None:
                for stmt in decl.body.statements:
                    if isinstance(stmt, ast.FunctionDecl):
                        add(SymbolInfo(
                            stmt.name, "function", stmt.loc, _function_detail(stmt)
                        ))
        elif isinstance(decl, ast.AiDecl):
            add(SymbolInfo(decl.name, "ai", decl.loc, f"ai {decl.name}"))
        elif isinstance(decl, ast.AppDecl):
            add(SymbolInfo(decl.name, "app", decl.loc, f"app {decl.name}"))
    return index


def _type_text(node: Optional[ast.TypeNode]) -> str:
    if node is None:
        return "Unit"
    if isinstance(node, ast.PrimitiveType):
        return node.name
    if isinstance(node, ast.NamedType):
        return f"{node.module}.{node.name}" if node.module else node.name
    if isinstance(node, ast.GenericType):
        return f"{node.name}<{', '.join(_type_text(a) for a in node.args)}>"
    if isinstance(node, ast.FunctionType):
        return "(" + ", ".join(_type_text(p) for p in node.params) + ") -> " + _type_text(node.returns)
    if isinstance(node, ast.TupleType):
        return "(" + ", ".join(_type_text(e) for e in node.elements) + ")"
    if isinstance(node, ast.OptionalType):
        return f"{_type_text(node.inner)}?"
    return "Unit"


def _function_detail(fn: ast.FunctionDecl) -> str:
    prefix = "async " if fn.is_async else ""
    params = ", ".join(
        f"{p.name}: {_type_text(p.type_annotation)}" for p in fn.params
    )
    ret = f" -> {_type_text(fn.returns)}" if fn.returns is not None else ""
    return f"{prefix}function {fn.name}({params}){ret}"


def _struct_detail(decl: ast.StructDecl) -> str:
    return f"type {decl.name} {{ {len(decl.fields)} field(s) }}"


def _field_detail(f: ast.FieldDecl) -> str:
    prefix = "secret " if f.secret else ""
    return f"{prefix}{f.name}: {_type_text(f.type_annotation)}"


# ---------------------------------------------------------------------------
# The server
# ---------------------------------------------------------------------------
class HappyLanguageServer:
    """A pure, transport-agnostic Happy language server.

    :meth:`handle` takes one decoded JSON-RPC message and returns a list of
    messages to send back (responses and/or notifications).  This makes the
    whole protocol layer testable without stdio.
    """

    def __init__(self, name: str = "happy-lsp", version: str = "1.0.0") -> None:
        self.name = name
        self.version = version
        self.documents = DocumentStore()
        self.initialized = False
        self.shutdown_requested = False
        self._indexes: Dict[str, Dict[str, SymbolInfo]] = {}

    # -- JSON-RPC dispatch ---------------------------------------------
    def handle(self, message: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Dispatch one JSON-RPC message; return the messages to emit."""
        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}

        if method is None:
            return []  # a response to a server->client request; ignore

        handler = {
            "initialize": self._on_initialize,
            "initialized": self._on_initialized,
            "shutdown": self._on_shutdown,
            "exit": self._on_exit,
            "textDocument/didOpen": self._on_did_open,
            "textDocument/didChange": self._on_did_change,
            "textDocument/didClose": self._on_did_close,
            "textDocument/completion": self._on_completion,
            "textDocument/hover": self._on_hover,
            "textDocument/definition": self._on_definition,
            "textDocument/documentSymbol": self._on_document_symbol,
        }.get(method)

        if handler is None:
            if msg_id is not None:
                return [self._error(msg_id, -32601, f"method not found: {method}")]
            return []

        result = handler(params)
        if msg_id is None:
            # A notification: any notifications the handler produced are
            # returned directly (handlers return lists for notifications).
            return result if isinstance(result, list) else []
        return [self._result(msg_id, result)]

    # -- lifecycle ------------------------------------------------------
    def _on_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "capabilities": {
                "textDocumentSync": {
                    "openClose": True,
                    "change": 1,  # full document sync
                },
                "completionProvider": {"triggerCharacters": [".", ":"]},
                "hoverProvider": True,
                "definitionProvider": True,
                "documentSymbolProvider": True,
            },
            "serverInfo": {"name": self.name, "version": self.version},
        }

    def _on_initialized(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        self.initialized = True
        return []

    def _on_shutdown(self, params: Dict[str, Any]) -> None:
        self.shutdown_requested = True
        return None

    def _on_exit(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        return []

    # -- document sync --------------------------------------------------
    def _on_did_open(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        doc = params.get("textDocument", {})
        uri = doc.get("uri", "")
        text = doc.get("text", "")
        self.documents.open(uri, text, doc.get("version", 1))
        return [self._publish_diagnostics(uri)]

    def _on_did_change(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        doc = params.get("textDocument", {})
        uri = doc.get("uri", "")
        changes = params.get("contentChanges", [])
        text = changes[-1].get("text", "") if changes else self.documents.get(uri) or ""
        self.documents.change(uri, text, doc.get("version", 1))
        return [self._publish_diagnostics(uri)]

    def _on_did_close(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        uri = params.get("textDocument", {}).get("uri", "")
        self.documents.close(uri)
        self._indexes.pop(uri, None)
        return [{
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": {"uri": uri, "diagnostics": []},
        }]

    # -- diagnostics ----------------------------------------------------
    def _publish_diagnostics(self, uri: str) -> Dict[str, Any]:
        text = self.documents.get(uri) or ""
        diagnostics = self.compute_diagnostics(text, uri)
        return {
            "jsonrpc": "2.0",
            "method": "textDocument/publishDiagnostics",
            "params": {"uri": uri, "diagnostics": diagnostics},
        }

    def compute_diagnostics(self, text: str, uri: str = "") -> List[Dict[str, Any]]:
        """Run the compiler + linter and return LSP diagnostics."""
        diagnostics: List[Dict[str, Any]] = []
        try:
            program = parse(text, filename=uri)
        except HappyError as exc:
            diagnostics.append(
                to_lsp_diagnostic(exc.message, 1, exc.location, code="E0001")
            )
            return diagnostics

        # Semantic analysis (errors + warnings).
        analysis = analyze(program, filename=uri)
        for d in analysis.diagnostics:
            diagnostics.append(
                to_lsp_diagnostic(
                    d.message,
                    _SEVERITY_MAP.get(d.severity, 2),
                    getattr(d, "loc", None),
                    code=d.code,
                )
            )

        # Lint findings.
        report = lint_source(text, filename=uri)
        for f in report.findings:
            diagnostics.append(
                to_lsp_diagnostic(
                    f.message,
                    _SEVERITY_MAP.get(f.severity, 2),
                    f.location,
                    code=f.code,
                    source="happy-lint",
                )
            )
        return diagnostics

    # -- completion -----------------------------------------------------
    def _on_completion(self, params: Dict[str, Any]) -> Dict[str, Any]:
        uri = params.get("textDocument", {}).get("uri", "")
        text = self.documents.get(uri) or ""
        items: List[Dict[str, Any]] = []

        for kw in KEYWORDS:
            items.append({"label": kw, "kind": 14})  # 14 = Keyword
        for fn in BUILTIN_FUNCTIONS:
            items.append({"label": fn, "kind": 3, "detail": "builtin"})  # 3 = Function
        for t in PRIMITIVE_TYPES:
            items.append({"label": t, "kind": 25, "detail": "primitive type"})  # 25 = TypeParameter

        index = self._index(uri, text)
        kind_map = {
            "type": 22, "enum": 13, "function": 3, "rule": 3,
            "permission": 21, "capability": 21, "agent": 7, "ai": 7,
            "app": 2, "variant": 20, "field": 8,
        }
        for name, info in index.items():
            items.append({
                "label": name,
                "kind": kind_map.get(info.kind, 6),
                "detail": info.detail,
            })
        return {"isIncomplete": False, "items": items}

    # -- hover (contract hints) ----------------------------------------
    def _on_hover(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        uri = params.get("textDocument", {}).get("uri", "")
        text = self.documents.get(uri) or ""
        word = self._word_at(text, params.get("position", {}))
        if not word:
            return None
        index = self._index(uri, text)
        info = index.get(word)
        if info is None:
            return None
        contents = [f"```happy\n{info.detail}\n```"]
        # Contract hints: attach the declaration's contract clauses.
        hint = self._contract_hint(text, word)
        if hint:
            contents.append(hint)
        return {"contents": {"kind": "markdown", "value": "\n\n".join(contents)}}

    def _contract_hint(self, text: str, name: str) -> str:
        """Return a markdown list of the contract clauses on ``name``."""
        try:
            program = parse(text)
        except HappyError:
            return ""
        for decl in program.declarations:
            if getattr(decl, "name", None) == name and isinstance(
                decl, (ast.FunctionDecl, ast.StructDecl, ast.AgentDecl, ast.AiDecl)
            ):
                clauses = list(getattr(decl, "contracts", []) or [])
                clauses += list(getattr(decl, "invariants", []) or [])
                if not clauses:
                    return ""
                lines = ["**Contracts**"]
                for c in clauses:
                    msg = f" — {c.message}" if c.message else ""
                    lines.append(f"- `{c.kind}`{msg}")
                return "\n".join(lines)
        return ""

    # -- definition -----------------------------------------------------
    def _on_definition(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        uri = params.get("textDocument", {}).get("uri", "")
        text = self.documents.get(uri) or ""
        word = self._word_at(text, params.get("position", {}))
        if not word:
            return None
        index = self._index(uri, text)
        info = index.get(word)
        if info is None or info.loc is None:
            return None
        return {
            "uri": uri,
            "range": _to_lsp_range(info.loc, info.loc),
        }

    # -- document symbols ----------------------------------------------
    def _on_document_symbol(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        uri = params.get("textDocument", {}).get("uri", "")
        text = self.documents.get(uri) or ""
        try:
            program = parse(text)
        except HappyError:
            return []
        symbols: List[Dict[str, Any]] = []
        kind_map = {
            "type": 23, "enum": 10, "function": 12, "rule": 12,
            "permission": 5, "capability": 5, "agent": 5, "ai": 5, "app": 2,
        }
        for decl in program.declarations:
            name = getattr(decl, "name", None)
            if not name:
                continue
            kind = _decl_kind(decl)
            symbols.append({
                "name": name,
                "kind": kind_map.get(kind, 13),
                "range": _to_lsp_range(decl.loc, decl.loc),
                "selectionRange": _to_lsp_range(decl.loc, decl.loc),
            })
        return symbols

    # -- helpers --------------------------------------------------------
    def _index(self, uri: str, text: str) -> Dict[str, SymbolInfo]:
        cached = self._indexes.get(uri)
        if cached is not None:
            return cached
        try:
            program = parse(text)
        except HappyError:
            return {}
        index = _index_program(program)
        self._indexes[uri] = index
        return index

    @staticmethod
    def _word_at(text: str, position: Dict[str, int]) -> str:
        line_no = position.get("line", 0)
        char = position.get("character", 0)
        lines = text.splitlines()
        if not (0 <= line_no < len(lines)):
            return ""
        line = lines[line_no]
        if char > len(line):
            char = len(line)
        start = char
        while start > 0 and (line[start - 1].isalnum() or line[start - 1] == "_"):
            start -= 1
        end = char
        while end < len(line) and (line[end].isalnum() or line[end] == "_"):
            end += 1
        return line[start:end]

    # -- JSON-RPC envelopes --------------------------------------------
    @staticmethod
    def _result(msg_id: Any, result: Any) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _decl_kind(decl: ast.Decl) -> str:
    if isinstance(decl, ast.StructDecl):
        return "type"
    if isinstance(decl, ast.EnumDecl):
        return "enum"
    if isinstance(decl, ast.FunctionDecl):
        return "function"
    if isinstance(decl, ast.RuleDecl):
        return "rule"
    if isinstance(decl, ast.PermissionDecl):
        return "permission"
    if isinstance(decl, ast.CapabilityDecl):
        return "capability"
    if isinstance(decl, ast.AgentDecl):
        return "agent"
    if isinstance(decl, ast.AiDecl):
        return "ai"
    if isinstance(decl, ast.AppDecl):
        return "app"
    return "unknown"


# ---------------------------------------------------------------------------
# stdio transport
# ---------------------------------------------------------------------------
class ProtocolError(Exception):
    """A malformed frame or JSON body; the server must keep serving."""


def _read_message(stream: io.BufferedReader) -> Optional[Dict[str, Any]]:
    """Read one ``Content-Length``-framed JSON-RPC message from ``stream``.

    Returns ``None`` at end of stream.  A malformed frame or an invalid JSON
    body raises :class:`ProtocolError` (rather than crashing the server) so the
    caller can report a JSON-RPC parse error and continue reading.
    """
    headers: Dict[str, str] = {}
    while True:
        line = stream.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        try:
            key, _, value = line.decode("ascii").partition(":")
        except UnicodeDecodeError:
            raise ProtocolError("malformed header line") from None
        headers[key.strip().lower()] = value.strip()
    try:
        length = int(headers.get("content-length", "0") or 0)
    except ValueError:
        raise ProtocolError("invalid Content-Length header") from None
    if length <= 0:
        raise ProtocolError("missing or non-positive Content-Length")
    body = stream.read(length)
    if not body:
        return None
    try:
        message = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(f"invalid JSON body: {exc}") from None
    if not isinstance(message, dict):
        raise ProtocolError("JSON-RPC message must be an object")
    return message


def _write_message(stream: io.BufferedWriter, message: Dict[str, Any]) -> None:
    """Write one ``Content-Length``-framed JSON-RPC message to ``stream``."""
    body = json.dumps(message).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    stream.write(header)
    stream.write(body)
    stream.flush()


def serve_stdio(
    stdin: Optional[io.BufferedReader] = None,
    stdout: Optional[io.BufferedWriter] = None,
) -> int:
    """Run the LSP server over stdio until ``exit`` is received.

    Returns the process exit code (0 on a clean shutdown, 1 otherwise).
    """
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    server = HappyLanguageServer()
    while True:
        try:
            message = _read_message(stdin)
        except ProtocolError as exc:
            # A single bad message must not take the whole server down: report
            # a JSON-RPC parse error and keep serving the next message.
            _write_message(
                stdout,
                {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32700, "message": f"parse error: {exc}"}},
            )
            continue
        if message is None:
            break
        try:
            for out in server.handle(message):
                _write_message(stdout, out)
        except Exception as exc:  # noqa: BLE001 - never die on one message
            msg_id = message.get("id")
            if msg_id is not None:
                _write_message(
                    stdout,
                    {"jsonrpc": "2.0", "id": msg_id,
                     "error": {"code": -32603, "message": f"internal error: {exc}"}},
                )
        if message.get("method") == "exit":
            break
    return 0 if server.shutdown_requested else 1
