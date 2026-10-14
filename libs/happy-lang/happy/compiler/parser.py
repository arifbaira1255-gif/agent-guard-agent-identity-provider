"""Deterministic recursive-descent parser for the Happy language.

Consumes the token stream produced by :mod:`happy.compiler.lexer` and builds the
AST defined in :mod:`happy.compiler.ast`.

Design notes
------------
* **Deterministic**: the grammar is LL(1)-friendly; every decision is made by
  looking at the current token (plus at most one token of lookahead).
* **Precise diagnostics**: every failure raises a :class:`ParseError` carrying
  the exact line/column, the offending source line, and a contextual
  suggestion (e.g. "did you mean 'function'?").
* **Newline handling**: newlines are soft statement terminators.  Statements
  may also be terminated by ``;``.  Blank lines are ignored.
"""

from __future__ import annotations

from typing import List, Optional

from . import ast
from .errors import ParseError, SourceLocation
from .lexer import Token, TokenKind, tokenize

__all__ = ["Parser", "parse"]


# Binary operator precedence (higher binds tighter).
_BINARY_PRECEDENCE = {
    "||": 1,
    "&&": 2,
    "==": 3,
    "!=": 3,
    "<": 4,
    "<=": 4,
    ">": 4,
    ">=": 4,
    "|": 5,
    "^": 6,
    "&": 7,
    "<<": 8,
    ">>": 8,
    "+": 9,
    "-": 9,
    "*": 10,
    "/": 10,
    "%": 10,
    "**": 11,
}

_RIGHT_ASSOCIATIVE = {"**"}

_ASSIGN_OPS = {"=", "+=", "-=", "*=", "/=", "%=", "**=", "<<=", ">>="}

# Keywords that may begin a top-level declaration.
_DECL_KEYWORDS = {
    "app",
    "type",
    "enum",
    "function",
    "rule",
    "permission",
    "capability",
    "agent",
    "ai",
    "module",
    "import",
    "trait",
    "impl",
    "export",
    "let",
    "var",
}

# Keywords that introduce a contract clause.
_CONTRACT_KEYWORDS = {"requires", "ensures", "invariant"}

# Keywords that may begin a statement.
_STMT_KEYWORDS = {
    "let",
    "var",
    "if",
    "while",
    "for",
    "return",
    "break",
    "continue",
    "match",
}

#: Maximum expression / block nesting depth before a clean diagnostic is raised.
#: Each nesting level costs several Python stack frames, so this is kept well
#: below the interpreter's recursion limit to guarantee a clean error.
_MAX_NESTING_DEPTH = 100


class Parser:
    """Recursive-descent parser turning tokens into an AST."""

    def __init__(
        self,
        tokens: List[Token],
        source: Optional[str] = None,
        filename: Optional[str] = None,
    ) -> None:
        self.tokens = tokens
        self.source = source
        self.filename = filename
        self._pos = 0
        # Guard against pathologically nested input (e.g. 200 nested parens)
        # so the parser reports a clean diagnostic instead of a RecursionError.
        self._depth = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def parse(self) -> ast.Program:
        """Parse the token stream into a :class:`~happy.compiler.ast.Program`."""
        program = ast.Program(loc=self._peek().loc)
        self._skip_newlines()

        # Optional leading module declaration.
        if self._check_keyword("module"):
            program.module = self._parse_module()
            self._skip_newlines()

        # Imports (may be interleaved with declarations in practice).
        while self._check_keyword("import"):
            program.imports.append(self._parse_import())
            self._skip_newlines()

        while not self._check(TokenKind.EOF):
            decl = self._parse_declaration()
            if decl is not None:
                program.declarations.append(decl)
            self._skip_newlines()

        return program

    # ------------------------------------------------------------------
    # Token helpers
    # ------------------------------------------------------------------
    def _peek(self, ahead: int = 0) -> Token:
        idx = self._pos + ahead
        if idx >= len(self.tokens):
            return self.tokens[-1]
        return self.tokens[idx]

    def _advance(self) -> Token:
        tok = self._peek()
        if tok.kind is not TokenKind.EOF:
            self._pos += 1
        return tok

    def _check(self, kind: TokenKind, value: object = None) -> bool:
        tok = self._peek()
        if tok.kind is not kind:
            return False
        return value is None or tok.value == value

    def _check_keyword(self, *names: str) -> bool:
        return self._peek().is_keyword(*names)

    def _check_operator(self, *ops: str) -> bool:
        return self._peek().is_operator(*ops)

    def _check_punct(self, *chars: str) -> bool:
        return self._peek().is_punct(*chars)

    def _match_keyword(self, *names: str) -> Optional[Token]:
        if self._check_keyword(*names):
            return self._advance()
        return None

    def _match_operator(self, *ops: str) -> Optional[Token]:
        if self._check_operator(*ops):
            return self._advance()
        return None

    def _match_punct(self, *chars: str) -> Optional[Token]:
        if self._check_punct(*chars):
            return self._advance()
        return None

    def _skip_newlines(self) -> None:
        while self._check(TokenKind.NEWLINE):
            self._advance()

    # ------------------------------------------------------------------
    # Error reporting
    # ------------------------------------------------------------------
    def _error(
        self,
        message: str,
        token: Optional[Token] = None,
        suggestion: Optional[str] = None,
    ) -> ParseError:
        tok = token or self._peek()
        return ParseError(
            message,
            location=tok.loc,
            source=self.source,
            suggestion=suggestion,
            filename=self.filename,
        )

    def _describe(self, tok: Token) -> str:
        if tok.kind is TokenKind.EOF:
            return "end of file"
        if tok.kind is TokenKind.NEWLINE:
            return "end of line"
        return f"'{tok.lexeme}'"

    def _suggest_for(self, tok: Token) -> Optional[str]:
        """Produce a contextual suggestion for an unexpected token."""
        if tok.kind is TokenKind.EOF:
            return "the file ended unexpectedly; check for an unclosed '{' or '('"
        if tok.kind is TokenKind.NEWLINE:
            return "unexpected end of line; the expression may be incomplete"
        if tok.kind is TokenKind.IDENT:
            # Common misspellings of keywords.
            near = {
                "func": "function",
                "fn": "function",
                "def": "function",
                "struct": "type",
                "class": "type",
                "permissions": "permission",
                "capabilities": "capability",
                "agents": "agent",
                "requires_": "requires",
            }
            if tok.value in near:
                return f"did you mean '{near[tok.value]}'?"
        return None

    def _expect(
        self,
        kind: TokenKind,
        value: object = None,
        what: Optional[str] = None,
    ) -> Token:
        tok = self._peek()
        if tok.kind is kind and (value is None or tok.value == value):
            return self._advance()
        expected = what or (repr(value) if value is not None else kind.name.lower())
        raise self._error(
            f"expected {expected} but found {self._describe(tok)}",
            token=tok,
            suggestion=self._suggest_for(tok),
        )

    def _expect_keyword(self, name: str) -> Token:
        return self._expect(TokenKind.KEYWORD, name, what=f"'{name}'")

    def _expect_ident(self, what: str = "an identifier") -> Token:
        tok = self._peek()
        if tok.kind is TokenKind.IDENT:
            return self._advance()
        raise self._error(
            f"expected {what} but found {self._describe(tok)}",
            token=tok,
            suggestion=self._suggest_for(tok),
        )

    def _expect_punct(self, char: str) -> Token:
        return self._expect(TokenKind.PUNCT, char, what=f"'{char}'")

    # ------------------------------------------------------------------
    # Statement terminators
    # ------------------------------------------------------------------
    def _consume_terminator(self) -> None:
        """Consume an optional ';' followed by a newline / '}' / EOF."""
        self._match_punct(";")
        if self._check(TokenKind.NEWLINE):
            self._skip_newlines()
            return
        if self._check_punct("}") or self._check(TokenKind.EOF):
            return
        tok = self._peek()
        raise self._error(
            f"expected end of statement but found {self._describe(tok)}",
            token=tok,
            suggestion="insert a newline or ';' to terminate the statement",
        )

    # ------------------------------------------------------------------
    # Declarations
    # ------------------------------------------------------------------
    def _parse_declaration(self) -> Optional[ast.Decl]:
        tok = self._peek()

        if tok.kind is TokenKind.KEYWORD:
            kw = tok.value
            if kw == "async" and self._peek(1).is_keyword("function"):
                return self._parse_function()
            if kw == "module":
                return self._parse_module()
            if kw == "import":
                return self._parse_import()
            if kw == "app":
                return self._parse_app()
            if kw == "type":
                return self._parse_struct()
            if kw == "enum":
                return self._parse_enum()
            if kw == "function":
                return self._parse_function()
            if kw == "rule":
                return self._parse_rule()
            if kw == "permission":
                return self._parse_permission()
            if kw == "capability":
                return self._parse_capability()
            if kw == "agent":
                return self._parse_agent()
            if kw == "ai":
                return self._parse_ai_decl()
            if kw == "trait":
                return self._parse_trait()
            if kw == "impl":
                return self._parse_impl()
            if kw == "export":
                return self._parse_export()
            if kw in ("let", "var"):
                return self._parse_const()

        raise self._error(
            f"expected a declaration but found {self._describe(tok)}",
            token=tok,
            suggestion=self._suggest_for(tok)
            or (
                "declarations start with one of: app, type, enum, function, "
                "async function, rule, permission, capability, agent, ai, "
                "trait, impl, module, import"
            ),
        )

    def _parse_module(self) -> ast.ModuleDecl:
        start = self._expect_keyword("module")
        name = self._parse_dotted_name()
        self._consume_terminator()
        return ast.ModuleDecl(name=name, loc=start.loc)

    def _parse_import(self) -> ast.ImportDecl:
        start = self._expect_keyword("import")

        # Form 1: import { a, b } from "module"
        if self._check_punct("{"):
            self._advance()
            symbols: List[str] = []
            self._skip_newlines()
            if not self._check_punct("}"):
                symbols.append(self._expect_ident("an imported symbol").value)
                while self._match_operator(","):
                    self._skip_newlines()
                    if self._check_punct("}"):
                        break
                    symbols.append(self._expect_ident("an imported symbol").value)
            self._expect_punct("}")
            self._expect_keyword("from")
            mod_tok = self._expect(TokenKind.STRING, what="a module path string")
            self._consume_terminator()
            return ast.ImportDecl(
                name=mod_tok.value, symbols=symbols, loc=start.loc
            )

        # Form 2: import a.b.c [as alias]  or  import a.b.c { x, y }
        name = self._parse_dotted_name()
        alias = None
        symbols: List[str] = []
        if self._check_punct("{"):
            self._advance()
            self._skip_newlines()
            if not self._check_punct("}"):
                symbols.append(self._expect_ident("an imported symbol").value)
                while self._match_operator(","):
                    self._skip_newlines()
                    if self._check_punct("}"):
                        break
                    symbols.append(self._expect_ident("an imported symbol").value)
            self._skip_newlines()
            self._expect_punct("}")
            self._consume_terminator()
            return ast.ImportDecl(name=name, symbols=symbols, loc=start.loc)
        if self._match_keyword("as"):
            alias = self._expect_ident("an import alias").value
        self._consume_terminator()
        return ast.ImportDecl(name=name, alias=alias, loc=start.loc)

    def _parse_const(self) -> ast.ConstDecl:
        start = self._peek()
        mutable = start.value == "var"
        self._advance()
        name = self._expect_ident("a name").value
        type_annotation = None
        if self._match_operator(":"):
            type_annotation = self._parse_type()
        value = None
        if self._match_operator("="):
            value = self._parse_expression()
        self._consume_terminator()
        return ast.ConstDecl(
            name=name,
            type_annotation=type_annotation,
            value=value,
            mutable=mutable,
            loc=start.loc,
        )

    def _parse_export(self) -> ast.ExportDecl:
        start = self._expect_keyword("export")
        names = [self._expect_ident("an exported name").value]
        while self._match_operator(","):
            self._skip_newlines()
            names.append(self._expect_ident("an exported name").value)
        self._consume_terminator()
        return ast.ExportDecl(names=names, loc=start.loc)

    def _parse_dotted_name(self) -> str:
        parts = [self._expect_ident("a name").value]
        while self._check_operator(".") and self._peek(1).kind is TokenKind.IDENT:
            self._advance()
            parts.append(self._advance().value)
        return ".".join(parts)

    def _parse_app(self) -> ast.AppDecl:
        start = self._expect_keyword("app")
        name = self._expect_ident("an app name").value
        contracts = self._parse_contracts()
        body = self._parse_block()
        return ast.AppDecl(name=name, body=body, contracts=contracts, loc=start.loc)

    def _parse_struct(self) -> ast.StructDecl:
        start = self._expect_keyword("type")
        name = self._expect_ident("a type name").value
        generics = self._parse_generic_params()
        implements: List[str] = []
        if self._match_keyword("implements"):
            implements.append(self._expect_ident("a trait name").value)
            while self._match_operator(","):
                implements.append(self._expect_ident("a trait name").value)
        self._expect_punct("{")
        self._skip_newlines()

        fields: List[ast.FieldDecl] = []
        invariants: List[ast.ContractClause] = []

        while not self._check_punct("}") and not self._check(TokenKind.EOF):
            if self._check_keyword("invariant"):
                invariants.append(self._parse_contract_clause())
                self._consume_terminator()
                continue
            fields.append(self._parse_field())
            self._consume_terminator()

        self._expect_punct("}")
        return ast.StructDecl(
            name=name,
            fields=fields,
            invariants=invariants,
            generics=generics,
            implements=implements,
            loc=start.loc,
        )

    def _parse_field(self) -> ast.FieldDecl:
        start = self._peek()
        secret = bool(self._match_keyword("secret"))
        name = self._expect_ident("a field name").value
        type_annotation = None
        default = None
        if self._match_operator(":"):
            type_annotation = self._parse_type()
        if self._match_operator("="):
            default = self._parse_expression()
        return ast.FieldDecl(
            name=name,
            type_annotation=type_annotation,
            default=default,
            secret=secret,
            loc=start.loc,
        )

    def _parse_enum(self) -> ast.EnumDecl:
        start = self._expect_keyword("enum")
        name = self._expect_ident("an enum name").value
        self._expect_punct("{")
        self._skip_newlines()

        variants: List[ast.EnumVariant] = []
        while not self._check_punct("}") and not self._check(TokenKind.EOF):
            vstart = self._peek()
            vname = self._expect_ident("a variant name").value
            payload: List[ast.TypeNode] = []
            if self._match_punct("("):
                if not self._check_punct(")"):
                    payload.append(self._parse_type())
                    while self._match_operator(","):
                        payload.append(self._parse_type())
                self._expect_punct(")")
            variants.append(ast.EnumVariant(name=vname, payload=payload, loc=vstart.loc))
            self._match_operator(",")
            self._consume_terminator()

        self._expect_punct("}")
        return ast.EnumDecl(name=name, variants=variants, loc=start.loc)

    def _parse_function(self) -> ast.FunctionDecl:
        start = self._peek()
        is_async = bool(self._match_keyword("async"))
        self._expect_keyword("function")
        name = self._expect_ident("a function name").value
        generics = self._parse_generic_params()
        params = self._parse_param_list()

        returns = None
        if self._match_operator("->"):
            returns = self._parse_type()

        contracts = self._parse_contracts()
        effects = self._parse_effects()

        body = None
        save = self._pos
        self._skip_newlines()
        if self._check_punct("{"):
            body = self._parse_block()
        else:
            self._pos = save
            self._consume_terminator()

        return ast.FunctionDecl(
            name=name,
            params=params,
            returns=returns,
            body=body,
            contracts=contracts,
            effects=effects,
            is_async=is_async,
            generics=generics,
            loc=start.loc,
        )

    def _parse_rule(self) -> ast.RuleDecl:
        start = self._expect_keyword("rule")
        name = self._expect_ident("a rule name").value

        params: List[ast.Param] = []
        if self._check_punct("("):
            params = self._parse_param_list()

        # Form: rule name: <condition>
        if self._match_operator(":"):
            condition = self._parse_expression()
            self._consume_terminator()
            return ast.RuleDecl(name=name, params=params, condition=condition, loc=start.loc)

        contracts = self._parse_contracts()
        body = self._parse_block()
        return ast.RuleDecl(
            name=name, params=params, body=body, contracts=contracts, loc=start.loc
        )

    def _parse_permission(self) -> ast.PermissionDecl:
        start = self._expect_keyword("permission")
        name = self._expect_ident("a permission name").value
        self._expect_punct("{")
        self._skip_newlines()

        can: List[str] = []
        cannot: List[str] = []
        while not self._check_punct("}") and not self._check(TokenKind.EOF):
            if self._match_keyword("can"):
                can.extend(self._parse_name_list())
            elif self._match_keyword("cannot"):
                cannot.extend(self._parse_name_list())
            else:
                tok = self._peek()
                raise self._error(
                    f"expected 'can' or 'cannot' but found {self._describe(tok)}",
                    token=tok,
                    suggestion="permission bodies contain 'can <action>' / 'cannot <action>'",
                )
            self._consume_terminator()

        self._expect_punct("}")
        return ast.PermissionDecl(name=name, can=can, cannot=cannot, loc=start.loc)

    def _parse_capability(self) -> ast.CapabilityDecl:
        start = self._expect_keyword("capability")
        name = self._expect_ident("a capability name").value
        self._expect_punct("{")
        self._skip_newlines()

        grants: List[str] = []
        while not self._check_punct("}") and not self._check(TokenKind.EOF):
            if self._match_keyword("can"):
                grants.extend(self._parse_name_list())
            elif self._check(TokenKind.IDENT) and self._peek().value == "grants":
                self._advance()
                grants.extend(self._parse_name_list())
            else:
                tok = self._peek()
                raise self._error(
                    f"expected 'grants' but found {self._describe(tok)}",
                    token=tok,
                    suggestion="capability bodies contain 'grants <name>'",
                )
            self._consume_terminator()

        self._expect_punct("}")
        return ast.CapabilityDecl(name=name, grants=grants, loc=start.loc)

    # ------------------------------------------------------------------
    # Traits / interfaces (Step 7)
    # ------------------------------------------------------------------
    def _parse_trait(self) -> ast.TraitDecl:
        start = self._expect_keyword("trait")
        name = self._expect_ident("a trait name").value
        self._expect_punct("{")
        self._skip_newlines()

        methods: List[ast.TraitMethod] = []
        while not self._check_punct("}") and not self._check(TokenKind.EOF):
            self._skip_newlines()
            if self._check_punct("}"):
                break
            mstart = self._peek()
            is_async = bool(self._match_keyword("async"))
            self._expect_keyword("function")
            mname = self._expect_ident("a method name").value
            params = self._parse_param_list()
            returns = None
            if self._match_operator("->"):
                returns = self._parse_type()
            contracts = self._parse_contracts()
            body = None
            save = self._pos
            self._skip_newlines()
            if self._check_punct("{"):
                body = self._parse_block()
            else:
                self._pos = save
            self._consume_terminator()
            methods.append(
                ast.TraitMethod(
                    name=mname,
                    params=params,
                    returns=returns,
                    contracts=contracts,
                    body=body,
                    loc=mstart.loc,
                )
            )

        self._expect_punct("}")
        return ast.TraitDecl(name=name, methods=methods, loc=start.loc)

    def _parse_impl(self) -> ast.ImplDecl:
        start = self._expect_keyword("impl")
        trait_name = self._expect_ident("a trait name").value
        self._expect_keyword("for")
        for_type = self._expect_ident("a type name").value
        self._expect_punct("{")
        self._skip_newlines()

        methods: List[ast.ImplMethod] = []
        while not self._check_punct("}") and not self._check(TokenKind.EOF):
            self._skip_newlines()
            if self._check_punct("}"):
                break
            mstart = self._peek()
            is_async = bool(self._match_keyword("async"))
            self._expect_keyword("function")
            mname = self._expect_ident("a method name").value
            params = self._parse_param_list()
            returns = None
            if self._match_operator("->"):
                returns = self._parse_type()
            contracts = self._parse_contracts()
            effects = self._parse_effects()
            body = None
            save = self._pos
            self._skip_newlines()
            if self._check_punct("{"):
                body = self._parse_block()
            else:
                self._pos = save
            self._consume_terminator()
            methods.append(
                ast.ImplMethod(
                    name=mname,
                    params=params,
                    returns=returns,
                    contracts=contracts,
                    effects=effects,
                    is_async=is_async,
                    body=body,
                    loc=mstart.loc,
                )
            )

        self._expect_punct("}")
        return ast.ImplDecl(
            name=trait_name, for_type=for_type, methods=methods, loc=start.loc
        )

    # ------------------------------------------------------------------
    # Pattern matching (Step 7)
    # ------------------------------------------------------------------
    def _parse_match(self) -> ast.MatchStmt:
        start = self._expect_keyword("match")
        subject = self._parse_expression()
        self._expect_punct("{")
        self._skip_newlines()

        arms: List[ast.MatchArm] = []
        while not self._check_punct("}") and not self._check(TokenKind.EOF):
            self._skip_newlines()
            if self._check_punct("}"):
                break
            astart = self._peek()
            pattern = self._parse_pattern()
            self._expect_operator("->")
            self._skip_newlines()
            bare = not self._check_punct("{")
            body = self._parse_match_arm_body()
            arms.append(
                ast.MatchArm(pattern=pattern, body=body, loc=astart.loc, bare_expr=bare)
            )
            self._match_operator(",")
            self._skip_newlines()

        self._expect_punct("}")
        # A `match` used as a statement is terminated like any other statement.
        self._consume_terminator()
        return ast.MatchStmt(subject=subject, arms=arms, loc=start.loc)

    def _parse_match_arm_body(self) -> ast.Block:
        """Parse the body of a match arm: either ``{ ... }`` or a statement."""
        self._skip_newlines()
        if self._check_punct("{"):
            return self._parse_block()
        stmt = self._parse_statement()
        return ast.Block(statements=[stmt], loc=stmt.loc)

    def _parse_pattern(self) -> ast.MatchPattern:
        first = self._parse_pattern_alt()
        if not self._match_operator("|"):
            return first
        patterns = [first]
        patterns.append(self._parse_pattern_alt())
        while self._match_operator("|"):
            patterns.append(self._parse_pattern_alt())
        return ast.MatchPattern(kind="or", patterns=patterns, loc=first.loc)

    def _parse_pattern_alt(self) -> ast.MatchPattern:
        tok = self._peek()

        # Wildcard
        if tok.kind is TokenKind.IDENT and tok.value == "_":
            self._advance()
            return ast.MatchPattern(kind="wildcard", name="_", loc=tok.loc)

        # Literal patterns
        if tok.kind is TokenKind.INT:
            self._advance()
            return ast.MatchPattern(
                kind="literal", value=ast.IntLiteral(value=tok.value, loc=tok.loc), loc=tok.loc
            )
        if tok.kind is TokenKind.FLOAT:
            self._advance()
            return ast.MatchPattern(
                kind="literal", value=ast.FloatLiteral(value=tok.value, loc=tok.loc), loc=tok.loc
            )
        if tok.kind is TokenKind.STRING:
            self._advance()
            return ast.MatchPattern(
                kind="literal", value=ast.StringLiteral(value=tok.value, loc=tok.loc), loc=tok.loc
            )
        if tok.kind is TokenKind.CHAR:
            self._advance()
            return ast.MatchPattern(
                kind="literal", value=ast.CharLiteral(value=tok.value, loc=tok.loc), loc=tok.loc
            )
        if tok.kind is TokenKind.BOOL:
            self._advance()
            return ast.MatchPattern(
                kind="literal", value=ast.BoolLiteral(value=tok.value, loc=tok.loc), loc=tok.loc
            )

        # Variant / binding / struct pattern
        if tok.kind is TokenKind.IDENT:
            self._advance()
            name = tok.value

            # Struct pattern: `Type { a, b }`
            if name[:1].isupper() and self._check_punct("{"):
                self._advance()
                self._skip_newlines()
                bindings: List[str] = []
                while not self._check_punct("}") and not self._check(TokenKind.EOF):
                    bindings.append(self._expect_ident("a field name").value)
                    if not self._match_operator(","):
                        break
                    self._skip_newlines()
                self._skip_newlines()
                self._expect_punct("}")
                return ast.MatchPattern(
                    kind="struct", name=name, bindings=bindings, loc=tok.loc
                )

            # Variant with payload: `Variant(a, b)`
            if name[:1].isupper() and self._check_punct("("):
                self._advance()
                self._skip_newlines()
                bindings = []
                if not self._check_punct(")"):
                    bindings.append(self._expect_ident("a binding name").value)
                    while self._match_operator(","):
                        self._skip_newlines()
                        if self._check_punct(")"):
                            break
                        bindings.append(self._expect_ident("a binding name").value)
                self._skip_newlines()
                self._expect_punct(")")
                return ast.MatchPattern(
                    kind="variant", name=name, bindings=bindings, loc=tok.loc
                )

            # Bare capitalised name => nullary variant; lowercase => binding.
            if name[:1].isupper():
                return ast.MatchPattern(kind="variant", name=name, loc=tok.loc)
            return ast.MatchPattern(kind="binding", name=name, loc=tok.loc)

        raise self._error(
            f"expected a match pattern but found {self._describe(tok)}",
            token=tok,
            suggestion=(
                "patterns are `_`, a binding name, a variant (`Some(x)`), a "
                "struct (`Point { x }`) or a literal"
            ),
        )

    def _parse_agent(self) -> ast.AgentDecl:
        start = self._expect_keyword("agent")
        name = self._expect_ident("an agent name").value
        self._expect_punct("{")
        self._skip_newlines()

        goal = None
        permissions: List[str] = []
        capabilities: List[str] = []
        effects = None
        contracts: List[ast.ContractClause] = []
        body_stmts: List[ast.Stmt] = []

        while not self._check_punct("}") and not self._check(TokenKind.EOF):
            self._skip_newlines()
            if self._check_punct("}"):
                break
            if self._check_keyword("goal"):
                self._advance()
                goal = self._parse_expression()
                self._consume_terminator()
            elif self._check_keyword("permission") and self._peek(1).is_punct("["):
                self._advance()
                permissions.extend(self._parse_bracket_name_list())
                self._consume_terminator()
            elif self._check_keyword("capability") and self._peek(1).is_punct("["):
                self._advance()
                capabilities.extend(self._parse_bracket_name_list())
                self._consume_terminator()
            elif self._check_keyword("effects"):
                effects = self._parse_effects()
            elif self._check_keyword(*_CONTRACT_KEYWORDS):
                contracts.append(self._parse_contract_clause())
                self._consume_terminator()
            elif self._check_keyword("function"):
                body_stmts.append(ast.ExprStmt(expr=None, loc=self._peek().loc))
                # Nested function declarations are stored as declarations.
                decl = self._parse_function()
                body_stmts[-1] = decl  # type: ignore[assignment]
                self._skip_newlines()
            else:
                body_stmts.append(self._parse_statement())

        self._expect_punct("}")
        body = ast.Block(statements=body_stmts, loc=start.loc) if body_stmts else None
        return ast.AgentDecl(
            name=name,
            goal=goal,
            permissions=permissions,
            capabilities=capabilities,
            effects=effects,
            body=body,
            contracts=contracts,
            loc=start.loc,
        )

    def _parse_ai_decl(self) -> ast.AiDecl:
        start = self._expect_keyword("ai")
        name = self._expect_ident("an ai block name").value
        self._expect_punct("{")
        self._skip_newlines()

        prompt = None
        goal = None
        contracts: List[ast.ContractClause] = []
        body_stmts: List[ast.Stmt] = []

        while not self._check_punct("}") and not self._check(TokenKind.EOF):
            self._skip_newlines()
            if self._check_punct("}"):
                break
            if self._check(TokenKind.IDENT, "prompt"):
                self._advance()
                prompt = self._parse_expression()
                self._consume_terminator()
            elif self._check_keyword("goal"):
                self._advance()
                goal = self._parse_expression()
                self._consume_terminator()
            elif self._check_keyword(*_CONTRACT_KEYWORDS):
                contracts.append(self._parse_contract_clause())
                self._consume_terminator()
            else:
                body_stmts.append(self._parse_statement())

        self._expect_punct("}")
        body = ast.Block(statements=body_stmts, loc=start.loc) if body_stmts else None
        return ast.AiDecl(
            name=name, prompt=prompt, goal=goal, body=body, contracts=contracts, loc=start.loc
        )

    # ------------------------------------------------------------------
    # Shared declaration pieces
    # ------------------------------------------------------------------
    def _parse_generic_params(self) -> List[str]:
        params: List[str] = []
        if self._check_operator("<"):
            self._advance()
            params.append(self._expect_ident("a type parameter").value)
            while self._match_operator(","):
                params.append(self._expect_ident("a type parameter").value)
            self._expect_operator(">")
        return params

    def _expect_operator(self, op: str) -> Token:
        return self._expect(TokenKind.OPERATOR, op, what=f"'{op}'")

    def _parse_param_list(self) -> List[ast.Param]:
        self._expect_punct("(")
        self._skip_newlines()
        params: List[ast.Param] = []
        if not self._check_punct(")"):
            params.append(self._parse_param())
            while self._match_operator(","):
                self._skip_newlines()
                if self._check_punct(")"):
                    break
                params.append(self._parse_param())
        self._skip_newlines()
        self._expect_punct(")")
        return params

    def _parse_param(self) -> ast.Param:
        start = self._peek()
        name = self._expect_ident("a parameter name").value
        type_annotation = None
        default = None
        if self._match_operator(":"):
            type_annotation = self._parse_type()
        if self._match_operator("="):
            default = self._parse_expression()
        return ast.Param(
            name=name, type_annotation=type_annotation, default=default, loc=start.loc
        )

    def _parse_contracts(self) -> List[ast.ContractClause]:
        clauses: List[ast.ContractClause] = []
        while True:
            save = self._pos
            self._skip_newlines()
            if self._check_keyword(*_CONTRACT_KEYWORDS):
                clauses.append(self._parse_contract_clause())
                # A contract clause may be followed by the declaration body on
                # the same line (`function f() requires x > 0 { ... }`), so a
                # `{` terminates the clause list without a newline.
                if self._check_punct("{"):
                    break
                self._consume_terminator()
            else:
                self._pos = save
                break
        return clauses

    def _parse_contract_clause(self) -> ast.ContractClause:
        start = self._advance()  # requires / ensures / invariant
        kind = start.value
        condition = self._parse_expression()
        message = None
        # Optional message: `requires x > 0, "x must be positive"`
        if self._match_operator(","):
            msg_tok = self._expect(TokenKind.STRING, what="a contract message string")
            message = msg_tok.value
        return ast.ContractClause(
            kind=kind, condition=condition, message=message, loc=start.loc
        )

    def _parse_effects(self) -> Optional[ast.EffectSpec]:
        save = self._pos
        self._skip_newlines()
        if not self._check_keyword("effects"):
            self._pos = save
            return None
        start = self._advance()
        effects: List[str] = []
        if self._match_punct("["):
            self._skip_newlines()
            if not self._check_punct("]"):
                effects.append(self._expect_ident("an effect name").value)
                while self._match_operator(","):
                    self._skip_newlines()
                    if self._check_punct("]"):
                        break
                    effects.append(self._expect_ident("an effect name").value)
            self._skip_newlines()
            self._expect_punct("]")
        else:
            effects.extend(self._parse_name_list())
        return ast.EffectSpec(effects=effects, loc=start.loc)

    def _parse_name_list(self) -> List[str]:
        names = [self._expect_ident("a name").value]
        while self._match_operator(","):
            names.append(self._expect_ident("a name").value)
        return names

    def _parse_bracket_name_list(self) -> List[str]:
        self._expect_punct("[")
        self._skip_newlines()
        names: List[str] = []
        if not self._check_punct("]"):
            names.append(self._expect_ident("a name").value)
            while self._match_operator(","):
                self._skip_newlines()
                if self._check_punct("]"):
                    break
                names.append(self._expect_ident("a name").value)
        self._skip_newlines()
        self._expect_punct("]")
        return names

    # ------------------------------------------------------------------
    # Types
    # ------------------------------------------------------------------
    def _parse_type(self) -> ast.TypeNode:
        tok = self._peek()

        if tok.kind is TokenKind.PRIMITIVE_TYPE:
            self._advance()
            base: ast.TypeNode = ast.PrimitiveType(name=tok.value, loc=tok.loc)
        elif tok.kind is TokenKind.IDENT:
            self._advance()
            name = tok.value
            module = None
            while self._check_operator("::"):
                self._advance()
                module = name
                name = self._expect_ident("a type name").value
            if self._check_operator("<"):
                self._advance()
                args = [self._parse_type()]
                while self._match_operator(","):
                    args.append(self._parse_type())
                self._expect_operator(">")
                base = ast.GenericType(name=name, args=args, loc=tok.loc)
            else:
                base = ast.NamedType(name=name, module=module, loc=tok.loc)
        elif tok.is_punct("("):
            self._advance()
            elements = [self._parse_type()]
            while self._match_operator(","):
                elements.append(self._parse_type())
            self._expect_punct(")")
            if self._match_operator("->"):
                returns = self._parse_type()
                base = ast.FunctionType(
                    params=elements, returns=returns, loc=tok.loc
                )
            else:
                base = ast.TupleType(elements=elements, loc=tok.loc)
        elif tok.is_punct("["):
            self._advance()
            inner = self._parse_type()
            self._expect_punct("]")
            base = ast.GenericType(name="List", args=[inner], loc=tok.loc)
        else:
            raise self._error(
                f"expected a type but found {self._describe(tok)}",
                token=tok,
                suggestion=(
                    "types are primitive (Int, Float, String, Bool, Byte, Char, "
                    "Unit) or named types"
                ),
            )

        # Optional suffix: `T?`
        while self._check_operator("?"):
            self._advance()
            base = ast.OptionalType(inner=base, loc=tok.loc)

        return base

    # ------------------------------------------------------------------
    # Statements
    # ------------------------------------------------------------------
    def _parse_block(self) -> ast.Block:
        self._enter()
        try:
            start = self._expect_punct("{")
            self._skip_newlines()
            statements: List[ast.Stmt] = []
            while not self._check_punct("}") and not self._check(TokenKind.EOF):
                statements.append(self._parse_statement())
                self._skip_newlines()
            self._expect_punct("}")
            return ast.Block(statements=statements, loc=start.loc)
        finally:
            self._depth -= 1

    def _parse_statement(self) -> ast.Stmt:
        self._skip_newlines()
        tok = self._peek()

        if tok.kind is TokenKind.KEYWORD:
            kw = tok.value
            if kw in ("let", "var"):
                return self._parse_let()
            if kw == "if":
                return self._parse_if()
            if kw == "while":
                return self._parse_while()
            if kw == "for":
                return self._parse_for()
            if kw == "match":
                return self._parse_match()
            if kw == "return":
                return self._parse_return()
            if kw == "break":
                self._advance()
                self._consume_terminator()
                return ast.BreakStmt(loc=tok.loc)
            if kw == "continue":
                self._advance()
                self._consume_terminator()
                return ast.ContinueStmt(loc=tok.loc)

        if tok.is_punct("{"):
            block = self._parse_block()
            return ast.ExprStmt(expr=None, loc=block.loc) if False else block  # type: ignore[return-value]

        return self._parse_simple_statement()

    def _parse_let(self) -> ast.LetStmt:
        start = self._advance()  # let / var
        mutable = start.value == "var"
        name = self._expect_ident("a variable name").value
        type_annotation = None
        value = None
        if self._match_operator(":"):
            type_annotation = self._parse_type()
        if self._match_operator("="):
            value = self._parse_expression()
        self._consume_terminator()
        return ast.LetStmt(
            name=name,
            type_annotation=type_annotation,
            value=value,
            mutable=mutable,
            loc=start.loc,
        )

    def _parse_if(self) -> ast.IfStmt:
        start = self._expect_keyword("if")
        condition = self._parse_expression()
        then_branch = self._parse_block()
        else_branch = None
        # Allow `else` on the same or next line.
        save = self._pos
        self._skip_newlines()
        if self._match_keyword("else"):
            if self._check_keyword("if"):
                else_branch = self._parse_if()
            else:
                else_branch = self._parse_block()
        else:
            self._pos = save
        return ast.IfStmt(
            condition=condition,
            then_branch=then_branch,
            else_branch=else_branch,
            loc=start.loc,
        )

    def _parse_while(self) -> ast.WhileStmt:
        start = self._expect_keyword("while")
        condition = self._parse_expression()
        body = self._parse_block()
        return ast.WhileStmt(condition=condition, body=body, loc=start.loc)

    def _parse_for(self) -> ast.ForStmt:
        start = self._expect_keyword("for")
        variable = self._expect_ident("a loop variable").value
        self._expect_keyword("in")
        iterable = self._parse_expression()
        body = self._parse_block()
        return ast.ForStmt(variable=variable, iterable=iterable, body=body, loc=start.loc)

    def _parse_return(self) -> ast.ReturnStmt:
        start = self._expect_keyword("return")
        value = None
        if not self._check(TokenKind.NEWLINE) and not self._check_punct(";") \
                and not self._check_punct("}") and not self._check(TokenKind.EOF):
            value = self._parse_expression()
        self._consume_terminator()
        return ast.ReturnStmt(value=value, loc=start.loc)

    def _parse_simple_statement(self) -> ast.Stmt:
        start = self._peek()
        expr = self._parse_expression()

        if self._check_operator(*_ASSIGN_OPS):
            op = self._advance().value
            value = self._parse_expression()
            self._consume_terminator()
            return ast.AssignStmt(target=expr, op=op, value=value, loc=start.loc)

        self._consume_terminator()
        return ast.ExprStmt(expr=expr, loc=start.loc)

    # ------------------------------------------------------------------
    # Expressions
    # ------------------------------------------------------------------
    def _parse_expression(self) -> ast.Expr:
        self._enter()
        try:
            return self._parse_binary(1)
        finally:
            self._depth -= 1

    def _enter(self) -> None:
        """Track nesting depth; raise a clean error past the limit."""
        self._depth += 1
        if self._depth > _MAX_NESTING_DEPTH:
            tok = self._peek()
            raise self._error(
                "expression or block nesting is too deep",
                token=tok,
                suggestion=(
                    f"the parser supports at most {_MAX_NESTING_DEPTH} levels "
                    "of nesting; simplify the expression"
                ),
            )

    def _parse_binary(self, min_prec: int) -> ast.Expr:
        left = self._parse_unary()

        while True:
            tok = self._peek()
            if tok.kind is not TokenKind.OPERATOR:
                break
            op = tok.value
            prec = _BINARY_PRECEDENCE.get(op)
            if prec is None or prec < min_prec:
                break
            self._advance()
            next_min = prec if op in _RIGHT_ASSOCIATIVE else prec + 1
            right = self._parse_binary(next_min)
            left = ast.BinaryOp(op=op, left=left, right=right, loc=tok.loc)

        return left

    def _parse_unary(self) -> ast.Expr:
        tok = self._peek()

        if tok.is_operator("!", "-", "+", "~"):
            self._advance()
            if tok.value == "!":
                operand = self._parse_unary()
            else:
                # Arithmetic prefix operators bind looser than `**`, so that
                # `-2 ** 2` is `-(2 ** 2)` == -4 (as in Python and maths).
                operand = self._parse_binary(_BINARY_PRECEDENCE["**"])
            return ast.UnaryOp(op=tok.value, operand=operand, loc=tok.loc)

        if tok.is_keyword("await"):
            self._advance()
            operand = self._parse_unary()
            return ast.AwaitExpr(operand=operand, loc=tok.loc)

        return self._parse_postfix()

    def _parse_postfix(self) -> ast.Expr:
        expr = self._parse_primary()

        while True:
            tok = self._peek()
            if tok.is_punct("("):
                self._advance()
                self._skip_newlines()
                args: List[ast.Expr] = []
                if not self._check_punct(")"):
                    args.append(self._parse_expression())
                    while self._match_operator(","):
                        self._skip_newlines()
                        if self._check_punct(")"):
                            break
                        args.append(self._parse_expression())
                self._skip_newlines()
                self._expect_punct(")")
                expr = ast.CallExpr(callee=expr, args=args, loc=tok.loc)
            elif tok.is_operator("."):
                self._advance()
                name = self._expect_ident("a member name").value
                expr = ast.MemberExpr(obj=expr, name=name, loc=tok.loc)
            elif tok.is_punct("["):
                self._advance()
                index = self._parse_expression()
                self._expect_punct("]")
                expr = ast.IndexExpr(obj=expr, index=index, loc=tok.loc)
            else:
                break

        return expr

    def _parse_primary(self) -> ast.Expr:
        tok = self._peek()

        if tok.kind is TokenKind.INT:
            self._advance()
            return ast.IntLiteral(value=tok.value, loc=tok.loc)
        if tok.kind is TokenKind.FLOAT:
            self._advance()
            return ast.FloatLiteral(value=tok.value, loc=tok.loc)
        if tok.kind is TokenKind.STRING:
            self._advance()
            return ast.StringLiteral(value=tok.value, loc=tok.loc)
        if tok.kind is TokenKind.CHAR:
            self._advance()
            return ast.CharLiteral(value=tok.value, loc=tok.loc)
        if tok.kind is TokenKind.BOOL:
            self._advance()
            return ast.BoolLiteral(value=tok.value, loc=tok.loc)
        if tok.is_keyword("null"):
            self._advance()
            return ast.NullLiteral(loc=tok.loc)
        if tok.kind is TokenKind.IDENT:
            self._advance()
            # Struct literal: `TypeName { field: value, ... }` — disambiguated
            # from a block by requiring a capitalised type name.
            if (tok.value[:1].isupper() and self._check_punct("{")
                    and self._looks_like_struct_literal()):
                return self._parse_struct_literal(tok)
            return ast.Identifier(name=tok.value, loc=tok.loc)

        if tok.is_punct("("):
            self._advance()
            self._skip_newlines()
            expr = self._parse_expression()
            self._skip_newlines()
            self._expect_punct(")")
            return expr

        if tok.is_punct("["):
            self._advance()
            self._skip_newlines()
            elements: List[ast.Expr] = []
            if not self._check_punct("]"):
                elements.append(self._parse_expression())
                while self._match_operator(","):
                    self._skip_newlines()
                    if self._check_punct("]"):
                        break
                    elements.append(self._parse_expression())
            self._skip_newlines()
            self._expect_punct("]")
            return ast.ListLiteral(elements=elements, loc=tok.loc)

        if tok.is_keyword("ai"):
            self._advance()
            if self._check_punct("{"):
                body = self._parse_block()
                return ast.AiExpr(body=body, loc=tok.loc)
            prompt = self._parse_expression()
            return ast.AiExpr(prompt=prompt, loc=tok.loc)

        raise self._error(
            f"expected an expression but found {self._describe(tok)}",
            token=tok,
            suggestion=self._suggest_for(tok),
        )

    def _looks_like_struct_literal(self) -> bool:
        """Return True if the ``{`` at the cursor opens a struct literal.

        A struct literal looks like ``{ ident : ... }`` or ``{ }``; a block
        starts with a statement keyword or an expression, so the presence of a
        ``:`` right after the first identifier is the deciding signal.
        """
        if not self._check_punct("{"):
            return False
        nxt = self._peek(1)
        if nxt.is_punct("}"):
            return True
        if nxt.kind is TokenKind.IDENT and self._peek(2).is_operator(":"):
            return True
        return False

    def _parse_struct_literal(self, type_tok: Token) -> ast.StructLiteral:
        self._expect_punct("{")
        self._skip_newlines()
        fields: List[ast.FieldInit] = []
        while not self._check_punct("}") and not self._check(TokenKind.EOF):
            fstart = self._peek()
            fname = self._expect_ident("a field name").value
            self._expect_operator(":")
            value = self._parse_expression()
            fields.append(ast.FieldInit(name=fname, value=value, loc=fstart.loc))
            if not self._match_operator(","):
                break
            self._skip_newlines()
        self._skip_newlines()
        self._expect_punct("}")
        return ast.StructLiteral(
            type_name=type_tok.value, fields=fields, loc=type_tok.loc
        )


def parse(source: str, filename: Optional[str] = None) -> ast.Program:
    """Tokenize and parse ``source`` into a :class:`~happy.compiler.ast.Program`."""
    tokens = tokenize(source, filename=filename)
    return Parser(tokens, source=source, filename=filename).parse()
