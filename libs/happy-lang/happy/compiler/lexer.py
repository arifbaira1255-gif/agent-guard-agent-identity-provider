"""Lexer for the Happy programming language (``.hpy``).

Converts raw source text into a flat stream of :class:`Token` objects.  Every
token records its exact start and end :class:`SourceLocation` so that later
stages (parser, type checker, ...) can produce precise diagnostics.

Supported lexical elements
--------------------------
* Primitive type keywords: ``Int``, ``Float``, ``String``, ``Bool``, ``Byte``,
  ``Char``, ``Unit``.
* Identifiers (Unicode-friendly, ``_``-separated).
* Integer literals (decimal, ``0x`` hex, ``0b`` binary, ``0o`` octal, ``_``
  digit separators) and float literals (fractional and/or exponent form).
* String literals (single-line and triple-quoted multi-line) and char literals.
* Boolean literals ``true`` / ``false``.
* Line comments ``// ...`` and nestable block comments ``/* ... */``.
* Operators and punctuation.
* Newlines are emitted as ``NEWLINE`` tokens (consecutive ones collapse) so the
  parser can use them as soft statement terminators.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from .errors import LexerError, SourceLocation

#: Unicode general categories that may *continue* an identifier but cannot
#: start one (combining marks used by Devanagari, Arabic, Thai, ... scripts).
_IDENT_CONTINUE_CATEGORIES = frozenset({"Mn", "Mc", "Nd", "Pc"})


def _is_ident_start(ch: str) -> bool:
    return ch.isalpha() or ch == "_"


def _is_ident_continue(ch: str) -> bool:
    if ch.isalnum() or ch == "_":
        return True
    return unicodedata.category(ch) in _IDENT_CONTINUE_CATEGORIES

__all__ = [
    "TokenKind",
    "Token",
    "Lexer",
    "tokenize",
    "KEYWORDS",
    "PRIMITIVE_TYPES",
]


class TokenKind(Enum):
    """The lexical category of a :class:`Token`."""

    INT = "INT"
    FLOAT = "FLOAT"
    STRING = "STRING"
    CHAR = "CHAR"
    BOOL = "BOOL"
    IDENT = "IDENT"
    PRIMITIVE_TYPE = "PRIMITIVE_TYPE"
    KEYWORD = "KEYWORD"
    OPERATOR = "OPERATOR"
    PUNCT = "PUNCT"
    NEWLINE = "NEWLINE"
    EOF = "EOF"


#: Reserved words of the Happy language.
KEYWORDS = frozenset(
    {
        "app",
        "let",
        "var",
        "function",
        "type",
        "enum",
        "module",
        "import",
        "requires",
        "ensures",
        "invariant",
        "rule",
        "permission",
        "capability",
        "agent",
        "ai",
        "can",
        "cannot",
        "goal",
        "effects",
        "secret",
        "async",
        "await",
        # traits / interfaces
        "trait",
        "impl",
        "export",
        "implements",
        # pattern matching
        "match",
        # control-flow / structural keywords used by the grammar
        "if",
        "else",
        "while",
        "for",
        "in",
        "return",
        "break",
        "continue",
        "as",
        "from",
        "true",
        "false",
        "null",
    }
)

#: Built-in primitive type names.
PRIMITIVE_TYPES = frozenset(
    {"Int", "Float", "String", "Bool", "Byte", "Char", "Unit"}
)

#: Boolean literal spellings.
BOOL_LITERALS = frozenset({"true", "false"})

#: Multi-character operators, longest first so greedy matching works.
_OPERATORS = [
    "**=",
    "<<=",
    ">>=",
    "...",
    "->",
    "=>",
    "==",
    "!=",
    "<=",
    ">=",
    "&&",
    "||",
    "<<",
    ">>",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "++",
    "--",
    "::",
    "**",
    "..",
    "+",
    "-",
    "*",
    "/",
    "%",
    "=",
    "<",
    ">",
    "!",
    "&",
    "|",
    "^",
    "~",
    "?",
    ".",
    ",",
    ":",
    ";",
    "@",
]

#: Bracketing punctuation.
_PUNCTUATION = ["(", ")", "{", "}", "[", "]"]

_SINGLE_CHAR_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "0": "\0",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "b": "\b",
    "f": "\f",
    "v": "\v",
}


@dataclass(frozen=True)
class Token:
    """A single lexical token with full positional information."""

    kind: TokenKind
    value: object
    lexeme: str
    loc: SourceLocation
    end_loc: SourceLocation

    @property
    def line(self) -> int:
        return self.loc.line

    @property
    def column(self) -> int:
        return self.loc.column

    def is_keyword(self, *names: str) -> bool:
        return self.kind is TokenKind.KEYWORD and self.value in names

    def is_operator(self, *ops: str) -> bool:
        return self.kind is TokenKind.OPERATOR and self.value in ops

    def is_punct(self, *chars: str) -> bool:
        return self.kind is TokenKind.PUNCT and self.value in chars

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"Token({self.kind.name}, {self.value!r}, "
            f"{self.loc.line}:{self.loc.column})"
        )


class Lexer:
    """Hand-written scanner for Happy source code."""

    def __init__(self, source: str, filename: Optional[str] = None) -> None:
        # Strip a leading UTF-8 BOM (U+FEFF) so BOM-prefixed files parse.
        if source.startswith("\ufeff"):
            source = source[1:]
        self.source = source
        self.filename = filename
        self._len = len(source)
        self._pos = 0
        self._line = 1
        self._col = 1
        self._tokens: List[Token] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def tokenize(self) -> List[Token]:
        """Scan the whole source and return the token list (ending in EOF)."""
        while not self._at_end():
            self._scan_token()

        eof_loc = self._loc()
        self._tokens.append(
            Token(TokenKind.EOF, None, "", eof_loc, eof_loc)
        )
        return self._tokens

    # ------------------------------------------------------------------
    # Character helpers
    # ------------------------------------------------------------------
    def _at_end(self) -> bool:
        return self._pos >= self._len

    def _peek(self, ahead: int = 0) -> str:
        idx = self._pos + ahead
        if idx >= self._len:
            return "\0"
        return self.source[idx]

    def _loc(self) -> SourceLocation:
        return SourceLocation(self._line, self._col, self._pos)

    def _advance(self) -> str:
        ch = self.source[self._pos]
        self._pos += 1
        if ch == "\n":
            self._line += 1
            self._col = 1
        else:
            self._col += 1
        return ch

    def _match(self, expected: str) -> bool:
        if self._at_end() or self.source[self._pos] != expected:
            return False
        self._advance()
        return True

    def _error(self, message: str, loc: Optional[SourceLocation] = None,
               suggestion: Optional[str] = None) -> LexerError:
        return LexerError(
            message,
            location=loc or self._loc(),
            source=self.source,
            suggestion=suggestion,
            filename=self.filename,
        )

    def _emit(self, kind: TokenKind, value: object, lexeme: str,
              start: SourceLocation) -> None:
        self._tokens.append(Token(kind, value, lexeme, start, self._loc()))

    # ------------------------------------------------------------------
    # Scanner
    # ------------------------------------------------------------------
    def _scan_token(self) -> None:
        ch = self._peek()

        # Whitespace (not newline).
        if ch in " \t\r\f\v":
            self._advance()
            return

        # Newlines -> NEWLINE token (collapse runs).
        if ch == "\n":
            start = self._loc()
            while self._peek() == "\n":
                self._advance()
            if not self._tokens or self._tokens[-1].kind is not TokenKind.NEWLINE:
                self._emit(TokenKind.NEWLINE, "\n", "\n", start)
            return

        # Comments.
        if ch == "/" and self._peek(1) == "/":
            self._skip_line_comment()
            return
        if ch == "/" and self._peek(1) == "*":
            self._skip_block_comment()
            return

        # String / char literals.
        if ch == '"':
            self._scan_string()
            return
        if ch == "'":
            self._scan_char()
            return

        # Numbers.
        if ch.isdigit():
            self._scan_number()
            return

        # Identifiers / keywords.
        if _is_ident_start(ch):
            self._scan_identifier()
            return

        # Operators and punctuation.
        if self._scan_operator_or_punct():
            return

        raise self._error(
            f"unexpected character {ch!r}",
            suggestion="remove the character or escape it inside a string literal",
        )

    # ------------------------------------------------------------------
    # Comments
    # ------------------------------------------------------------------
    def _skip_line_comment(self) -> None:
        while not self._at_end() and self._peek() != "\n":
            self._advance()

    def _skip_block_comment(self) -> None:
        start = self._loc()
        self._advance()  # '/'
        self._advance()  # '*'
        depth = 1
        while depth > 0:
            if self._at_end():
                raise self._error(
                    "unterminated block comment",
                    loc=start,
                    suggestion="close the comment with '*/'",
                )
            if self._peek() == "/" and self._peek(1) == "*":
                self._advance()
                self._advance()
                depth += 1
            elif self._peek() == "*" and self._peek(1) == "/":
                self._advance()
                self._advance()
                depth -= 1
            else:
                self._advance()

    # ------------------------------------------------------------------
    # Literals
    # ------------------------------------------------------------------
    def _scan_number(self) -> None:
        start = self._loc()
        start_pos = self._pos
        is_float = False

        if self._peek() == "0" and self._peek(1) in "xXbBoO":
            base_char = self._peek(1).lower()
            self._advance()
            self._advance()
            digits = {"x": "0123456789abcdefABCDEF_",
                      "b": "01_",
                      "o": "01234567_"}[base_char]
            if self._peek() not in digits:
                raise self._error(
                    f"malformed {base_char}-prefixed integer literal",
                    loc=start,
                    suggestion="add at least one digit after the base prefix",
                )
            while self._peek() in digits:
                self._advance()
            lexeme = self.source[start_pos:self._pos]
            value = int(lexeme.replace("_", ""), {"x": 16, "b": 2, "o": 8}[base_char])
            self._emit(TokenKind.INT, value, lexeme, start)
            return

        while self._peek().isdigit() or self._peek() == "_":
            self._advance()

        # Fractional part.
        if self._peek() == "." and self._peek(1).isdigit():
            is_float = True
            self._advance()
            while self._peek().isdigit() or self._peek() == "_":
                self._advance()

        # Exponent part.
        if self._peek() in "eE":
            nxt = self._peek(1)
            after = self._peek(2)
            if nxt.isdigit() or (nxt in "+-" and after.isdigit()):
                is_float = True
                self._advance()
                if self._peek() in "+-":
                    self._advance()
                while self._peek().isdigit() or self._peek() == "_":
                    self._advance()

        lexeme = self.source[start_pos:self._pos]
        clean = lexeme.replace("_", "")
        try:
            if is_float:
                fval = float(clean)
                if fval in (float("inf"), float("-inf")) or fval != fval:
                    # ``float("1e400")`` is ``inf`` rather than an error; an
                    # infinite literal cannot be generated as valid Python.
                    raise OverflowError(lexeme)
                self._emit(TokenKind.FLOAT, fval, lexeme, start)
            else:
                self._emit(TokenKind.INT, int(clean), lexeme, start)
        except (ValueError, OverflowError):
            raise self._error(
                "numeric literal is too large to represent",
                loc=start,
                suggestion="use a smaller literal, or split the value across "
                "several operations",
            ) from None

    def _scan_string(self) -> None:
        start = self._loc()
        start_pos = self._pos

        # Triple-quoted multi-line string.
        if self._peek(1) == '"' and self._peek(2) == '"':
            self._advance()
            self._advance()
            self._advance()
            chars: List[str] = []
            while True:
                if self._at_end():
                    raise self._error(
                        "unterminated multi-line string literal",
                        loc=start,
                        suggestion='close the string with """',
                    )
                if (self._peek() == '"' and self._peek(1) == '"'
                        and self._peek(2) == '"'):
                    self._advance()
                    self._advance()
                    self._advance()
                    break
                chars.append(self._advance())
            lexeme = self.source[start_pos:self._pos]
            self._emit(TokenKind.STRING, "".join(chars), lexeme, start)
            return

        self._advance()  # opening quote
        chars = []
        while True:
            if self._at_end() or self._peek() == "\n":
                raise self._error(
                    "unterminated string literal",
                    loc=start,
                    suggestion='close the string with a matching \'"\'',
                )
            ch = self._peek()
            if ch == '"':
                self._advance()
                break
            if ch == "\\":
                chars.append(self._scan_escape(start))
            else:
                chars.append(self._advance())
        lexeme = self.source[start_pos:self._pos]
        self._emit(TokenKind.STRING, "".join(chars), lexeme, start)

    def _scan_char(self) -> None:
        start = self._loc()
        start_pos = self._pos
        self._advance()  # opening quote

        if self._at_end() or self._peek() == "\n":
            raise self._error(
                "unterminated character literal",
                loc=start,
                suggestion="character literals look like 'a' or '\\n'",
            )

        if self._peek() == "\\":
            value = self._scan_escape(start)
        else:
            value = self._advance()

        if self._peek() != "'":
            raise self._error(
                "character literal must contain exactly one character",
                loc=start,
                suggestion="use a string literal \"...\" for multiple characters",
            )
        self._advance()  # closing quote
        lexeme = self.source[start_pos:self._pos]
        self._emit(TokenKind.CHAR, value, lexeme, start)

    def _scan_escape(self, start: SourceLocation) -> str:
        self._advance()  # backslash
        if self._at_end():
            raise self._error("unterminated escape sequence", loc=start)
        esc = self._advance()
        if esc in _SINGLE_CHAR_ESCAPES:
            return _SINGLE_CHAR_ESCAPES[esc]
        if esc == "u":
            return self._scan_unicode_escape(start)
        if esc == "x":
            return self._scan_hex_escape(start, 2)
        raise self._error(
            f"unknown escape sequence '\\{esc}'",
            loc=start,
            suggestion="valid escapes: \\n \\t \\r \\0 \\\\ \\' \\\" \\uXXXX",
        )

    def _scan_unicode_escape(self, start: SourceLocation) -> str:
        if self._peek() == "{":
            self._advance()
            digits = ""
            while self._peek() != "}" and not self._at_end():
                digits += self._advance()
            if self._peek() != "}":
                raise self._error("unterminated \\u{...} escape", loc=start)
            self._advance()
        else:
            digits = ""
            for _ in range(4):
                if not self._peek() or self._peek() in "\0":
                    raise self._error("incomplete \\uXXXX escape", loc=start)
                digits += self._advance()
        try:
            return chr(int(digits, 16))
        except ValueError:
            raise self._error(
                f"invalid unicode escape '\\u{digits}'", loc=start
            ) from None

    def _scan_hex_escape(self, start: SourceLocation, width: int) -> str:
        digits = ""
        for _ in range(width):
            if self._peek() == "\0":
                raise self._error("incomplete \\xXX escape", loc=start)
            digits += self._advance()
        try:
            return chr(int(digits, 16))
        except ValueError:
            raise self._error(
                f"invalid hex escape '\\x{digits}'", loc=start
            ) from None

    # ------------------------------------------------------------------
    # Identifiers / keywords
    # ------------------------------------------------------------------
    def _scan_identifier(self) -> None:
        start = self._loc()
        start_pos = self._pos
        while _is_ident_continue(self._peek()):
            self._advance()
        lexeme = self.source[start_pos:self._pos]

        if lexeme in PRIMITIVE_TYPES:
            self._emit(TokenKind.PRIMITIVE_TYPE, lexeme, lexeme, start)
        elif lexeme in BOOL_LITERALS:
            self._emit(TokenKind.BOOL, lexeme == "true", lexeme, start)
        elif lexeme in KEYWORDS:
            self._emit(TokenKind.KEYWORD, lexeme, lexeme, start)
        else:
            self._emit(TokenKind.IDENT, lexeme, lexeme, start)

    # ------------------------------------------------------------------
    # Operators / punctuation
    # ------------------------------------------------------------------
    def _scan_operator_or_punct(self) -> bool:
        start = self._loc()
        for op in _OPERATORS:
            if self.source.startswith(op, self._pos):
                for _ in range(len(op)):
                    self._advance()
                self._emit(TokenKind.OPERATOR, op, op, start)
                return True
        for punct in _PUNCTUATION:
            if self.source.startswith(punct, self._pos):
                self._advance()
                self._emit(TokenKind.PUNCT, punct, punct, start)
                return True
        return False


def tokenize(source: str, filename: Optional[str] = None) -> List[Token]:
    """Convenience wrapper: tokenize ``source`` and return the token list."""
    return Lexer(source, filename=filename).tokenize()
