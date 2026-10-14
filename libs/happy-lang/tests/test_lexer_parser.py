"""Unit tests for the Happy compiler lexer and parser.

Run with::

    python -m pytest tests/test_lexer_parser.py -v
    # or, without pytest:
    python tests/test_lexer_parser.py
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.compiler import ast, parse, tokenize  # noqa: E402
from happy.compiler.errors import LexerError, ParseError  # noqa: E402
from happy.compiler.lexer import TokenKind  # noqa: E402


class TestLexer(unittest.TestCase):
    def test_primitive_types(self):
        toks = tokenize("Int Float String Bool Byte Char Unit")
        kinds = [t.kind for t in toks if t.kind is not TokenKind.EOF]
        self.assertTrue(all(k is TokenKind.PRIMITIVE_TYPE for k in kinds))
        self.assertEqual(
            [t.value for t in toks if t.kind is TokenKind.PRIMITIVE_TYPE],
            ["Int", "Float", "String", "Bool", "Byte", "Char", "Unit"],
        )

    def test_keywords(self):
        src = ("app let var function type enum module import requires ensures "
               "invariant rule permission capability agent ai can cannot goal "
               "effects secret async await")
        toks = tokenize(src)
        kws = [t.value for t in toks if t.kind is TokenKind.KEYWORD]
        self.assertIn("app", kws)
        self.assertIn("requires", kws)
        self.assertIn("capability", kws)
        self.assertIn("await", kws)
        self.assertEqual(len(kws), 23)

    def test_numbers(self):
        toks = tokenize("42 3.14 0xFF 0b1010 0o17 1_000 6.02e23")
        values = [t.value for t in toks if t.kind in (TokenKind.INT, TokenKind.FLOAT)]
        self.assertEqual(values, [42, 3.14, 255, 10, 15, 1000, 6.02e23])

    def test_strings_and_chars(self):
        src = '"hello\\nworld" ' + "'a'" + " '\\n' " + '"""multi\nline"""'
        toks = tokenize(src)
        strings = [t.value for t in toks if t.kind is TokenKind.STRING]
        chars = [t.value for t in toks if t.kind is TokenKind.CHAR]
        self.assertEqual(strings[0], "hello\nworld")
        self.assertEqual(strings[1], "multi\nline")
        self.assertEqual(chars, ["a", "\n"])

    def test_bools(self):
        toks = tokenize("true false")
        self.assertEqual(
            [t.value for t in toks if t.kind is TokenKind.BOOL], [True, False]
        )

    def test_line_and_block_comments(self):
        src = "let x = 1 // line comment\n/* block\n comment */ let y = 2"
        toks = tokenize(src)
        idents = [t.value for t in toks if t.kind is TokenKind.IDENT]
        self.assertEqual(idents, ["x", "y"])

    def test_nested_block_comments(self):
        src = "/* outer /* inner */ still outer */ let z = 3"
        toks = tokenize(src)
        self.assertIn("z", [t.value for t in toks if t.kind is TokenKind.IDENT])

    def test_line_and_column_tracking(self):
        src = "let x = 1\nlet y = 2"
        toks = tokenize(src)
        y_tok = [t for t in toks if t.value == "y"][0]
        self.assertEqual(y_tok.line, 2)
        self.assertEqual(y_tok.column, 5)

    def test_operators(self):
        toks = tokenize("-> => == != <= >= && || ** :: ..")
        ops = [t.value for t in toks if t.kind is TokenKind.OPERATOR]
        self.assertEqual(
            ops, ["->", "=>", "==", "!=", "<=", ">=", "&&", "||", "**", "::", ".."]
        )

    def test_unterminated_string_raises(self):
        with self.assertRaises(LexerError) as ctx:
            tokenize('let s = "oops')
        self.assertIn("unterminated string", str(ctx.exception))
        self.assertIn("1:9", str(ctx.exception))

    def test_unexpected_character_raises(self):
        with self.assertRaises(LexerError):
            tokenize("let x = 1 $ 2")


class TestParserDeclarations(unittest.TestCase):
    def test_module_and_imports(self):
        src = 'module a.b.c\nimport std.io\nimport { X, Y } from "std.core"'
        prog = parse(src)
        self.assertEqual(prog.module.name, "a.b.c")
        self.assertEqual(len(prog.imports), 2)
        self.assertEqual(prog.imports[1].symbols, ["X", "Y"])
        self.assertEqual(prog.imports[1].name, "std.core")

    def test_struct_with_secret_and_invariant(self):
        src = """
        type Account {
            id: Int
            secret pin: Byte
            balance: Float = 0.0
            invariant balance >= 0.0
        }
        """
        prog = parse(src)
        struct = prog.of_kind(ast.StructDecl)[0]
        self.assertEqual(struct.name, "Account")
        self.assertEqual(len(struct.fields), 3)
        self.assertTrue(struct.fields[1].secret)
        self.assertEqual(struct.fields[2].default.value, 0.0)
        self.assertEqual(len(struct.invariants), 1)
        self.assertEqual(struct.invariants[0].kind, "invariant")

    def test_enum_with_payloads(self):
        src = """
        enum Kind {
            A
            B(Int)
            C(String, Float)
        }
        """
        prog = parse(src)
        enum = prog.of_kind(ast.EnumDecl)[0]
        self.assertEqual([v.name for v in enum.variants], ["A", "B", "C"])
        self.assertEqual(len(enum.variants[2].payload), 2)

    def test_function_with_contracts_and_effects(self):
        src = """
        function add(a: Int, b: Int) -> Int
            requires a >= 0
            ensures result == a + b
            effects [io]
        {
            return a + b
        }
        """
        prog = parse(src)
        fn = prog.of_kind(ast.FunctionDecl)[0]
        self.assertEqual(fn.name, "add")
        self.assertEqual(len(fn.params), 2)
        self.assertEqual(fn.returns.name, "Int")
        self.assertEqual([c.kind for c in fn.contracts], ["requires", "ensures"])
        self.assertEqual(fn.effects.effects, ["io"])
        self.assertEqual(len(fn.body.statements), 1)

    def test_async_function_and_await(self):
        src = """
        async function f() -> Float {
            let r = await g()
            return r
        }
        """
        prog = parse(src)
        fn = prog.of_kind(ast.FunctionDecl)[0]
        self.assertTrue(fn.is_async)
        let_stmt = fn.body.statements[0]
        self.assertIsInstance(let_stmt.value, ast.AwaitExpr)

    def test_permission_can_cannot(self):
        src = """
        permission P {
            can read
            can write
            cannot delete
        }
        """
        prog = parse(src)
        perm = prog.of_kind(ast.PermissionDecl)[0]
        self.assertEqual(perm.can, ["read", "write"])
        self.assertEqual(perm.cannot, ["delete"])

    def test_capability_grants(self):
        src = """
        capability C {
            grants audit
            grants force_close
        }
        """
        prog = parse(src)
        cap = prog.of_kind(ast.CapabilityDecl)[0]
        self.assertEqual(cap.grants, ["audit", "force_close"])

    def test_rule_condition_form(self):
        src = "rule positive(x: Int): x > 0"
        prog = parse(src)
        rule = prog.of_kind(ast.RuleDecl)[0]
        self.assertEqual(rule.name, "positive")
        self.assertIsInstance(rule.condition, ast.BinaryOp)

    def test_agent_declaration(self):
        src = """
        agent Teller {
            goal "serve customers"
            permission [AccountAccess]
            capability [AdminOverride]
            effects [io, net]
            requires balance >= 0.0
        }
        """
        prog = parse(src)
        agent = prog.of_kind(ast.AgentDecl)[0]
        self.assertEqual(agent.name, "Teller")
        self.assertEqual(agent.goal.value, "serve customers")
        self.assertEqual(agent.permissions, ["AccountAccess"])
        self.assertEqual(agent.capabilities, ["AdminOverride"])
        self.assertEqual(agent.effects.effects, ["io", "net"])
        self.assertEqual(len(agent.contracts), 1)

    def test_ai_declaration(self):
        src = """
        ai Detector {
            prompt "find fraud"
            goal "high precision"
            ensures result != null
            let t = 0.5
        }
        """
        prog = parse(src)
        ai = prog.of_kind(ast.AiDecl)[0]
        self.assertEqual(ai.name, "Detector")
        self.assertEqual(ai.prompt.value, "find fraud")
        self.assertEqual(ai.goal.value, "high precision")
        self.assertEqual(len(ai.contracts), 1)
        self.assertEqual(len(ai.body.statements), 1)

    def test_app_declaration(self):
        src = """
        app Demo {
            let x = 1
            print(x)
        }
        """
        prog = parse(src)
        app = prog.of_kind(ast.AppDecl)[0]
        self.assertEqual(app.name, "Demo")
        self.assertEqual(len(app.body.statements), 2)


class TestParserStatements(unittest.TestCase):
    def test_let_var(self):
        src = "function f() { let a = 1\n var b: Int = 2 }"
        prog = parse(src)
        stmts = prog.of_kind(ast.FunctionDecl)[0].body.statements
        self.assertFalse(stmts[0].mutable)
        self.assertTrue(stmts[1].mutable)
        self.assertEqual(stmts[1].type_annotation.name, "Int")

    def test_if_else_chain(self):
        src = """
        function f() {
            if a > 0 {
                return 1
            } else if a < 0 {
                return -1
            } else {
                return 0
            }
        }
        """
        prog = parse(src)
        stmt = prog.of_kind(ast.FunctionDecl)[0].body.statements[0]
        self.assertIsInstance(stmt, ast.IfStmt)
        self.assertIsInstance(stmt.else_branch, ast.IfStmt)

    def test_while_and_for(self):
        src = """
        function f() {
            while x < 10 { x = x + 1 }
            for i in items { print(i) }
        }
        """
        prog = parse(src)
        stmts = prog.of_kind(ast.FunctionDecl)[0].body.statements
        self.assertIsInstance(stmts[0], ast.WhileStmt)
        self.assertIsInstance(stmts[1], ast.ForStmt)
        self.assertEqual(stmts[1].variable, "i")

    def test_assignment_operators(self):
        src = "function f() { x += 1\n y = 2 }"
        prog = parse(src)
        stmts = prog.of_kind(ast.FunctionDecl)[0].body.statements
        self.assertEqual(stmts[0].op, "+=")
        self.assertEqual(stmts[1].op, "=")

    def test_break_continue(self):
        src = "function f() { while true { break\n continue } }"
        prog = parse(src)
        body = prog.of_kind(ast.FunctionDecl)[0].body.statements[0].body
        self.assertIsInstance(body.statements[0], ast.BreakStmt)
        self.assertIsInstance(body.statements[1], ast.ContinueStmt)


class TestParserExpressions(unittest.TestCase):
    def test_operator_precedence(self):
        src = "function f() { let x = 1 + 2 * 3 }"
        prog = parse(src)
        expr = prog.of_kind(ast.FunctionDecl)[0].body.statements[0].value
        self.assertEqual(expr.op, "+")
        self.assertEqual(expr.right.op, "*")

    def test_parenthesized_precedence(self):
        src = "function f() { let x = (1 + 2) * 3 }"
        prog = parse(src)
        expr = prog.of_kind(ast.FunctionDecl)[0].body.statements[0].value
        self.assertEqual(expr.op, "*")
        self.assertEqual(expr.left.op, "+")

    def test_call_member_index(self):
        src = "function f() { let x = a.b(1)[2] }"
        prog = parse(src)
        expr = prog.of_kind(ast.FunctionDecl)[0].body.statements[0].value
        self.assertIsInstance(expr, ast.IndexExpr)
        self.assertIsInstance(expr.obj, ast.CallExpr)
        self.assertIsInstance(expr.obj.callee, ast.MemberExpr)

    def test_unary_and_list(self):
        src = "function f() { let x = -a\n let y = [1, 2, 3] }"
        prog = parse(src)
        stmts = prog.of_kind(ast.FunctionDecl)[0].body.statements
        self.assertIsInstance(stmts[0].value, ast.UnaryOp)
        self.assertEqual(len(stmts[1].value.elements), 3)

    def test_ai_expression(self):
        src = 'function f() { let x = ai { "score" } }'
        prog = parse(src)
        expr = prog.of_kind(ast.FunctionDecl)[0].body.statements[0].value
        self.assertIsInstance(expr, ast.AiExpr)


class TestDiagnostics(unittest.TestCase):
    def test_parse_error_has_location(self):
        src = "function f() {\n    let x = \n}"
        with self.assertRaises(ParseError) as ctx:
            parse(src, filename="bad.hpy")
        err = ctx.exception
        self.assertIsNotNone(err.location)
        self.assertEqual(err.location.line, 2)
        rendered = err.render()
        self.assertIn("bad.hpy:2:", rendered)
        self.assertIn("^", rendered)

    def test_missing_brace_suggestion(self):
        src = "type T {\n    x: Int\n"
        with self.assertRaises(ParseError) as ctx:
            parse(src)
        self.assertIn("'}'", str(ctx.exception))

    def test_unknown_declaration_suggestion(self):
        src = "func f() {}"
        with self.assertRaises(ParseError) as ctx:
            parse(src)
        self.assertIn("did you mean 'function'", str(ctx.exception))

    def test_lexer_error_location(self):
        with self.assertRaises(LexerError) as ctx:
            tokenize("let x = 1\nlet y = @#")
        self.assertEqual(ctx.exception.location.line, 2)


class TestFullScript(unittest.TestCase):
    def test_full_demo_script_parses(self):
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "examples",
            "banking.hpy",
        )
        with open(path, "r", encoding="utf-8") as fh:
            source = fh.read()

        prog = parse(source, filename="banking.hpy")

        self.assertIsNotNone(prog.module)
        self.assertEqual(prog.module.name, "demo.banking")
        self.assertEqual(len(prog.imports), 2)

        self.assertEqual(len(prog.of_kind(ast.StructDecl)), 1)
        self.assertEqual(len(prog.of_kind(ast.EnumDecl)), 1)
        self.assertEqual(len(prog.of_kind(ast.FunctionDecl)), 2)
        self.assertEqual(len(prog.of_kind(ast.PermissionDecl)), 1)
        self.assertEqual(len(prog.of_kind(ast.CapabilityDecl)), 1)
        self.assertEqual(len(prog.of_kind(ast.RuleDecl)), 1)
        self.assertEqual(len(prog.of_kind(ast.AgentDecl)), 1)
        self.assertEqual(len(prog.of_kind(ast.AiDecl)), 1)
        self.assertEqual(len(prog.of_kind(ast.AppDecl)), 1)

        # Spot-check the async function.
        fetch = prog.find("fetch_rate")
        self.assertTrue(fetch.is_async)
        self.assertEqual(fetch.effects.effects, ["net"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
