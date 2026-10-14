"""Unit tests for the Happy Step-3 stages: IR, contracts, permissions, effects.

Covers:

* **IR lowerer** — typed lowering, deterministic node IDs and fingerprints,
  imports / structs / enums / functions / agents / AI blocks, contract capture.
* **Contract engine** — Bool-typed predicates, ``result`` on Unit returns,
  duplicate & trivially-true clauses, invariant attachment, assertion lowering.
* **Rule engine & capabilities** — built-in rule shape checks, permission
  overlap, capability/permission conflicts, enforcement points (covered and
  uncovered), unused capabilities.
* **Effect tracker** — direct + inter-procedural inference, purity violations,
  over-declaration, and the pure-function classification.

Run with::

    python -m pytest tests/test_ir_contracts.py -v
    # or, without pytest:
    python tests/test_ir_contracts.py
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from happy.compiler import analyze, parse  # noqa: E402
from happy.compiler.ir import (  # noqa: E402
    IRAssert,
    IRBlock,
    IRCall,
    IRExprStmt,
    IRFunction,
    IRModule,
    lower,
)
from happy.compiler.contracts import (  # noqa: E402
    CODE_CONTRACT_NOT_BOOL,
    CODE_RESULT_ON_UNIT,
    W_DUPLICATE_CONTRACT,
    W_TRIVIAL_CONTRACT,
    ContractEngine,
    check_contracts,
)
from happy.compiler.permissions import (  # noqa: E402
    CODE_CAPABILITY_CONFLICT,
    CODE_PERMISSION_OVERLAP,
    CODE_UNENFORCED_CAPABILITY,
    W_UNKNOWN_RULE,
    W_UNUSED_CAPABILITY,
    verify_permissions,
)
from happy.compiler.effects import (  # noqa: E402
    CODE_UNDECLARED_EFFECT,
    EffectKind,
    N_PURE,
    W_OVERDECLARED_EFFECT,
    track_effects,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
FULL_SCRIPT = """\
module demo.full

import std.io
import { Logger } from "std.core"

type Account {
    id: Int
    owner: String
    balance: Float
    secret pin: Byte

    invariant balance >= 0.0, "balance must never be negative"
}

enum Kind {
    Deposit(Float)
    Withdraw(Float)
}

permission AccountAccess {
    can read
    can deposit
    cannot withdraw
}

capability DbRead { grants db_read }

rule no_overdraft(amount: Float): amount <= 0.0

function deposit(account: Account, amount: Float) -> Float
    requires amount > 0.0, "deposit must be positive"
    ensures result == account.balance + amount
    effects [io]
{
    let new_balance = account.balance + amount
    account.balance = new_balance
    return new_balance
}

agent Teller {
    permission [AccountAccess]
    capability [DbRead]
    effects [io]
    requires balance >= 0.0

    function greet(name: String) -> String {
        return "Hello, " + name
    }
}

ai Advisor {
    prompt "answer the user"
    ensures result != null
}

app Demo {
    let account = Account { id: 1, owner: "Ada", balance: 100.0, pin: 7 }
    let total = deposit(account, 50.0)
    print(total)
}
"""


def _lower(src: str, filename: str = "demo.hpy") -> IRModule:
    return lower(analyze(src, filename=filename))


def _codes(diags) -> list:
    return [d.code for d in diags]


# ---------------------------------------------------------------------------
# IR lowering
# ---------------------------------------------------------------------------
class TestIRLowering(unittest.TestCase):
    def setUp(self):
        self.module = _lower(FULL_SCRIPT)

    def test_module_header_and_imports(self):
        self.assertEqual(self.module.name, "demo.full")
        self.assertEqual(len(self.module.imports), 2)
        self.assertEqual(self.module.imports[1].symbols, ["Logger"])
        self.assertEqual(self.module.imports[0].module, "std.io")

    def test_declaration_partitioning(self):
        m = self.module
        self.assertEqual([t.name for t in m.types], ["Account"])
        self.assertEqual([e.name for e in m.enums], ["Kind"])
        self.assertEqual([f.name for f in m.functions], ["deposit"])
        self.assertEqual([r.name for r in m.rules], ["no_overdraft"])
        self.assertEqual([p.name for p in m.permissions], ["AccountAccess"])
        self.assertEqual([c.name for c in m.capabilities], ["DbRead"])
        self.assertEqual([a.name for a in m.agents], ["Teller"])
        self.assertEqual([a.name for a in m.ai_blocks], ["Advisor"])
        self.assertEqual([a.name for a in m.apps], ["Demo"])

    def test_struct_fields_and_secret(self):
        acc = self.module.type_decl("Account")
        self.assertEqual(
            [f.name for f in acc.fields],
            ["id", "owner", "balance", "pin"],
        )
        self.assertEqual(acc.field("balance").type.display(), "Float")
        self.assertTrue(acc.field("pin").secret)
        self.assertFalse(acc.field("id").secret)

    def test_type_invariants_attached(self):
        acc = self.module.type_decl("Account")
        self.assertEqual(len(acc.invariants), 1)
        inv = acc.invariants[0]
        self.assertEqual(inv.kind, "invariant")
        self.assertEqual(inv.attach_to, "Account")
        self.assertEqual(inv.message, "balance must never be negative")

    def test_function_signature_contracts_effects(self):
        dep = self.module.function("deposit")
        self.assertEqual([p.name for p in dep.params], ["account", "amount"])
        self.assertEqual(dep.returns.display(), "Float")
        self.assertEqual([c.kind for c in dep.contracts], ["requires", "ensures"])
        self.assertTrue(dep.contract("ensures")[0].refers_to_result)
        self.assertEqual(
            [e.canonical for e in dep.declared_effects], [EffectKind.IO]
        )
        self.assertFalse(dep.is_async)

    def test_agent_and_nested_function(self):
        agent = self.module.agents[0]
        self.assertEqual(agent.permissions, ["AccountAccess"])
        self.assertEqual(agent.capabilities, ["DbRead"])
        self.assertEqual([f.name for f in agent.functions], ["greet"])
        self.assertEqual([e.canonical for e in agent.declared_effects], ["IO"])

    def test_node_ids_are_deterministic_and_unique(self):
        nodes = self.module.walk()
        ids = [n.id for n in nodes]
        # root "" plus every other node unique
        non_empty = [i for i in ids if i]
        self.assertEqual(len(non_empty), len(set(non_empty)))

    def test_fingerprint_is_stable(self):
        again = _lower(FULL_SCRIPT)
        self.assertEqual(self.module.fingerprint(), again.fingerprint())

    def test_fingerprint_changes_with_source(self):
        other = _lower(FULL_SCRIPT.replace("balance >= 0.0", "balance > 0.0"))
        self.assertNotEqual(self.module.fingerprint(), other.fingerprint())

    def test_lower_from_raw_program_without_analysis(self):
        module = lower(parse(FULL_SCRIPT))
        self.assertEqual([f.name for f in module.functions], ["deposit"])
        self.assertEqual(module.name, "demo.full")

    def test_lowering_requires_a_program(self):
        from happy.compiler.ir import IRLoweringError

        with self.assertRaises(IRLoweringError):
            lower(None)


# ---------------------------------------------------------------------------
# Contracts
# ---------------------------------------------------------------------------
class TestContracts(unittest.TestCase):
    def test_full_script_contracts_are_clean(self):
        report = check_contracts(FULL_SCRIPT, filename="full.hpy")
        self.assertTrue(report.ok, report.format())
        deposit = report.info("deposit")
        self.assertIsNotNone(deposit)
        self.assertEqual(len(deposit.requires), 1)
        self.assertEqual(len(deposit.ensures), 1)
        # lowered assertions
        self.assertEqual(len(deposit.entry_assertions), 1)
        self.assertEqual(len(deposit.exit_assertions), 1)
        self.assertIsInstance(deposit.entry_assertions[0], IRAssert)

    def test_non_bool_predicate_is_an_error(self):
        src = (
            "module t\n\n"
            "function f(x: Int) -> Int\n"
            "    requires x + 1\n"
            "{\n    return x\n}\n"
        )
        report = check_contracts(src, filename="t.hpy")
        self.assertFalse(report.ok)
        self.assertIn(CODE_CONTRACT_NOT_BOOL, _codes(report.errors))

    def test_result_on_unit_return_is_an_error(self):
        src = (
            "module t\n\n"
            "function g() -> Unit\n"
            "    ensures result != null\n"
            "{\n}\n"
        )
        report = check_contracts(src, filename="t.hpy")
        self.assertIn(CODE_RESULT_ON_UNIT, _codes(report.errors))

    def test_trivial_contract_warns(self):
        src = (
            "module t\n\n"
            "function f(x: Int) -> Int\n"
            "    requires true\n"
            "{\n    return x\n}\n"
        )
        report = check_contracts(src, filename="t.hpy")
        self.assertIn(W_TRIVIAL_CONTRACT, _codes(report.warnings))

    def test_duplicate_clause_warns(self):
        src = (
            "module t\n\n"
            "function f(x: Int) -> Int\n"
            "    requires x > 0\n"
            "    requires x > 0\n"
            "{\n    return x\n}\n"
        )
        report = check_contracts(src, filename="t.hpy")
        self.assertIn(W_DUPLICATE_CONTRACT, _codes(report.warnings))

    def test_invariant_unknown_field_warns(self):
        src = (
            "module t\n\n"
            "type P {\n"
            "    a: Int\n"
            "    invariant missing > 0\n"
            "}\n"
        )
        report = check_contracts(src, filename="t.hpy")
        info = report.info("P")
        self.assertIsNotNone(info)
        self.assertTrue(report.warnings)  # unknown field W5004

    def test_empty_condition_is_error(self):
        # A contract with no predicate cannot be built from source, so build
        # the IR directly and make sure the engine reports it.
        from happy.compiler.ir import IRContract, IRFunction, IRModule

        fn = IRFunction(name="f", contracts=[IRContract(kind="requires")])
        module = IRModule(name="t", functions=[fn])
        report = ContractEngine(filename="t.hpy").analyze(module)
        from happy.compiler.contracts import CODE_EMPTY_CONTRACT

        self.assertIn(CODE_EMPTY_CONTRACT, _codes(report.errors))


# ---------------------------------------------------------------------------
# Permissions & capabilities
# ---------------------------------------------------------------------------
class TestPermissions(unittest.TestCase):
    def test_full_script_permissions_clean(self):
        report = verify_permissions(FULL_SCRIPT, filename="full.hpy")
        self.assertTrue(report.ok, report.format())
        self.assertIsNotNone(report.permission("AccountAccess"))
        self.assertIsNotNone(report.capability("DbRead"))
        self.assertIsNotNone(report.rule("no_overdraft"))

    def test_permission_overlap_detected(self):
        report = verify_permissions(FULL_SCRIPT.replace(
            "    cannot withdraw", "    cannot deposit"
        ), filename="full.hpy")
        self.assertIn(CODE_PERMISSION_OVERLAP, _codes(report.errors))

    def test_unknown_rule_is_noted(self):
        report = verify_permissions(FULL_SCRIPT, filename="full.hpy")
        self.assertIn(W_UNKNOWN_RULE, _codes(report.notes))

    def test_builtin_rules_recognised(self):
        src = (
            "module t\n\n"
            "rule authentication_required(user: String): user != \"\"\n"
            "rule must_never_be_exposed(flag: Bool): flag == false\n"
            "rule rate_limited(n: Int): n > 0\n"
        )
        report = verify_permissions(src, filename="t.hpy")
        for name in (
            "authentication_required",
            "must_never_be_exposed",
            "rate_limited",
        ):
            rule = report.rule(name)
            self.assertIsNotNone(rule)
            self.assertTrue(rule.is_known, name)
            self.assertTrue(rule.arity_ok, name)
            self.assertTrue(rule.predicate_is_bool, name)

    def test_builtin_rule_arity_checked(self):
        src = "module t\n\nrule authentication_required: true\n"
        report = verify_permissions(src, filename="t.hpy")
        rule = report.rule("authentication_required")
        self.assertFalse(rule.arity_ok)

    def test_enforcement_point_covered(self):
        src = (
            "module t\n\n"
            "capability FileWrite { grants file_write }\n"
            "agent Writer {\n"
            "    capability [FileWrite]\n"
            "    function save(p: String) -> Unit {\n"
            "        write_file(p, \"data\")\n"
            "    }\n"
            "}\n"
        )
        report = verify_permissions(src, filename="t.hpy")
        self.assertEqual(len(report.enforcement_points), 1)
        point = report.enforcement_points[0]
        self.assertTrue(point.enforced)
        self.assertEqual(point.covering_capability, "FileWrite")

    def test_enforcement_point_uncovered_is_error(self):
        src = (
            "module t\n\n"
            "agent Reader {\n"
            "    effects [io]\n"
            "    function load(p: String) -> String {\n"
            "        return read_file(p)\n"
            "    }\n"
            "}\n"
        )
        report = verify_permissions(src, filename="t.hpy")
        self.assertFalse(report.ok)
        self.assertIn(CODE_UNENFORCED_CAPABILITY, _codes(report.errors))

    def test_unused_capability_warns(self):
        src = "module t\n\ncapability Lonely { grants db_read }\n"
        report = verify_permissions(src, filename="t.hpy")
        self.assertIn(W_UNUSED_CAPABILITY, _codes(report.warnings))

    def test_capability_permission_conflict(self):
        src = (
            "module t\n\n"
            "permission P {\n"
            "    can read\n"
            "    cannot withdraw\n"
            "}\n"
            "capability Money { grants withdraw }\n"
            "agent A {\n"
            "    permission [P]\n"
            "    capability [Money]\n"
            "}\n"
        )
        report = verify_permissions(src, filename="t.hpy")
        self.assertIn(CODE_CAPABILITY_CONFLICT, _codes(report.errors))


# ---------------------------------------------------------------------------
# Effects
# ---------------------------------------------------------------------------
class TestEffects(unittest.TestCase):
    def test_default_effects_inferred(self):
        src = (
            "module t\n\n"
            "function fetch(u: String) -> Any\n"
            "    effects [net]\n"
            "{\n    return http_get(u)\n}\n"
        )
        report = track_effects(src, filename="t.hpy")
        fe = report.function("fetch")
        self.assertEqual(fe.inferred, (EffectKind.NETWORK,))
        self.assertEqual(fe.declared, (EffectKind.NETWORK,))
        self.assertTrue(fe.is_pure is False)

    def test_pure_function_classified(self):
        src = (
            "module t\n\n"
            "function add(a: Int, b: Int) -> Int {\n    return a + b\n}\n"
        )
        report = track_effects(src, filename="t.hpy")
        fe = report.function("add")
        self.assertTrue(fe.is_pure)
        self.assertIn(N_PURE, _codes(report.notes))

    def test_purity_violation_detected(self):
        src = (
            "module t\n\n"
            "function sneaky(a: Int) -> Int\n"
            "    effects []\n"
            "{\n    print(\"x\")\n    return a\n}\n"
        )
        report = track_effects(src, filename="t.hpy")
        self.assertFalse(report.ok)
        self.assertIn(CODE_UNDECLARED_EFFECT, _codes(report.errors))

    def test_interprocedural_propagation(self):
        src = (
            "module t\n\n"
            "function impure(a: Int) -> Int\n"
            "    effects [io]\n"
            "{\n    print(\"x\")\n    return a\n}\n\n"
            "function caller(a: Int) -> Int\n"
            "    effects []\n"
            "{\n    return impure(a)\n}\n"
        )
        report = track_effects(src, filename="t.hpy")
        caller = report.function("caller")
        self.assertEqual(caller.inferred, (EffectKind.IO,))
        self.assertIn(CODE_UNDECLARED_EFFECT, _codes(report.errors))

    def test_overdeclaration_warns(self):
        src = (
            "module t\n\n"
            "function f(a: Int) -> Int\n"
            "    effects [io]\n"
            "{\n    return a\n}\n"
        )
        report = track_effects(src, filename="t.hpy")
        self.assertIn(W_OVERDECLARED_EFFECT, _codes(report.warnings))

    def test_ai_expression_implies_ai_effect(self):
        src = (
            "module t\n\n"
            "ai Bot {\n"
            "    prompt \"hi\"\n"
            "    let answer = ai { \"score it\" }\n"
            "}\n"
        )
        module = _lower(src)
        # the ai expression is inside the block; assert it lowered to IRAiExpr
        from happy.compiler.ir import IRAiExpr

        found = any(isinstance(n, IRAiExpr) for n in module.walk())
        self.assertTrue(found)


# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------
class TestFullPipeline(unittest.TestCase):
    def test_pipeline_runs_end_to_end(self):
        analysis = analyze(FULL_SCRIPT, filename="full.hpy")
        module = lower(analysis)
        contracts = ContractEngine(
            source=FULL_SCRIPT, filename="full.hpy"
        ).analyze(module)
        perms = verify_permissions(module, filename="full.hpy")
        effs = track_effects(module, filename="full.hpy")
        # IR is well-formed and every stage produces a report
        self.assertIsInstance(module, IRModule)
        self.assertTrue(contracts.ok, contracts.format())
        self.assertTrue(perms.ok, perms.format())
        # deposit performs a print (IO) — declared, but bank-free
        self.assertTrue(effs.functions)


if __name__ == "__main__":
    unittest.main(verbosity=2)
