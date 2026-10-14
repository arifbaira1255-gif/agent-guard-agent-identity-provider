# Happy (.hpy) — Pitch Deck

*A short, slide-per-section deck. Each `##` is one slide.*

---

## Slide 1 — Title
# Happy (.hpy)
### The AI-native language where safety is enforced, not suggested
Working prototype v1.0.0 · Complete compiler + runtime + security + AI layer · Ready to license, sell, or acquire

---

## Slide 2 — The problem
- AI now writes a large share of code — **unverified**.
- Existing languages give you **no trust boundary** around generated code.
- Safety features (contracts, permissions, sandboxing) are bolted on, language-by-language.
- Result: speed up authoring, inherit **unbounded risk**.

> The industry lacks a language whose very semantics make unsafe code *fail closed*.

---

## Slide 3 — The product
**Happy** is a statically-typed, contract- and capability-oriented language with one integrated
toolchain:

```
.hpy source → Lexer → Parser → Types/Traits → IR → Optimize → Python (source-mapped)
            → Runtime (contracts, capabilities, secrets, async)
            → Security Analyzer + AI Verification + Developer Tooling
```

Everything above is implemented and runs. Nothing on the slide is aspirational.

---

## Slide 4 — The differentiators (the moat)
1. **Contracts** — `requires`/`ensures`/`invariant` checked at runtime and by the type checker.
2. **Capabilities & permissions** — declared authority, enforced at both compile and run time.
3. **Effects** — side effects are part of the type.
4. **Secret types** — leaking a secret raises `R3001`; redaction available.
5. **AI trust ladder** — `RAW → PARSED → GROUNDED → VERIFIED → TESTED → APPROVED`.
6. **Security analyzer** — 10 rule families over the typed IR.
7. **Zero runtime dependencies** — auditable and embeddable.

---

## Slide 5 — Architecture at a glance
- Compiler front end (~11.5k LOC): lexer, parser, AST, types, symbols, semantic analysis.
- IR + optimizer; Python-3 backend with **source maps** (~1.3k LOC).
- Runtime (~2.3k LOC): contracts, capability, secrets, async, context.
- Standard library (17 modules).
- AI layer (~2.4k LOC): providers (OpenAI/Claude/Gemini/local), plan generator, agent sandbox, verifier.
- Security (~950 LOC): rule engine, project audit.
- Tooling: CLI, package manager, formatter, linter, debugger, docgen, REPL, publisher, **LSP**.

---

## Slide 6 — Traction / readiness (evidence)
| Metric | Result |
|---|---|
| Tests | **418 passed + 187 subtests** |
| Master runner | **11 / 11 stages** |
| Release audit | **0 errors / 0 warnings** |
| Coverage | **51%** (10 files at 100%) |
| Compile speed | ~**280 compiles/sec** |
| Execution | ~**1,094 runs/sec** |
| Examples | **4 / 4** run |
| Dependencies | **0** runtime |

Reproducible on a clean machine from the packaged archive.

---

## Slide 7 — Market positioning
- **Adjacent to:** AI coding assistants (Copilot/Cursor-style), smart-contract languages (Solidity),
  safety-first systems languages (Rust), and policy/sandbox engines.
- **Where Happy wins:** it is the *verification and enforcement* layer those tools lack — the
  language rejects unknown calls at compile time and denies capability-less sensitive operations at
  runtime, so only contract- and capability-clean code executes.
- **Buyers:** AI platform vendors needing a safe execution target for generated code; fintech/security
  teams needing enforced authority; devtool companies wanting an owned language stack.

---

## Slide 8 — Why this is a rare asset
- A **whole language ecosystem** — front end, IR, backend, runtime, stdlib, security, AI, tooling —
  as one coherent, dependency-free, tested artifact.
- Normally a multi-year, multi-team build; here it is complete and measured.
- **Owned outright**, so it can be licensed or acquired with a clean, single-source story.

---

## Slide 9 — Monetization paths
- **Proprietary sale** of the whole IP.
- **Dual-license** — open core for adoption + commercial license for production/embedded use.
- **Per-seat / per-product commercial license** (see draft agreement).
- **Strategic acquisition** by an AI platform, fintech, or devtool vendor.

---

## Slide 10 — Risks & honest status
- Live LLM calls need a vendor key (offline mock by default).
- Test coverage is uneven (CLI layer 9%); native-code backend and hosted registry are not built.
- Current `LICENSE` is an MIT placeholder — a licensing decision is required before sale.
- These are **disclosed** in the package; no metric on these slides is fabricated.

---

## Slide 11 — The ask
- Engage on **licensing, sale or acquisition** of the Happy Language IP.
- Next step: run the included demo (`demo/run_demo.py`) and review `TECHNICAL_SPEC.md` and
  `BENCHMARKS.md`.

> *Happy: generate code fast — and trust it because the language makes unsafe code impossible to approve.*
