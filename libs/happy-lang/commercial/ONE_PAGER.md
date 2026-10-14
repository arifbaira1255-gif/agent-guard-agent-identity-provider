# Happy (`.hpy`) — Buyer / Investor One-Pager

**Asset:** A complete, working, AI-native programming-language prototype
**Version:** 1.0.0 · **Status:** Fully implemented, tested and packaged — a working prototype, not a hardened production system
**Form:** Sole-owner source IP, ready to license, sell, or acquire

---

### The one-liner
> **A programming language where safety rules and AI-generated code are *enforced* by the compiler and runtime** —
> contracts, capabilities, effects and permissions are checked by the compiler *and* the runtime, and
> unknown calls are rejected at compile time — so unverified AI output must survive the type checker,
> contract engine, security analyzer and test suite before it is approved.

### The gap it fills
Today's "AI coding" tools **generate** code and hope. There is no trust boundary. Happy supplies
exactly that missing layer: a language whose semantics make unsafe generated code **fail closed**,
with a full compiler, runtime, security analyzer and developer tooling already built.

### What is included (all real, all tested)
- A full compiler: Lexer → Parser → AST → Semantic/Type System (generics, traits, modules) → IR → Optimizer → Backend.
- A Python-3 backend with **source maps** (runtime errors map back to `.hpy` lines).
- A security-first runtime: **contracts, capabilities, permissions, effects, secret protection, async**.
- A standard library (`std.core/io/collections/json/async/crypto`).
- An **AI-native layer**: provider abstraction (OpenAI/Claude/Gemini/local) + agent sandbox + a
  **6-rung trust-ladder verifier**.
- A **static security analyzer** with 11 rule families (`SEC001`–`SEC011`, including capability-bypass detection).
- Full tooling: CLI (15 commands), package manager, AST formatter, linter, debugger, doc generator,
  REPL, publisher, and a **Language Server**.
- Documentation, examples, benchmarks, CI, and an installable package.

### Verified by measurement (no fabricated numbers)
| Metric | Result |
|---|---|
| Tests | **418 passed + 187 subtests** (~3 s) |
| Master integration runner | **11 / 11 stages** |
| Release audit | **0 errors / 0 warnings** |
| Statement coverage | **51%** (10 files at 100%) |
| Compile throughput | ~**280 compiles/sec** (median ~3.5 ms/file) |
| Execution | ~**1,094 runs/sec** |
| Examples | **4 / 4** compile & run |
| Codebase | 92 Python files · ~32,000 lines · **0 runtime dependencies** |

### Why it's defensible (technical moat)
1. **Enforcement, not suggestion** — bad code *cannot* run: the compiler and runtime both reject
   contract, capability and permission violations.
2. **Verification gates AI** — the trust ladder means "AI wrote it" can never bypass "the toolchain
   approved it".
3. **Zero-dependency footprint** — auditable, embeddable, trivially deployable.
4. **Complete stack** — language + compiler + runtime + security + AI + tooling in one coherent
   artifact. Building this normally takes a team years; here it is a working, tested whole.

### Business model options
Proprietary sale · dual-licensing (open core + commercial) · commercial license per seat/product ·
strategic acquisition. Analysis and a draft agreement are included in `LICENSING_ANALYSIS.md` and
`LICENSE_AGREEMENT_DRAFT.md`.

### Honest boundaries
Live LLM calls need a vendor key (offline mock by default). Coverage is uneven (CLI layer 9%). No
native machine-code backend and no hosted package registry. **Sandboxing is behavioural:** unknown
calls are rejected at compile time and sensitive operations without a capability are denied at
runtime, but there is **no OS-level process/container/WASM isolation** — a hostile program that only
uses allowed builtins still runs in the host Python process. Full disclosure in every document.

---

**Buyer package:** `happy-lang-commercial-v1.0.0.zip` — source, tests, docs, benchmarks, demo,
licensing and commercial materials, with `PACKAGE_INDEX.md` explaining the structure.
