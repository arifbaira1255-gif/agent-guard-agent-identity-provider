# Happy (.hpy) — Licensing Options Analysis

**Purpose:** help the owner choose a commercial licensing path for the Happy Language IP.
**Important:** this is a business/technical analysis, **not legal advice**. A qualified attorney
should review any decision and the accompanying draft agreement before execution.

---

## 0. Current state

- The repository ships a **`LICENSE` file containing the MIT License** (placeholder text, author
  "Happy Language Contributors").
- If the asset is to be sold or exclusively licensed, the owner must first **confirm sole
  authorship/ownership** of all code (it is self-contained and dependency-free, which makes this
  straightforward) and then **replace the MIT grant** with the chosen commercial terms *before*
  any transfer.
- ⚠️ **Action item:** decide between the options below and set the final `LICENSE` accordingly.
  Do not execute a sale while an MIT grant is in force — it would grant perpetual rights to
  everyone.

---

## 1. Options considered

### Option A — Proprietary (all rights reserved)
**Model:** Source is closed; distribution only under negotiated commercial terms (or as part of an
asset sale). A short proprietary `LICENSE` ("All rights reserved") replaces MIT.

- **Pros:** maximum control and valuation; no third party obtains free rights; cleanest for an
  acquisition.
- **Cons:** no community adoption/funnel; slower ecosystem growth; every user must be signed.
- **Best when:** the strategic goal is a **sale/acquisition** or a small number of high-value
  enterprise deals.

### Option B — Dual licensing (open core + commercial)
**Model:** Release an **open-source core** (e.g. AGPL-3.0 or a source-available licence like BSL/
SSPL for a defined period) under a copyleft/commercial-hostile licence, and sell a **commercial
licence** that removes those obligations.

- **Pros:** drives adoption and de-facto standard status while monetizing commercial users; the
  classic "open core" growth engine.
- **Cons:** requires ongoing OSS maintenance and marketing; AGPL deters some enterprises; revenue
  lags adoption.
- **Best when:** the goal is **market adoption** with monetization of commercial deployments.

### Option C — Commercial licence (single tier, non-copyleft)
**Model:** Source available to licensees under paid terms (per-seat, per-product, or per-domain),
with or without an evaluation/free tier for individuals.

- **Pros:** simple, predictable pricing; enterprise-friendly; still permits a free trial tier.
- **Cons:** needs pricing/packaging and enforcement; less virality than open core.
- **Best when:** there is a clear enterprise/embedded buyer segment.

### Option D — Strategic acquisition
**Model:** Sell the IP outright (asset purchase or share purchase) to a platform vendor.

- **Pros:** immediate, clean exit; buyer integrates the stack.
- **Cons:** one counterparty; valuation depends on the narrative and buyer's roadmap fit.
- **Best when:** an AI platform / fintech / devtool vendor wants an owned safe-execution language.

---

## 2. Recommendation

**For a near-term "license/sell/acquire" objective, start with Option C (commercial licence) +
prepare for Option D (acquisition).** Keep Option B as a fallback to maximize adoption if a
strategic buyer does not materialize within the target window.

Rationale:
- The asset is **complete and dependency-free**, so it can be licensed immediately without an OSS
  community to seed.
- A **dual-license open core** is more work (community, governance, trademark) and delays near-term
  revenue.
- An **outright sale** is always available and should be positioned in parallel.

---

## 3. Suggested commercial licence terms (starting point)

| Term | Suggested default | Notes |
|---|---|---|
| Grant | Non-exclusive, non-transferable, worldwide right to use, modify and embed Happy in licensee products | Exclusive terms reserved for acquisition |
| Scope | Per organisation, per product line, or per named legal entity | Keep scope explicit; avoid silent multi-entity use |
| Fees | Annual subscription (per-seat or per-product) and/or one-time perpetual + maintenance | Offer an evaluation tier (e.g. 30 days) |
| Redistribution | Allowed only when embedded; **no** standalone resale of the toolchain or a competing language product | Protects the core asset |
| Source access | Full source under NDA / commercial terms | Enables embedding and audits |
| Support & SLA | Optional paid tier (best-effort vs. SLA-backed) | Monetizes beyond the licence |
| IP ownership | Owner retains all IP; no assignment | Assignment only in a full sale |
| Audit | Reasonable records + audit right for compliance | Standard enterprise protection |
| Term & termination | Annual, auto-renew; termination for breach | Cure period for breach |
| Warranty & liability | "As-is", limited warranty, liability capped at fees paid | Standard risk allocation |
| Governing law / venue | To be chosen by owner | Jurisdiction-specific |

---

## 4. Comparison table

| Criterion | A. Proprietary | B. Dual-license | C. Commercial | D. Acquisition |
|---|---|---|---|---|
| Speed to first revenue | Medium | Slow | **Fast** | Depends |
| Max long-term value | High | High | High | Medium–High |
| Adoption / funnel | Low | **Highest** | Low–Medium | n/a |
| OSS maintenance burden | None | **High** | Low | None |
| Fit for "sell/acquire soon" | ✓ | ✗ | ✓✓ | ✓✓ |
| Legal complexity | Low | Medium–High | Medium | High (M&A) |

---

## 5. Pre-sale checklist (owner)

1. **Ownership clear** — confirm all code is owner-authored; no third-party licences are embedded
   (the toolchain has **zero third-party runtime dependencies**, which simplifies this).
2. **Set the LICENSE** — replace the MIT placeholder with the chosen terms; keep `LICENSE` and
   `pyproject.toml` `license` metadata consistent.
3. **Trademark** — consider registering "Happy" / the `.hpy` mark (optional but valuable).
4. **Provenance** — retain the CHANGELOG and the build-step history as an auditable provenance record.
5. **Disclosure pack** — TECH SPEC, BENCHMARKS, and the honest limitations list (already in this
   package) double as buyer due-diligence material.
6. **Counsel review** — have the final `LICENSE` and the draft agreement reviewed before signing.

---

*This document is a decision aid, not legal advice.*
