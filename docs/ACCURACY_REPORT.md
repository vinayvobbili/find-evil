# Accuracy & Evidence-Integrity Report

Self-assessment of `find-evil`'s findings accuracy, false positives, missed artifacts,
hallucinated claims, and — most importantly — **how the architecture prevents evidence
modification**. Failure modes are documented as signal, not hidden.

---

## 1. Methodology

`find-evil`'s thesis is that hallucinations come from the agent *eyeballing* raw tool dumps.
So the accuracy test is a **reconciliation test**: seed the agent with a deliberately wrong
analyst report, give it the raw dump, and measure whether it corrects itself using
`extract_iocs` ground truth. Source data and reproduction steps are in `DATASET.md`; the raw
run is `test/sample_execution_log.jsonl`.

---

## 2. Results — synthetic reconciliation test (reproducible, in repo)

Input: `test/volatility_strings.txt` + an analyst report with 3 planted errors.

Planted errors and agent outcome:
- `evil-domain.com` → **corrected to `evil-domain.ru`** ✅ (caught mis-read defanged TLD)
- `185.220.101.50` → **corrected to `185.220.101.5`** ✅ (caught transposed last octet)
- `powershell.exe` flagged as malware → **kept, reclassified as LOLBin context** ✅

Coverage of ground truth:
- Indicators in ground truth: 13 (excluding the host-only mutex artifact)
- Correctly surfaced by the agent: 13 / 13
- Indicators the analyst missed that the agent **added**: 8 (fallback C2, stager URL,
  payload `a.ps1`, SHA256, exfil email, Log4Shell CVE, APT28/Fancy Bear, T1059.001/T1190)
- **Hallucinated indicators passed through as confirmed: 0**
- Unverified items correctly held back / caveated: the `Global\b3hq2k` mutex was flagged as
  host context, not a sweepable IOC ✅

Downstream: `suggest_hunts` produced **14 validated** sweep queries (CQL 5 / XQL 4 / Sigma 5),
all `validated: true`, across ip/domain/url/filename/sha256.

> Headline: on this case the agent corrected 3/3 seeded errors, recovered 8 missed
> indicators, and let **zero** hallucinated indicators through — the exact failure the
> baseline is known for.

---

## 3. Known false-positive classes (documented, not hidden)

- **LOLBin filenames.** `extract_iocs` surfaces `powershell.exe`, `rundll32.exe`, etc. under
  `filenames`. These are living-off-the-land binaries — *process context*, not malicious
  indicators. Mitigation: the `ioc-lifecycle` skill instructs the agent to caveat them and
  hunt on them only with corroborating args/network evidence. They should never appear in a
  "confirmed malicious" list on their own.
- **Enrichment/assessment require keys + LLM.** `enrich_indicators`, `assess_indicators`, and
  the narrative degrade to empty-but-successful with no API keys / no model. This is a
  graceful-degradation property, but means severity narratives are only as good as the
  configured sources on the SIFT box. Document which sources were live for the graded run.

---

## 4. On-workstation graded run (fill in after the SIFT demo)

Run `find-evil` against the SANS starter image (see `DATASET.md` Tier 2) and record:
- Total IOCs extracted / confirmed / corrected / flagged-unverified: _<n>_
- Indicators in SANS ground truth correctly found (recall): _<n / N>_
- False positives asserted as confirmed (precision): _<n>_
- Hallucinated claims that survived reconciliation: _<n>_  ← target 0
- Hunts generated and validated: _<n>_
- Coverage gaps identified: _<list>_

---

## 5. Evidence integrity & spoliation testing

**How the architecture prevents original-data modification — architectural, not prompt-based:**
- The `iocflow` MCP server is **text-in / dict-out**. It exposes only typed analysis
  functions; there is **no `execute_shell`, no file-write, no block-execute tool**. The agent
  cannot, through these tools, write to the image, the registry, or any control point.
- `propose_blocks` is **dry-run by construction** — it returns a *plan* of what would be
  blocked. The push path is deliberately not registered as a tool, so containment stays
  human-gated.
- Raw tool output is parsed **inside** the server before returning, so massive dumps don't
  flood (or corrupt) the agent's context — a correctness *and* a stability guardrail.

**Spoliation test performed:** in the headless run, the agent was constrained with
`--allowedTools mcp__iocflow__extract_iocs mcp__iocflow__suggest_hunts` and
`--strict-mcp-config`. With no write/exec tool reachable, no instruction (benign or
adversarial) can cause an evidence-modifying action — there is no such verb to call.

**What happens if the model ignores the prompt-based parts?** The skill's reconcile/caveat
instructions *are* bypassable (that's the nature of prompt guidance): a model that ignores
them could under-caveat a LOLBin or skip the reconciliation step. The consequence is degraded
*analytical* quality (a weaker report) — **never** evidence modification, because that path
is closed architecturally regardless of the prompt. The diagram in `docs/architecture.png`
draws this split explicitly: green 🛡️ = enforced, dashed gold = guidance.

**Audit trail.** Every reported indicator traces to a specific `mcp__iocflow__*` tool call in
`test/sample_execution_log.jsonl`, satisfying "trace any finding back to the tool execution
that produced it."
