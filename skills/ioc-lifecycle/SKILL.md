# Skill: IOC Lifecycle (iocflow MCP)

## Overview
Use this skill whenever a forensic tool emits text that may contain indicators of
compromise — Plaso/psort timelines, Volatility `strings`/`netscan`/`pslist`/`cmdline`,
YARA hits, Sleuth Kit output, registry dumps, web/EDR/Windows event logs. Instead of
reading the raw dump and asserting indicators yourself, route the text through the
`iocflow` MCP server. The server parses raw output natively and returns a structured,
false-positive-defended indicator set — keeping giant dumps out of your context window
and out of your conclusions.

This is a read-only / dry-run capability. None of these tools modify evidence, push a
block, or run a shell command. The `iocflow` MCP server exposes only typed functions;
it has no `execute_shell` tool to abuse.

## Why this exists
The baseline agent hallucinates indicators because it eyeballs large tool dumps and
guesses: it mis-reads defanged domains (`evil[.]ru`), invents hashes, or flags benign
LOLBins (`powershell.exe`, `rundll32.exe`) as the IOC. `iocflow` replaces the guess with
a deterministic extractor that re-fangs, validates against the Public Suffix List,
de-duplicates hashes across MD5/SHA1/SHA256, and applies benign allowlists. Trust the
extractor over your own read.

## Tools (iocflow MCP server)
- `extract_iocs(text)` — IPs, domains, URLs, hashes, filenames, CVEs, emails, MITRE
  ATT&CK techniques, threat actors, malware families. Deterministic; no network.
- `enrich_indicators(text)` — extract, then look each indicator up against configured
  threat-intel sources (VirusTotal / AbuseIPDB / abuse.ch). Empty but successful with no
  API keys.
- `assess_indicators(text)` — extract + enrich, then an analyst-style severity, narrative,
  findings, and recommendations.
- `suggest_hunts(text, dialects)` — ready-to-run "were we touched elsewhere?" sweeps in
  `sigma`, `cortex` (XQL), and `crowdstrike` (CQL).
- `propose_blocks(text)` — DRY-RUN block plan: what *would* be blocked, and where. Never
  acts. Pushing a real block is deliberately not an MCP tool — it stays human-gated.
- `to_stix_bundle(text)` / `from_stix_bundle(stix)` — STIX 2.1 round-trip.

## Workflow (raw artifact → reconciled findings)
1. Run the forensic tool as usual (e.g. `vol.py windows.strings`, `psort.py`, `yara`).
2. Capture its text output to a variable/file.
3. Call `extract_iocs` on that exact text. This is your ground-truth indicator set.
4. **Reconcile (self-correction — required).** Compare the indicators you would have
   reported by eye against `extract_iocs`'s output:
   - Indicators you asserted that the extractor did **not** confirm → mark
     **"unverified — possible hallucination"** and do not present them as findings.
   - Indicators the extractor found that you missed → add them.
   - Defanged/mangled values → use the extractor's canonical (re-fanged) form.
5. Call `suggest_hunts` to produce the lateral "were we touched?" queries for the
   confirmed set.
6. (Optional) `assess_indicators` for a severity + narrative; `propose_blocks` for a
   dry-run containment plan to hand a human.
7. Cite every reported indicator back to the tool execution whose text produced it.

## False Positive Testing
Before finalizing, re-run `extract_iocs` on a slice of known-benign output from the same
host (e.g. baseline `pslist`). Any indicator that appears in both the malicious and the
benign slice is suspect — note it rather than asserting it. `powershell.exe` / `rundll32.exe`
and other LOLBins surface as `filenames`; treat them as process *context*, not as
malicious indicators, unless command-line or network evidence corroborates.

## Evidence Integrity
This skill cannot alter the image, the registry, or any control point. The MCP server is
text-in / dict-out; `propose_blocks` is dry-run by construction and the execute path is
not exposed. This is an **architectural** guardrail, not a prompt request — there is no
tool here that can spoliate evidence.

## Install location
`~/.claude/skills/ioc-lifecycle/SKILL.md` — sits alongside Protocol SIFT's
`memory-analysis`, `plaso-timeline`, `sleuthkit`, `windows-artifacts`, and `yara-hunting`
skills. The MCP server is registered in `~/.claude/.mcp.json` (or via
`claude mcp add iocflow -- iocflow-mcp`).
