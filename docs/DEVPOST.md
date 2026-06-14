# find-evil 🔎 — teaching Protocol SIFT to catch its own mistakes

> Devpost project story for the SANS **FIND EVIL!** hackathon.
> Repo: https://github.com/vinayvobbili/find-evil · License: MIT

## 💡 Inspiration

Protocol SIFT is a genuinely clever idea: take the SANS SIFT Workstation — 200+ forensic
tools — and put a Claude Code agent in front of them so a responder can investigate at
machine speed. It works. But the hackathon brief says the quiet part out loud: *"It also
hallucinates more than we'd like."*

I've spent years building an AI SOC, and I know exactly **why** it hallucinates. The agent
runs a forensic tool, gets back a 50,000-line text dump, and then *eyeballs* it to pull out
indicators. That's where reality breaks: a defanged `evil[.]ru` gets read back as `.com`, an
IP's last octet gets transposed, `powershell.exe` gets called "the malware." Free-text
reading of huge dumps is precisely the task LLMs are worst at — and in DFIR a wrong
indicator means a wrong containment decision at 3 AM.

So I didn't try to make the agent "read more carefully." I took the reading away from it. 🛡️

## 🧩 What it does

`find-evil` bolts my open-source [`iocflow`](https://github.com/vinayvobbili/iocflow) IOC
lifecycle onto Protocol SIFT as **a custom MCP server plus one skill**. Now, whenever a
forensic tool emits text, the agent doesn't guess — it routes that text through a
deterministic, false-positive-defended extractor and then **reconciles its own eyeballed
findings against ground truth**:

- ✅ **Extract** — IOCs pulled from Plaso timelines, Volatility `strings`/`netscan`,
  YARA hits, logs: IPs, domains, URLs, hashes, CVEs, emails, MITRE techniques, threat
  actors, malware families — re-fanged, PSL-validated, hash-deduped, LOLBin-aware.
- 🔁 **Self-correct** — the skill forces the agent to compare what it *would have reported*
  against the extractor's set, correct wrong values, **flag anything unverified as a
  possible hallucination**, and add what it missed.
- 🎯 **Hunt** — generate "were we touched elsewhere?" sweeps in CrowdStrike CQL, Cortex XQL,
  and Sigma for the confirmed set.
- 🚫 **Contain (dry-run)** — a block *plan* a human can approve. The execute path is
  deliberately not a tool.

In a real headless run (in the repo at `test/sample_execution_log.jsonl`), the agent was
handed an analyst report with three planted errors and a raw Volatility dump. On its own it
corrected `evil-domain.com → evil-domain.ru`, corrected `185.220.101.50 → 185.220.101.5`,
kept `powershell.exe` but reclassified it as a LOLBin, **added 8 indicators the analyst
missed**, and generated 14 validated hunt queries. Every finding traces to a specific tool
call.

## 🎯 Real case results — SANS evidence (`graded/`)

I then ran it for real against the SANS *Example Compromised System Data* — a clean host and
a compromised one. Memory + disk, read-only, SHA256 hashed before and after (**unchanged**).

- 🦠 **`base-wkstn-05` — real evil found.** A 2018 APT scenario: `WmiPrvSE → powershell →
  rundll32` execution chain, a **fileless PowerShell Empire** gzip-base64 stager (`H4sI…`),
  and external C2 `www.venetodns.trade`. Disk corroborated the *how* — WinRM/PSRemoting
  lateral movement under a stolen SQL service account (`shieldbase\spsql`), plus Empire
  injection IOCs (CreateRemoteThread ×75, named pipes ×5,445).
- ⟲ **The money-shot self-correction.** `netscan` showed **only internal peers** (a proxy at
  `172.16.4.10:8080`). The eyeball read was *"no external C2 — contained."* **Wrong.** The
  real C2 egresses *through the proxy*, so it never appears as a foreign IP in the
  connection table — the extractor surfaced it from the **PowerShell command text** instead.
  The agent corrected itself: *there IS external C2; the connection table alone misled me.*
  Genuine, not staged.
- 🧮 **False-positive discipline.** 15 suspicious external domains were present in strings;
  only `venetodns.trade` is tied to the intrusion. The other 14 are Outlook mail-spam
  (`*.ru`, `keto*.trade`) — **reported 1 confirmed C2, 14 unverified**, not a "15 malicious
  domains" headline. `cluster_actor_infrastructure` returned **0 campaigns** rather than
  fabricate an attribution, and `propose_blocks` stayed **`dry_run: true`**.
- 🧼 **`base-wkstn-01` — clean baseline.** 0 confirmed evil, 0 retained hallucinations. Four
  scary-looking artifacts each cleared *with a tool*: proxy egress explained, `malfind`
  empty (refutes injection), `subject_srv.exe` = F-Response IR agent, and `Mnemosyne.sys` =
  F-Response's **signed acquisition driver**, not a rootkit. Honesty cuts both ways: it
  found evil where it existed and refused to invent it where it didn't.

Full trace — every finding → the exact tool call — is in `graded/FINDINGS_RECONCILIATION.md`
and `graded/wkstn05/FINDINGS_RECONCILIATION.md`; the headless log is
`graded/graded_execution_log.jsonl`.

## 🛠️ How I built it

The first hour of recon changed everything: **Protocol SIFT isn't an MCP framework — it *is*
Claude Code** configured on the SIFT box (`~/.claude/CLAUDE.md`, a permissions
`settings.json`, and five `skills/*/SKILL.md`). That's a gift, because Claude Code natively
loads MCP servers and skills. So the integration is small and *first-class*, not a hack:

1. **`iocflow` MCP server** — `iocflow` already ships an MCP server (`iocflow-mcp`, FastMCP
   over stdio) exposing the lifecycle as **typed functions**: `extract_iocs`,
   `enrich_indicators`, `assess_indicators`, `suggest_hunts`, `propose_blocks` (dry-run),
   and STIX round-trip. No `execute_shell`. Raw tool output is parsed *inside* the server,
   so the 50,000-line dump never floods the agent's context window.
2. **The `ioc-lifecycle` skill** — a 6th SIFT skill that changes the agent's *procedure*:
   extract → reconcile (self-correct) → hunt, instead of asserting by eye.
3. **`install.sh`** — an idempotent bolt-on that runs after Protocol SIFT's own installer:
   `pip install iocflow[mcp]`, register the MCP server, drop the skill.

This is **two supported architectural patterns at once**: Direct Agent Extension (Claude
Code) *and* Custom MCP Server — the one the brief calls "the most sound architecture in the
evaluation."

## 🧗 Challenges I ran into

- **"Any case data" anxiety.** `iocflow` parses *text*, not disk images. Would it even apply
  to forensics? I de-risked it before writing a line of prose: SIFT tools *emit* text, and
  feeding real Plaso/Volatility output straight in surfaced clean, re-fanged IOCs. The data
  type never mattered — the tool output is the interface.
- **Proving self-correction without a SIFT image.** Because Protocol SIFT is Claude Code, I
  could reproduce the *entire* agent→MCP→iocflow loop headlessly on a Linux box and capture
  a real execution log — the planted-error test above — before ever booting the OVA.
- **Honest false positives.** The extractor surfaces `powershell.exe`/`rundll32.exe` as
  filenames. Those are LOLBins — context, not IOCs. Rather than hide it, the skill *teaches
  the agent to caveat them*, and the accuracy report documents it as a known class.

## 📚 What I learned

The strongest guardrail isn't a better prompt — it's an **architecture where the dangerous
action doesn't exist as a tool**. The agent can't spoliate evidence or push a block through
`find-evil` because the MCP server is text-in / dict-out and never exposes those verbs. That
turns "please be careful" (prompt-based, bypassable) into "you physically cannot"
(architectural). The same shift fixes hallucination: don't ask the LLM to read carefully —
hand the reading to a deterministic parser and make the LLM *reconcile*.

## 🚀 What's next

- Expose `iocflow`'s ATT&CK coverage-gap (`assess_coverage`) as an MCP tool so the agent
  also answers "can we even detect this?" inline.
- Wire live enrichment (VirusTotal / AbuseIPDB / abuse.ch) on the SIFT box for verdicts.
- A reconciliation benchmark: run with and without `find-evil` over labeled cases and
  publish the hallucination-rate delta as a community baseline.
- Upstream the `ioc-lifecycle` skill to Protocol SIFT.
