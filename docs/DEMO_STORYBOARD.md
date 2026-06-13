# Demo Video Storyboard (5:00 max)

Screencast of live terminal execution on the SIFT Workstation, audio narration, **at least
one self-correction sequence** (required). Target ~4:30 to leave headroom. Record at 1080p,
terminal font large enough to read. Each scene lists the on-screen action and the narration.

---

## Scene 0 — Cold open (0:00–0:20)
**On screen:** title card → `find-evil` + the architecture diagram (`docs/architecture.png`).
**Narration:** "AI attackers reach domain control in minutes. Protocol SIFT lets a Claude
Code agent drive the SIFT Workstation's 200+ forensic tools at that speed — but it
hallucinates indicators because it eyeballs raw tool dumps. find-evil fixes that by taking
the reading away from the model."

## Scene 1 — The setup (0:20–0:50)
**On screen:** `claude mcp list` → shows `iocflow`. `ls ~/.claude/skills/` → shows
`ioc-lifecycle` next to the five SIFT skills. Briefly show `cat .mcp.json`.
**Narration:** "One bolt-on: a typed iocflow MCP server and a sixth skill. The server is
text-in, dict-out — there's no shell, no file-write, no block-execute. The agent physically
can't modify evidence through it."

## Scene 2 — Baseline failure (0:50–1:30)
**On screen:** run a forensic tool on the SANS image, e.g.
`vol.py -f memory.vmem windows.strings | head`. Show the raw, noisy dump. Ask the agent
(without the skill) to "list the IOCs" → it produces a plausible but **wrong** indicator (a
mis-fanged domain or transposed IP). Pause on the error.
**Narration:** "Here's the problem live — reading by eye, the agent mis-reports an
indicator. In DFIR a wrong indicator is a wrong containment decision."

## Scene 3 — The self-correction (the money shot) (1:30–2:50)
**On screen:** now with `find-evil` active, hand the agent the same dump (and/or the flawed
analyst report). Show it **call `mcp__iocflow__extract_iocs`**, then narrate its own
reconciliation on screen:
- corrects `evil-domain.com` → `evil-domain.ru`
- corrects `185.220.101.50` → `185.220.101.5`
- keeps `powershell.exe` but **reclassifies it as a LOLBin**
- **adds** the 8 indicators it had missed
**Narration:** "Same agent, same dump — but now it doesn't trust its own eyes. It calls the
extractor, compares, and corrects itself: two wrong values fixed, a benign LOLBin
reclassified, eight missed indicators recovered. Zero hallucinated indicators survive."

## Scene 4 — From findings to action (2:50–3:40)
**On screen:** agent calls `mcp__iocflow__suggest_hunts` → show generated Sigma / Cortex XQL
/ CrowdStrike CQL sweeps ("were we touched elsewhere?"). Then `propose_blocks` → show it's a
**DRY-RUN plan**, explicitly not executed.
**Narration:** "Confirmed indicators become runnable hunt queries across three platforms, and
a dry-run containment plan a human approves. The block never fires from the agent — that
verb doesn't exist as a tool."

## Scene 4b — Actor pivot (optional, only if case is phishing/domain-driven) (3:40–4:00)
**On screen:** agent calls `mcp__domainflow-pivot__cluster_actor_infrastructure` on the
extracted domains. Show it either cluster them into one actor campaign, **or** (more
powerfully) return *no cluster* and the agent explaining it won't fabricate an infrastructure
link absent shared pivots.
**Narration:** "Optional breadth: pivot the extracted domains into the actor's wider campaign
— and notice it only links on real shared infrastructure, never a guess."
*(If the demo runs long or the case isn't domain-driven, cut this scene — it's secondary.)*

## Scene 5 — Audit trail & integrity (4:00–4:20)
**On screen:** open `test/sample_execution_log.jsonl` (or the live run's log); highlight a
finding and trace it to the exact `mcp__iocflow__extract_iocs` call. Then re-hash the
evidence image and show the SHA256 is **unchanged**.
**Narration:** "Every finding traces back to the tool call that produced it. And the original
image's hash is unchanged — evidence integrity isn't a promise, it's enforced by an
architecture with no path to write."

## Scene 6 — Close (4:20–4:40)
**On screen:** repo URL `github.com/vinayvobbili/find-evil`, MIT badge, "pip install
iocflow[mcp]", the architecture diagram again.
**Narration:** "find-evil — built on open-source iocflow, MIT licensed, one command to add to
any Protocol SIFT install. Teach the agent to catch its own mistakes."

---

## Capture checklist
- [ ] Terminal theme high-contrast, font ≥ 16pt
- [ ] SANS starter image already downloaded + hashed before recording
- [ ] Dry-run a full pass once so timings are known
- [ ] Record the self-correction scene in one take (no cuts) for credibility
- [ ] Keep total ≤ 5:00; aim 4:30
- [ ] Export 1080p MP4; also cut a ~30s teaser for Slack/socials

## Maps to judging criteria
- **Autonomous execution (tiebreaker):** Scene 3 self-correction
- **IR accuracy:** Scenes 2→3 (hallucination caught & corrected)
- **Constraint implementation:** Scenes 1, 4, 5 (architectural, not prompt, guardrails)
- **Audit trail:** Scene 5 (finding → tool call; unchanged hash)
- **Usability:** Scenes 1, 6 (one-command install)
