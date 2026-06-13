# Mac / SIFT Handoff — final on-workstation steps

Everything that doesn't need the OVA is done and pushed. This is the only part that needs
your Mac. **All commands run inside the SIFT VM terminal** (the Ubuntu guest), not macOS.

Target: submit all 8 deliverables on Devpost by **2026-06-15, 11:45pm EDT**.

---

## 0. Pre-flight — have these ready before you start
- [ ] SIFT Workstation OVA imported and booted (VMware/VirtualBox), with **internet** in the guest.
- [ ] An **Anthropic login / API key** for Claude Code (Protocol SIFT installs the `claude`
      CLI but you must authenticate it — see Step 2).
- [ ] **SANS starter evidence** downloaded from the Protocol SIFT Slack (disk image + memory
      capture). Note the filename.
- [ ] A **screen recorder** with audio (QuickTime on macOS recording the VM window is fine).
- [ ] (Optional) `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` exported in the guest so
      `enrich_indicators` / `assess_indicators` return live verdicts instead of empty.

---

## 1. Hash the evidence FIRST (proves you never modified it)
```bash
sha256sum /path/to/starter_image.E01 | tee ~/evidence_hash_before.txt
```
Re-run this after analysis at the end; the hash must be identical.

## 2. Install Protocol SIFT + authenticate Claude
```bash
# Protocol SIFT (installs the claude CLI + its 5 DFIR skills + permissions)
curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash

# Authenticate Claude Code (interactive). Either:
claude          # then run /login
# ...or use an API key:
# export ANTHROPIC_API_KEY=sk-ant-...
```

## 3. Add find-evil (iocflow + domainflow pivot + the ioc-lifecycle skill)
```bash
curl -fsSL https://raw.githubusercontent.com/vinayvobbili/find-evil/main/install.sh | bash
```

## 4. Verify the bridge
```bash
claude mcp list        # expect: iocflow, domainflow-pivot
ls ~/.claude/skills/   # expect: ioc-lifecycle alongside the 5 SIFT skills
```
If a server is listed but errors at runtime, confirm the package imports:
`python3 -c "import iocflow, domainflow; print('ok')"`.

---

## 5. Run the investigation (this is what you record)
Follow `docs/DEMO_STORYBOARD.md` scene by scene. The shape:

```bash
# create a case dir (protocol-sift copies its case template here)
mkdir -p ~/cases/findevil && cd ~/cases/findevil

# Scene 2 — produce some raw forensic output to investigate, e.g.:
vol.py -f /path/to/memory.vmem windows.netscan > netscan.txt
vol.py -f /path/to/memory.vmem windows.strings | head -2000 > strings.txt
#   ...or a plaso timeline:
log2timeline.py --storage-file plaso.dump /path/to/starter_image.E01
psort.py -w timeline.csv plaso.dump

# Scene 3 — let the agent triage WITH find-evil (interactive, this is the demo)
claude
#   then prompt, e.g.:
#   "Triage strings.txt and netscan.txt. Use the ioc-lifecycle skill: extract IOCs with
#    iocflow, reconcile your read against the extractor, flag anything unverified, then
#    suggest hunts. If you find C2/phishing domains, pivot them with
#    cluster_actor_infrastructure."
```

The self-correction money shot (Scene 3) is the agent calling `mcp__iocflow__extract_iocs`
and correcting its own eyeballed findings. Record that in **one take**.

## 6. Capture a clean execution log (deliverable #8)
Run one headless pass so judges get a structured, traceable log:
```bash
claude -p "Extract and reconcile the IOCs in this output, flag any unverified, then suggest hunts: $(cat strings.txt)" \
  --allowedTools mcp__iocflow__extract_iocs mcp__iocflow__suggest_hunts \
  --output-format stream-json --verbose | tee ~/cases/findevil/graded_execution_log.jsonl
```

## 7. Close the loop
```bash
sha256sum /path/to/starter_image.E01    # must match ~/evidence_hash_before.txt
```
- [ ] Fill `docs/ACCURACY_REPORT.md` **§4** with real counts (extracted / confirmed /
      corrected / unverified / hunts / coverage gaps).
- [ ] Fill `docs/DATASET.md` **Tier 2** with the image name + SHA256.
- [ ] Add the `graded_execution_log.jsonl` to the repo (or attach on Devpost).

---

## 8. Submit on Devpost (all 8 — missing one = elimination)
1. Code repo — https://github.com/vinayvobbili/find-evil ✅
2. Demo video (≤5 min) — your recording → upload (YouTube/Vimeo unlisted, link on Devpost)
3. Architecture diagram — `docs/architecture.png` ✅
4. Written description — paste `docs/DEVPOST.md` into the story fields ✅
5. Dataset doc — `docs/DATASET.md` (Tier 2 filled) ✅
6. Accuracy report — `docs/ACCURACY_REPORT.md` (§4 filled) ✅
7. Try-it-out — README "Install on the SIFT Workstation" + this file ✅
8. Execution logs — `test/sample_*.jsonl` + `graded_execution_log.jsonl` ✅

Suggested Devpost **project title** (stand out in a 4,300-entry gallery):
> *find-evil — the IOC-lifecycle layer that stops Protocol SIFT hallucinating*

---

## Gotchas
- Commands run **inside the SIFT guest**, not macOS.
- `claude` must be authenticated in the guest or every agent step fails silently.
- No API keys → enrichment/assessment come back empty (graceful, but note it in the report).
- If `claude mcp list` is empty after install, re-run the `claude mcp add` lines from
  `install.sh` manually.
