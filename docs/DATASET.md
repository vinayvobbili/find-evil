# Dataset Documentation

`find-evil` was tested against two tiers of data: a reproducible **synthetic corpus** that
ships in this repo (so judges can re-run the core claim without downloading anything), and
the **SANS starter evidence** images used for the on-workstation demo.

---

## Tier 1 — Synthetic forensic-tool-output corpus (in repo, reproducible)

Because `iocflow` consumes *text* (not raw images), the meaningful unit of test data is the
**text a SIFT tool emits**. These files reproduce the shape of Plaso/Volatility output and
carry a known ground-truth indicator set, so the reconciliation claim is verifiable offline.

### `test/volatility_strings.txt`
Simulated `vol.py windows.strings` excerpt from a compromised host's `powershell.exe`
(PID 4812). **Ground-truth indicators:**
- IP: `185.220.101.5`
- Domains: `evil-domain.ru`, `cobalt-c2.net` (fallback C2)
- URL: `http://185.220.101.5/a.ps1`
- Filenames: `powershell.exe` (LOLBin — context, not IOC), `a.ps1` (payload)
- SHA256: `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08`
- Email: `admin@evil-domain.ru`
- CVE: `CVE-2021-44228` (Log4Shell)
- Threat actors: `APT28`, `Fancy Bear`
- MITRE: `T1059.001`, `T1190`
- Host artifact (not a sweepable IOC): mutex `Global\b3hq2k`

### `test/volatility_netscan.txt`
Simulated `vol.py windows.netscan`. **Ground truth:** IPs `185.220.101.5`, `45.142.212.61`;
domain `cobalt-c2.net`; processes `powershell.exe`, `rundll32.exe` (both LOLBins).

### `test/plaso_timeline.csv`
Simulated `psort.py` CSV timeline (filesystem + registry + web + Defender rows). **Ground
truth:** MD5 `a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4`, domain/URL `evil-domain.ru`, IP
`185.220.101.5`, filenames `install.ps1` / `powershell.exe`.

### Defanging note
Indicators are stored **defanged** (`evil-domain[.]ru`, `185.220.101[.]5`) exactly as real
tool output and analyst notes carry them. A core part of the test is that the extractor
**re-fangs** them to canonical form — and that the agent adopts the canonical value over a
mis-read.

### What the test exercises
`test/sample_execution_log.jsonl` is a real headless Claude Code run over
`volatility_strings.txt`. The agent was seeded with a deliberately **wrong** analyst report
(3 planted errors) and had to reconcile it against `extract_iocs`. See `ACCURACY_REPORT.md`
for results.

### Reproduce
```bash
pip install 'iocflow[mcp]'
claude -p "Reconcile the IOCs in this dump against extract_iocs, flag any unverified: $(cat test/volatility_strings.txt)" \
  --mcp-config .mcp.json --strict-mcp-config \
  --allowedTools mcp__iocflow__extract_iocs mcp__iocflow__suggest_hunts
```

---

## Tier 2 — SANS starter evidence (on-workstation demo)

The graded demo runs on the SIFT Workstation against the **starter evidence datasets**
provided on the Protocol SIFT Slack (disk image + memory capture of a compromised Windows
system). These are not redistributed here. Fill in at capture time:

- **Image name / file:** _<starter image filename>_
- **Source:** Protocol SIFT Slack → starter resources
- **SHA256 (as downloaded):** _<hash>_  ← record to prove the original was never modified
- **Acquisition type:** _<E01 / raw dd / vmem / etc.>_
- **Tools run via Protocol SIFT:** _<plaso, vol.py windows.pslist/netscan/strings, yara, ...>_
- **What the agent found:** _<confirmed IOCs, hunts generated, coverage gaps>_
- **Ground truth (if SANS publishes it):** _<known-evil artifacts for scoring>_

> Reproducibility check: re-hash the image after analysis and confirm the SHA256 is
> unchanged — evidence integrity is verified by the hash, not just asserted.
