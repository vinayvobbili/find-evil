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

The graded demo runs on the SIFT Workstation against the **"Example Compromised System
Data"** published by the hackathon (disk image + memory capture of a compromised Windows
system). These are not redistributed here. Fill in at capture time:

- **Host:** `base-wkstn-01.shieldbase.lan` — Windows 10 x64 build 16299 (1709), captured
  2021-09-16 UTC.
- **Files analyzed (two artifacts, same host, same incident):**
  | Artifact | Acquisition | Bytes | SHA256 (as analyzed) |
  |---|---|---|---|
  | `base-wkstn-01-mem.img` | raw memory (F-Response/Mnemosyne) | 3,221,225,472 | `2caefa29dd738228d1274a6d3a75d60dbdbf3eda2483e1e5bd0a500e9ac07fbc` |
  | `base-wkstn-01-c-drive.E01` | FTK Imager E01, NTFS C: (31 GiB media) | 16,923,891,211 | `ede47a0733203134f92c8ae46df4f5106b78a2c357fdb1d3c84301261076429f` |
  | `base-wkstn-01-mem.zip` (container) | download wrapper | 1,270,425,664 | `ef061848edb0d0014155f8ee43cbc67f759520fa96de249ffbd45045b602e29a` |
- **Source:** FIND EVIL! Devpost → Resources / "Download Example Compromised System Data"
  to-do (served from SANS Egnyte; the Protocol SIFT Slack is for Q&A, not data hosting).
- **Tools run via Protocol SIFT:** Volatility3 (`windows.info / pslist / netscan / cmdline /
  pstree / malfind`); TSK (`ewfmount`, `fls`, `icat`) read-only; EvtxECmd (Sysmon, 308,812
  events); all output routed through `mcp__iocflow__extract_iocs` + `suggest_hunts`.
- **What the agent found:** `base-wkstn-01` is a **clean baseline host** — **0 confirmed
  malicious indicators, 0 external network IOCs** (all `netscan` peers RFC1918), **0 surviving
  hallucinations.** Four scary-looking artifacts were each run down with a tool and cleared:
  svchost→`172.16.4.10:8080` = **proxy** (Sysmon `RuleName: Proxy` ×271,007); "injected svchost"
  = **refuted** (`malfind` empty); `C:\windows\subject_srv.exe` = **F-Response** IR agent;
  `Mnemosyne.sys` kernel driver = **F-Response acquisition driver** (validly signed, *Agile Risk
  Management LLC*). 1 validated Sigma hunt generated. Full trace + counts:
  `docs/ACCURACY_REPORT.md` §4 and the case file `analysis/FINDINGS_RECONCILIATION.md`.
- **Ground truth:** this host shows no adversary activity (the `base-` prefix is the *environment*
  name — `shieldbase.lan` — not "baseline"; sibling host `base-wkstn-05` below is compromised).
  Recall vs. malice = N/A here; the result is a precision/anti-hallucination demonstration.

> Reproducibility check **passed**: both images were re-hashed after the full analysis and the
> SHA256s above were **unchanged** — evidence integrity verified by hash, not merely asserted.
> Working copies were held `chmod 444`; all reads via `ewfmount` (read-only) + `icat`.

### Host 2 — `base-wkstn-05` (COMPROMISED, Path B)

From the bundle's "Compromised APT Attack Scenarios / SRL-2018 Compromised Enterprise Network."

| Artifact | Acquisition | SHA256 (as analyzed) |
|---|---|---|
| `base-wkstn-05-memory.img` | raw memory (dc3dd; bundled MD5 `bb6df5c0…c4fe0` verified) | `74ff679b25727d5fb7a8f70217d6fad965efd806260b7d224f0b38bd1c436115` |
| `base-wkstn-05-cdrive.E01` | FTK/EWF, NTFS C: (29 GiB) | `a94f2a866e2e562c58c3fbcd3a94882f2d3c3db3c66a5e5eedf16a4b1c0a65e0` |

- **Host:** Windows 7 SP1 x64, `172.16.7.15` / `shieldbase.lan`, captured 2018-09-06.
- **Tools:** Volatility3 `windows.psscan` + `netscan` (list-walk plugins fail on this image — see
  note in §4b), raw-image `strings` carving, TSK `ewfmount`/`icat` (read-only), EvtxECmd (Sysmon +
  PowerShell Operational). Routed through `extract_iocs` / `suggest_hunts` / `propose_blocks` /
  `cluster_actor_infrastructure`.
- **What the agent found:** **compromised** — `WmiPrvSE→powershell→rundll32` chain, a fileless
  PowerShell **Empire** stager, and external C2 **`www.venetodns.trade`** egressing via the proxy
  (so absent from `netscan` — recovered from the PowerShell command). Disk confirmed PSRemoting
  lateral movement under stolen SQL account `shieldbase\spsql` + Empire injection IOCs. **1 C2
  reported out of 15 candidate domains** (14 were email/defender noise); **0 fabricated** actor
  clusters; block plan **dry-run only**. Full trace: `docs/ACCURACY_REPORT.md` §4b and
  `analysis/wkstn05/FINDINGS_RECONCILIATION.md`.
- **Integrity:** memory image re-hashed after analysis — **unchanged**; all reads read-only.
