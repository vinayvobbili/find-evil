# Graded run — real SANS evidence (base-wkstn-01)

Artifacts from the on-workstation graded analysis of the SANS "Example Compromised System Data"
host `base-wkstn-01` (memory + disk). See `docs/ACCURACY_REPORT.md` §4 and `docs/DATASET.md`
Tier 2 for the writeup.

- `graded_execution_log.jsonl` — headless `claude -p` stream-json log (deliverable #8): the
  agent extracting + reconciling IOCs on real netscan/cmdline, restricted to iocflow MCP tools.
- `FINDINGS_RECONCILIATION.md` — the three-finding trace: every finding → exact tool call +
  output file, with four genuine self-corrections (RFC1918 filter, malfind refutes injection,
  F-Response reclassification, Mnemosyne signed-driver = acquisition tool not rootkit).
- `00_windows_info.txt`, `02_netscan.txt`, `05_malfind.txt`, `06_iocflow_extract.json` — raw
  Volatility3 + iocflow provenance backing the findings.
- `evidence_hashes.txt` — pre/post SHA256 (unchanged) proving read-only chain of custody.

Large derived artifacts (251 MB Sysmon EVTX, 453 MB parsed CSV, 616k-line MFT bodyfile) are not
committed; they regenerate from the evidence with the commands in FINDINGS_RECONCILIATION.md.

## wkstn05/ — COMPROMISED host (Path B)
Real evil found on `base-wkstn-05` (Win7, SRL-2018 APT scenario): WMI/PSRemoting → PowerShell
Empire stager → rundll32, external C2 `venetodns.trade` (egressing via proxy, so absent from the
connection table). See `FINDINGS_RECONCILIATION.md`, `01_psscan.txt` (attack chain),
`02_netscan.txt`, `06_iocflow_extract.json` (iocflow output), `07_raw_string_hunt.txt`.
Demonstrates: finding real evil + holding to 1-of-15 domains + 0 fabricated actor clusters.
Large derived artifacts (163MB Sysmon EVTX, parsed CSVs) regenerate from evidence.
