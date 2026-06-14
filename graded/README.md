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
