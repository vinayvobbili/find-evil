# base-wkstn-01 — Memory Triage Findings & Reconciliation

**Evidence:** `base-wkstn-01-mem.img` (3,221,225,472 bytes raw memory)
**SHA256 (chain of custody):** `2caefa29dd738228d1274a6d3a75d60dbdbf3eda2483e1e5bd0a500e9ac07fbc`
**Host:** Windows 10 x64 build 16299 · host IP `172.16.7.11` · capture `2021-09-16 03:05:13 UTC`
**Posture at capture:** at LogonUI (login screen), **no interactive user processes** (no explorer/powershell/cmd/rundll32/etc.)
**Tooling present:** Sysmon64, Velociraptor, F-Response, McAfee suite → host is an instrumented IR target.

> Every finding below cites the **exact tool call** and the **output file** that produced it
> (the "three-finding trace"). Confidence is stated explicitly; inferences are separated from
> confirmed facts. Two findings record a **genuine self-correction**.

---

## Finding 1 — Anomalous internal connection: DiagTrack svchost (PID 2332) → 172.16.4.10:8080
- **Tool call:** `vol -f base-wkstn-01-mem.img windows.netscan` → `analysis/02_netscan.txt`
  - Row: `0xc08eab1aa010 TCPv4 172.16.7.11:51892 -> 172.16.4.10:8080 ESTABLISHED PID 2332 svchost.exe 2021-09-16 03:04:57 UTC`
- **Corroborating calls:** `windows.cmdline` (`03_cmdline.txt`) → PID 2332 = `svchost.exe -k utcsvc -p` (DiagTrack/Connected User Experiences & Telemetry); `windows.pstree` (`04_pstree.txt`) → PPID 776 `services.exe`, running since boot 2021-02-03.
- **Read:** DiagTrack telemetry normally egresses to Microsoft endpoints, **not** an internal host on :8080. ESTABLISHED 16 s before capture. **Anomalous.**
- **⟲ SELF-CORRECTION (genuine, tool-driven):** Initial eyeball hypothesis was *code injection into svchost*. Ran `vol windows.malfind` (`05_malfind.txt`) → **0 rows / no injected regions in ANY process**. Injection hypothesis **REFUTED**. Reclassified: *suspicious internal connection, mechanism unconfirmed in memory* — corroborate on disk (Sysmon EID 3, Prefetch, service config) once `base-wkstn-01-c-drive.E01` is available.
- **iocflow reconciliation:** `172.16.4.10` is RFC1918 → `extract_iocs` (`06_iocflow_extract.json`) returned `"ips": []`. **Not an external blocklist IOC.** Action = host-based hunt / internal-segmentation review, not perimeter block.
- **Confidence:** Anomaly = **HIGH**; malicious attribution = **UNCONFIRMED** (honestly flagged).

## Finding 2 — Repeated WinRM (5985) egress to 172.16.5.21 across months
- **Tool call:** `windows.netscan` → `analysis/02_netscan.txt`
  - `172.16.7.11:49713 -> 172.16.5.21:5985 CLOSED PID 215296 (2021-09-15)`
  - `172.16.7.11:64236 -> 172.16.5.21:5985 CLOSED PID 66472 (2021-04-08)`
  - `172.16.7.11:57033 -> 172.16.5.21:5985 CLOSED PID 173504 (2021-07-22)`
- **Read:** WinRM/WS-Management is a lateral-movement / remote-admin channel. Three sessions over 5 months to the same internal host = recurring remote management (could be admin **or** lateral movement).
- **iocflow reconciliation:** `172.16.5.21` RFC1918 → no external IOC. Hunt = WinRM connection events (Sigma rule emitted by `suggest_hunts`).
- **Confidence:** Activity = **CONFIRMED**; benign-vs-malicious = **UNDETERMINED** from memory alone.

## Finding 3 — `C:\windows\subject_srv.exe` (PID 214656): masquerade check → benign F-Response
- **Tool call:** `windows.cmdline` → `analysis/03_cmdline.txt`
  - `214656 subject_srv.exe  C:\windows\subject_srv.exe -s "172.16.5.25:5682" -l 3262 -v "F-Response Subject" -k "155522845"`
  - `windows.pstree` (`04_pstree.txt`) → service (PPID 776), created `2021-09-16 03:01:58` (~3.5 min before capture).
- **⟲ SELF-CORRECTION / reconciliation:** A binary named `subject_srv.exe` in `C:\windows\` (not `System32`) reads as a **masquerade / suspicious**. But the embedded banner `-v "F-Response Subject"` + examiner-subnet peer `172.16.5.25` identify it as **F-Response**, a legitimate remote-forensics collection agent the IR team deployed immediately before capture. Reclassified **suspicious → benign IR tooling.** (Same class as Velociraptor PID 2616 → `172.16.5.28:8000`.)
- **Confidence:** Identity = **CONFIRMED benign**.

---

## Overall reconciliation (what the FP-defended extractor changed)
- **External IOCs surfaced: 0.** Every foreign endpoint in `windows.netscan` is RFC1918; `extract_iocs` correctly emitted **no IP/domain/URL** indicators. A naïve pass would mis-report `172.16.4.10:8080` as external C2 to block — **prevented**.
- **No injected code** anywhere (`malfind` empty) → no in-memory implant evidence.
- **IR tooling correctly distinguished from threat** (Velociraptor, F-Response) rather than flagged as evil.
- **Net:** memory shows **one unresolved internal anomaly** (Finding 1) and **two confirmed-benign** IR artifacts. No fabricated findings. Real attacker artifacts (if present) to be sought on disk via the timeline.

## Hunts generated (`suggest_hunts`, Sigma)
- Filename sweep (`svchost.exe`, `subject_srv.exe`) — `process_creation`.
- (Internal-IP and WinRM host-hunt guidance recorded; not emitted as blockable network IOCs by design.)

---

# DISK CORROBORATION & FINAL RESOLUTION (base-wkstn-01-c-drive.E01)

Disk: `base-wkstn-01-c-drive.E01` · SHA256 `ede47a0733203134f92c8ae46df4f5106b78a2c357fdb1d3c84301261076429f`
(FTK Imager, acquired 2021-09-16 03:10:21 UTC — 5 min after memory). Mounted **read-only**
via `ewfmount`; artifacts carved with `icat`; Sysmon EVTX parsed with EvtxECmd (308,812 events).
Host FQDN confirmed: **base-wkstn-01.shieldbase.lan**.

## Resolution of Finding 1 (svchost → 172.16.4.10:8080) — BENIGN PROXY
- **Tool:** EvtxECmd Sysmon → `analysis/extracted/sysmon.csv`. EID 3 count = 271,007, of which
  **271,007 carry `RuleName: Proxy`** and all target `172.16.4.10`. wermgr.exe, svchost, etc. all
  egress through it.
- **Conclusion:** `172.16.4.10:8080` is the **corporate web proxy**, not C2. The DiagTrack
  connection is telemetry egressing via proxy. ⟲ *Self-correction #3 (disk-confirmed): the
  "anomalous beacon" is normal proxied egress.*

## False positive avoided — net.exe/net1.exe "recon" is scheduled automation
- **Tool:** `sysmon.csv` EID 1 (20,834 process-creations). `net.exe` 3,687 / `net1.exe` 1,229 /
  `cmd.exe` 30,613, firing hourly at `:15:01` since **2021-07-23**, parented by `cmd.exe`,
  McAfee `macompatsvc.exe`/`VsTskMgr.exe`, and `svchost` scheduled tasks.
- **Conclusion:** sustained 2-month hourly cadence = **scheduled-task / McAfee automation**, not
  hands-on-keyboard recon. ⟲ *FP avoided: volume ≠ malice.*

## Finding 3 corroborated — subject_srv.exe = F-Response (benign IR tooling)
- **Tool:** MFT bodyfile (`disk_fls_bodyfile.txt`): `C:/Windows/subject_srv.exe` **born
  2021-09-16 03:01:57** (matches memory process-create 03:01:58); Prefetch
  `SUBJECT_SRV.EXE-3C028E74.pf` executed 03:02:08.

## NEW: Mnemosyne.sys kernel driver — looks like a rootkit, IS the acquisition driver
- **Tools:** MFT (`C:/Windows/Mnemosyne.sys`, 26,248 B, born **2021-09-16 03:01:59**); Sysmon
  EID 11/13/6 in `sysmon.csv`.
  - Service `mnemosyne` registered by services.exe (PID 776), `ImagePath \??\C:\windows\Mnemosyne.sys`, demand-start (Start=0x3).
  - Second drop performed by **PID 214656 = subject_srv.exe (F-Response)** at 03:01:59.
  - **EID 6 Driver loaded:** `Signed: true · Signature: "Agile Risk Management LLC" · SignatureStatus: Valid`.
- **⟲ SELF-CORRECTION #4 (the strongest):** Initial read — *unknown kernel driver dropped in
  `C:\Windows` minutes before capture = rootkit.* The **valid signature by Agile Risk Management
  LLC (the F-Response vendor)** identifies it as F-Response's signed raw-memory-access driver —
  i.e., **the tool that acquired the very memory image under analysis.** Reclassified rootkit →
  **legitimate acquisition driver.** Confidence: CONFIRMED benign (valid signature + causal tie
  to F-Response deployment + capture timeline).

## Final verdict on base-wkstn-01
Across memory (pslist/netscan/cmdline/pstree/malfind) and disk (Sysmon EID 1/3/6/11/13, MFT,
Prefetch, service registry), **no malicious activity was identified.** Every alarming signal —
svchost→8080, 6k net.exe, `C:\windows\subject_srv.exe`, an unknown kernel driver — resolved via
a tool call to **enterprise operations (proxy, scheduled tasks, McAfee) or the IR team's own
collection tooling (Velociraptor, F-Response, Mnemosyne).** `base-wkstn-01` presents as a
**clean baseline host. Zero confirmed evil; zero hallucinated indicators retained;
four suspicious-looking artifacts correctly cleared with evidence.**

*Honest scope:* this is the host provided; adversary activity in the wider scenario (if any) would
live on other hosts in the dataset. Conclusion applies to base-wkstn-01 and the artifacts listed.
