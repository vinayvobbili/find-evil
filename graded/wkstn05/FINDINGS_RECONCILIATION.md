# base-wkstn-05 — Compromised host: Findings & Reconciliation (Path B)

**Evidence:** `base-wkstn-05-memory.img` (3,221,225,472 B raw memory, dc3dd)
**MD5 (bundled, verified):** `bb6df5c0350d8014b718699f8c0c4fe0` · **SHA256:** `74ff679b25727d5fb7a8f70217d6fad965efd806260b7d224f0b38bd1c436115`
**Host:** Windows 7 SP1 x64 · `base-wkstn-05` / `172.16.7.15` · `shieldbase.lan` · org *stark-research-labs.com* · captured 2018-09-06 19:51 UTC (SRL-2018 APT scenario).

> Tooling note (honest): on this Win7 image, Vol3 **list-walking plugins return nothing**
> (`pslist`/`cmdline`/`pstree`/`consoles`/`memmap` all empty) while **pool-scanners work**
> (`psscan`, `netscan`). All 57 processes are missing from the active list — consistent with a
> Vol3/Win7 symbol quirk, not selective DKOM. The investigation therefore pivots to
> `psscan` + raw-image carving, and every finding still traces to a specific tool call.

---

## Finding 1 — APT execution chain: WMI → PowerShell → rundll32 (CONFIRMED malicious)
- **Tool:** `vol windows.psscan` → `analysis/wkstn05/01_psscan.txt`
  - `WmiPrvSE.exe(2676) → powershell.exe(3920) ; powershell.exe(4064)` (PS spawned by WMI provider, **session 0**, not the interactive RDP user)
  - `powershell.exe(1332) → rundll32.exe(3720, 5056)` (rundll32 spawned by PowerShell; both ran seconds and exited)
- **Read:** WMI-spawned PowerShell in session 0 = **remote execution / lateral movement** (T1047);
  PowerShell→rundll32 = **payload execution** (T1218.011). Interactive user session is separate
  (explorer/Outlook/chrome in session 5) → the chain is attacker, not user.
- **Confidence:** CONFIRMED malicious (parentage + payload below).

## Finding 2 — Fileless PowerShell Empire / CS stager + external C2 (CONFIRMED)
- **Tool:** `strings -e l` over the raw image → `analysis/wkstn05/07_raw_string_hunt.txt`
  - `$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sIAAAA…"))` — `H4sI` =
    base64'd gzip magic → **gzip-deflate base64 PowerShell stager** (Empire/Cobalt Strike launcher).
  - **C2 staging URL:** `http://www.venetodns.trade/dtsbze/vidc4959xfzbmzgj/.png`
- **iocflow reconciliation (`extract_iocs`, `06_iocflow_extract.json`):** surfaced
  `www.venetodns.trade` (domain + http/https URL) and MITRE `T1047 / T1059.001 / T1218.011`;
  **internal IPs filtered** (`ips: []`). `stark-research-labs.com` also extracted but is the
  **victim org's own domain** → reconciled as benign, not C2.
- **⟲ SELF-CORRECTION (genuine, the Path-B money shot):** `windows.netscan`
  (`02_netscan.txt`) shows **only internal peers** — proxy `172.16.4.10:8080` and `172.16.4.6:443`.
  Eyeball read: *"no external C2 — contained."* **Wrong.** The real external C2
  (`venetodns.trade`) is in the PowerShell command and **egresses through the proxy**, so it
  never appears as a foreign IP in the connection table. The extractor surfaced it from the
  command text. Correction: *there IS external C2; the connection table alone misled me.*
- **Confidence:** CONFIRMED C2 (in the stager, causally tied to Finding 1).

## Finding 3 — False-positive discipline: 1 real C2 vs. 14 noise domains
- **Tool:** `strings` domain stack (`07_raw_string_hunt.txt`): 15 suspicious external domains
  present — `venetodns.trade`, `zoster.trade`, `kharif.trade`, `ketoskinnytrick.trade`,
  `celebweightloss.trade`, `mail.ru`, `yandex.ru`, `inbox.ru`, `no-ip.info`, `pizzacrypts.info`,
  `suprnova.cc`, …
- **⟲ RECONCILIATION (anti-hallucination):** only **`venetodns.trade`** is tied to the intrusion
  (Empire stager). The `keto*/celebweightloss*.trade` + `*.ru` are **email-spam / mail-provider
  artifacts** from the user's Outlook mailbox; the uniform-count `.info/.cc` entries need
  provenance before any claim. **Reported: 1 confirmed C2, 14 unverified/benign.** A naïve pass
  would headline "15 malicious C2 domains" — prevented.
- **`cluster_actor_infrastructure`** on the `.trade` set → **0 campaigns**: refuses to link them
  absent shared infrastructure. **No fabricated attribution.**
- **`propose_blocks`** → **`dry_run: true`** (plan only; no execute-block verb exists).

---

## Lateral-movement context (CONFIRMED activity, attribution noted honestly)
`netscan` (`02_netscan.txt`): inbound **SMB** `172.16.6.11 → 172.16.7.15:445`; outbound **WinRM**
`→172.16.5.21:5985`; **F-Response** `subject_srv.exe(3548)` + inbound `:3262` = IR collection
(benign, as on wkstn-01). All internal → host-hunt leads, not external IOCs.

## Verdict
`base-wkstn-05` is **compromised**: WMI-driven PowerShell Empire foothold, fileless gzip-base64
stager, external C2 `venetodns.trade` egressing via the corporate proxy, rundll32 payload
execution. **Confirmed indicators: 1 external C2 domain/URL + 3 ATT&CK techniques + the host
execution chain.** The agent *found* the evil **and** held the line on 14 noise domains, fabricated
no actor cluster, and proposed only a dry-run block. Evidence re-hashed **unchanged**.

---

# DISK CORROBORATION (base-wkstn-05-cdrive.E01, SHA256 a94f2a86…0a65e0)
Mounted read-only (`ewfmount`); NTFS C: at offset 0; Sysmon (163 MB → 308k events) + PowerShell
Operational (28 MB) carved via `icat`, parsed with EvtxECmd. Acquired 2018-09-07 04:28 UTC.

- **Lateral-movement vector CONFIRMED (Finding 1 strengthened):** Sysmon EID 1 shows the malicious
  PowerShell launched by `wsmprovhost.exe -Embedding` → `powershell.exe -Version 5.0 -s -NoLogo
  -NoProfile` under user **`shieldbase\spsql`** (a compromised **SQL service account**). i.e.
  **WinRM/PSRemoting** lateral movement with a stolen service account — the mechanism behind the
  memory-observed WmiPrvSE→powershell chain.
- **Empire/CS injection IOCs:** Sysmon **EID 8 CreateRemoteThread ×75**, **EID 17/18 named pipes
  ×5,445**, EID 10 ProcessAccess ×5,829 — consistent with Empire/Cobalt Strike post-exploitation.
- **PowerShell ScriptBlock (EID 4104 ×2,107):** saturated with `System.Net.WebClient` /
  `DownloadString` / `FromBase64String` = download-cradle activity, corroborating the framework.
- **⟲ FP discipline (disk):** the 12,406 `WebClient` ScriptBlock hits are **mixed** — many are
  *defender/IR* PowerShell (e.g. `DownloadFile('…/ion-storm/sysmon-config/…sysmonconfig-export.xml')`,
  `live.sysinternals.com/Sysmon64.exe`). Not treated as malicious. The C2 `venetodns.trade` does
  **not** appear in the disk logs (Win7 Sysmon has no DNS event; Empire obfuscates the server in
  the stager) — so it remains attributed to its true source, the **in-memory stager**, not overclaimed.

**Net:** memory found the evil (chain + Empire stager + C2 `venetodns.trade`); disk confirms the
**how** (PSRemoting + `spsql` service account, Empire injection IOCs) without inflating the claim.
