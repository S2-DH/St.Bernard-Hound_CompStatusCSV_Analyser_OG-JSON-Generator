# 🩸 BHE CompStatus Analyser

**BloodHound Enterprise — SharpHound Collection Status Analyser**

A PowerShell script that parses the `*_compstatus.csv` output from SharpHound Enterprise collection jobs and produces an interactive, self-contained HTML report. Quickly identify which computers failed collection, why they failed, which protocol was involved, and what to fix — without digging through raw CSV files.

Built as part of the **SpecterOps TAM Toolkit**.

---

## 📸 Screenshots

### Interactive menu — single or multi-file comparison

<!-- 
  ============================================================
  SCREENSHOT 1 — PASTE YOUR IMAGE HERE
  Replace the line below with your actual screenshot filename
  e.g. ![PowerShell menu](screenshots/menu.png)
  ============================================================
-->

> 📷 *Screenshot 1 — paste a screenshot of the PowerShell menu here*

```
  +------------------------------------------------------+
  |  BloodHound Enterprise - CompStatus Analyser  v2.1  |
  |  SpecterOps TAM Toolkit                             |
  +------------------------------------------------------+

  [*] Found 3 compstatus file(s) in: C:\BHELogs

    [1]  2026-03-22-09-00-01_1413_compstatus.csv   (18 KB)
    [2]  2026-03-23-09-00-02_1413_compstatus.csv   (19 KB)
    [3]  2026-03-24-10-38-02_1413_compstatus.csv   (21 KB)

    [4]  Compare ALL 3 files - cross-run report

  Enter choice: _
```

---

### HTML report — summary, filters, and results

<!-- 
  ============================================================
  SCREENSHOT 2 — PASTE YOUR IMAGE HERE
  Replace the line below with your actual screenshot filename
  e.g. ![HTML report](screenshots/report.png)
  ============================================================
-->

> 📷 *Screenshot 2 — paste a screenshot of the HTML report open in a browser here*

---

## What it does

SharpHound Enterprise writes a `*_compstatus.csv` after every collection job. Drop this script into the same folder, run it, and it will:

- Auto-discover all `*compstatus*.csv` files in the directory
- Show an interactive menu when multiple files are found
- Parse every row — including malformed rows caused by long embedded exception messages
- Categorise each result by failure type and map it to the underlying collection protocol (WMI, RPC, SMB, LDAP, Remote Registry)
- Generate a timestamped, self-contained HTML report

---

## Quick start

```powershell
# Run from the folder containing your compstatus CSV files
.\Analyze-BHECompStatus.ps1

# Custom output folder
.\Analyze-BHECompStatus.ps1 -OutputFolder "C:\Reports"

# Non-interactive — analyse all files, no prompts
.\Analyze-BHECompStatus.ps1 -NoMenu
```

Reports are written to a `Reports\` subfolder:

```
BHE-CompStatus-SingleRun_2026-03-24_11-05-32.html
BHE-CompStatus-MultiRun_2026-03-24_11-12-45.html
```

---

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-SearchFolder` | Script directory | Where to look for `*compstatus*.csv` files |
| `-OutputFolder` | `.\Reports\` | Where to write the HTML report |
| `-ReportTitle` | `BHE Collection Status Report` | Title prefix in the report header |
| `-NoMenu` | — | Skip the interactive menu |

---

## Report features

| Feature | Details |
|---|---|
| 🩺 Remediation quick-ref | Cards at the top for every failure category found — click to jump to full guidance |
| 📊 Summary cards | Clickable — jump to the relevant section with one click, all filters reset |
| 📈 Failure chart | Donut chart with count and percentage per error category |
| 🔍 Computer spotlight | Sticky search bar — type a name (partial match, comma-separate multiple) |
| 🖥️ Issues table | Filterable by text, category, method, IP; sortable columns |
| ❌ Failures table | Every failed row, filterable by category and method |
| 🔧 Remediation cards | Per-category root cause and fix steps |
| 📋 Full audit log | All rows with method, data type, file, and CSV line number |
| 📤 Export / Print | Export filtered results as CSV or print any section / full report as PDF |

---

## Collection method mapping

| Task | Protocol | Data collected |
|---|---|---|
| ComputerAvailability | TCP Port Scan | Reachability |
| NetWkstaUserEnum | SMB / NetWkstaUserEnum | Active sessions |
| GetMembersInAlias | SMB / SAMRPC | Local group members |
| LSAEnumerateAccountsWithUserRight | RPC / LSARPC | Privileged rights |
| ReadRegistrySettings — DotNetWmi | WMI | NTLM / registry config |
| ReadRegistrySettings — RemoteRegistry | Remote Registry (RRP) | NTLM / registry config |
| ReadComputerProperties / ReadUserProperties | LDAP | Computer / user attributes |

---

## Error categories

| Category | Typical cause |
|---|---|
| **NotActive** | Computer offline, VM powered down, or stale AD object |
| **PortNotOpen** | TCP 445 or TCP 135 blocked by firewall or host policy |
| **AccessDenied** | Service account lacks `NetWkstaUserEnum` rights |
| **StatusAccessDenied** | `SeSecurityPrivilege` missing for LSA enumeration |
| **RPCError** | RPC Endpoint Mapper unreachable or Remote Registry service stopped |
| **RegistryError** | Remote Registry running but LSA key ACL denies read |
| **CollectorError** | Unhandled SharpHound exception — check full error in audit log |

`PortScanSkipped` (SharpHound port-scan optimisation) is treated as `Success`.

---

## Multi-file comparison

Selecting *Compare ALL* produces a cross-run report with every unique computer listed once:

| Traffic light | Meaning |
|---|---|
| 🟢 OK — All Files | Successful in every run |
| 🟠 Mixed | Succeeded in some runs, failed in others |
| 🔴 Failed — All Files | Never succeeded across any run |

---

## Sample test file

`sample_compstatus_100.csv` is included — **104 computers, 680 rows**, covering every error category using *Solo Leveling* character names on the `SOLO-LEVELING.COM` domain. Format matches SharpHound output exactly (UTF-8 BOM, CRLF, space-after-comma).

---

## Requirements

- PowerShell 5.1+ (standard on Windows 10 / Server 2016+)
- `Microsoft.VisualBasic` assembly (included in .NET Framework — present by default)
- A browser to open the report (Chrome recommended)
- Internet access from the browser for Chart.js (`cdn.jsdelivr.net`) — report is otherwise fully self-contained

---

## Files

```
├── Analyze-BHECompStatus.ps1     ← main script
├── sample_compstatus_100.csv     ← test data (all error categories)
├── README.md                     ← this file
└── screenshots/
    ├── menu.png                  ← replace with your screenshot
    └── report.png                ← replace with your screenshot
```

---

*SpecterOps TAM Toolkit — BloodHound Enterprise*
