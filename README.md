[README.md](https://github.com/user-attachments/files/26240990/README.md)
# 🩸 BHE CompStatus Analyser

**BloodHound Enterprise — SharpHound Collection Status Analyser**  
BHE Toolkit · PowerShell 5.1+ · v2.1

A script that parses the `*_compstatus.csv` output from SharpHound Enterprise collection jobs and produces a fast, interactive HTML report. Identify collection failures, the protocol involved, affected subnet, and the remediation steps — without digging through raw CSV.

---

## 📸 Screenshots

### Interactive menu

<!-- Replace with: ![Menu](screenshots/menu.png) -->
> 📷 *Paste a screenshot of the PowerShell menu here*

---

### HTML report

<!-- Replace with: ![Report](screenshots/report.png) -->
> 📷 *Paste a screenshot of the HTML report here*

---

## Quick start

Place the script in the same folder as your compstatus CSV files and run:

```powershell
.\Analyze-BHECompStatus.ps1
```

The script auto-discovers all `*compstatus*.csv` files. If more than one is found it shows a numbered menu. The HTML report is written to a `Reports\` subfolder.

---

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-SearchFolder` | Script directory | Where to look for `*compstatus*.csv` files |
| `-OutputFolder` | `.\Reports\` | Where to write the HTML report |
| `-ReportTitle` | `BHE Collection Status Report` | Title prefix in the report header |
| `-NoMenu` | — | Skip the interactive menu, process all files immediately |

```powershell
# Custom folders
.\Analyze-BHECompStatus.ps1 -SearchFolder "C:\BHELogs" -OutputFolder "C:\Reports"

# Custom title
.\Analyze-BHECompStatus.ps1 -ReportTitle "states.local — Weekly Run"

# Non-interactive (scheduled tasks / automation)
.\Analyze-BHECompStatus.ps1 -NoMenu
```

---

## Interactive menu

When more than one CSV is found:

```
  +------------------------------------------------------+
  |  BloodHound Enterprise - CompStatus Analyser  v2.1  |
  |  BHE Toolkit                                        |
  +------------------------------------------------------+

  [*] Found 3 compstatus file(s) in: C:\BHELogs

    [1]  2026-03-22-09-00-01_1413_compstatus.csv   (18 KB)
    [2]  2026-03-23-09-00-02_1413_compstatus.csv   (19 KB)
    [3]  2026-03-24-10-38-02_1413_compstatus.csv   (21 KB)

    [4]  Compare ALL 3 files — cross-run report

  Enter choice: _
```

Single file selection produces a **Single Run** report. Option `[N+1]` produces a **Multi-Run Comparison** with cross-run traffic lights per computer.

---

## Report sections

### 🩺 Remediation quick-reference
Sits above the summary — one card per failure category present in the data, showing occurrence count and a plain-English summary. Click any card to jump to the full remediation guidance.

### 📊 Summary cards
Seven clickable stat cards. Click any card to jump to the relevant section with all filters reset.

### 📈 Failure distribution chart
Donut chart with per-category count and percentage on hover.

### 🔍 Computer spotlight search
Sticky search bar below the header. Type any computer name (partial match supported, comma-separate for multiple). Each result card shows:
- Traffic-light status · IP · ok/fail counts · CSV line number(s)
- Error category badges · collection method badges
- Quick links: Issues Table · Audit Log · Failures Only

### 🖥️ Computers with Issues
One row per computer with at least one failure. Filters:
- Free-text search
- Error category dropdown
- Failed method dropdown
- **Subnet dropdown** — filters to a specific `/24` (e.g. `172.16.1.x`)
- Hide Unknown IP checkbox
- Sortable columns: Computer, IP, OK count, Failed count, Status

Columns: Computer · IP · Tasks OK · Tasks Failed · Error Categories · **Failed Methods** · Status · File / Line(s)

### ❌ All Failed Results
Every failed row from the CSV. Same filters as the Issues table. Paginated — 100 rows per page with numeric pagination controls. Handles large datasets efficiently.

Columns: Computer · Task · Category · **Method** · **Data Collected** · Status Detail · IP · File / Line

### 🔧 Remediation Guidance
Collapsible card per error category. Each card includes root cause, fix steps, and an **affected computers table** showing Computer · IP · Failed Task(s) · Method — no more scrolling through a wall of comma-separated names.

| Category | Typical cause |
|---|---|
| **NotActive** | Computer offline, VM powered down, or stale AD object |
| **PortNotOpen** | TCP 445 or TCP 135 blocked by firewall or host policy |
| **AccessDenied** | Service account lacks `NetWkstaUserEnum` rights (`SrvsvcSessionInfo` ACL) |
| **StatusAccessDenied** | `SeSecurityPrivilege` missing for `LSAEnumerateAccountsWithUserRight` |
| **RPCError** | RPC Endpoint Mapper unreachable or Remote Registry service stopped |
| **RegistryError** | Remote Registry running but LSA key ACL denies read access |
| **CollectorError** | Unhandled SharpHound exception — review full error in audit log |

### 💤 Not Active
Collapsible list of all computers that failed the availability check only.

### 📋 Full Audit Log
Every row from the source CSV. Paginated — 100 rows per page. Free-text searchable.

### 📤 Export and print
Each section includes:
- **Export CSV** — exports currently filtered/visible rows only (paginated tables export all filtered rows, not just the current page)
- **Print / PDF** — expands section and opens browser print dialog (use *Save as PDF* in Chrome)
- **Export Full Report PDF** (Audit Log) — expands all sections then prints

---

## Collection method mapping

| Task | Protocol | Data collected |
|---|---|---|
| ComputerAvailability | TCP Port Scan | Reachability |
| NetWkstaUserEnum | SMB / NetWkstaUserEnum | Active sessions |
| GetMembersInAlias — * | SMB / SAMRPC | Local group members |
| LSAEnumerateAccountsWithUserRight | RPC / LSARPC | Privileged rights |
| ReadRegistrySettings — DotNetWmi | WMI | NTLM / registry config |
| ReadRegistrySettings — RemoteRegistry | Remote Registry (RRP) | NTLM / registry config |
| ReadComputerProperties / ReadUserProperties | LDAP | Computer / user attributes |

`PortScanSkipped` (SharpHound port-scan optimisation — fast-path availability) is treated as `Success` and does not appear as a failure.

---

## Subnet filter

The subnet dropdown in the Issues and Failures tables automatically populates with every distinct `/24` found in the data. Selecting `172.16.1.x` shows only computers in that subnet; combine with the category and method dropdowns to drill into e.g. *"which WMI failures are in the 10.0.3.x server subnet?"*

> **Note on PortNotOpen / NotActive and Unknown IPs:**
> - **PortNotOpen with a real IP** — SharpHound resolved the hostname in DNS before attempting the port check, so an IP is present. These computers appear correctly in the subnet filter under their `/24`.
> - **PortNotOpen with Unknown IP** — DNS resolution failed as well as the port check, so no IP could be determined. These only appear under *All Subnets*.
> - **NotActive** — the availability check failed before any IP was recorded. The majority of NotActive entries will show `Unknown`, though some environments populate this from a prior DNS lookup.
> - The **Hide Unknown IP** checkbox removes all `Unknown` rows from view, leaving only machines where a subnet can be determined. The **subnet dropdown** simply won't list a subnet for which every computer shows `Unknown`.

---

## Multi-file comparison

Selecting *Compare ALL* runs a cross-run analysis. Additional sections:

**Files Analysed** — per-file success/fail counts and traffic-light status per file.

**All Computers — Cross-Run Status** — every unique computer listed once:

| | Meaning |
|---|---|
| 🟢 OK — All Files | Successful in every run |
| 🟠 Mixed | Succeeded in some runs, failed in others — intermittent |
| 🔴 Failed — All Files | Never succeeded across any analysed run |

The File / Line(s) column groups by file in multi-run mode: `2026-03-24_compstatus.csv: 135, 136 | 2026-03-25_compstatus.csv: 141`.

---

## Performance — large datasets

The Failures and Audit Log tables use **virtual pagination**: row data is stored as a JavaScript array and only 100 rows are rendered into the DOM at a time. Filters and searches run against the data array rather than DOM nodes, so a 7,000-computer / 50,000-row dataset opens and filters as quickly as a 100-row one. Page navigation appears below each table automatically when there is more than one page.

The Issues and Remediation tables render all rows directly (these are bounded by the number of unique computers with failures — typically far smaller).

---

## Sample test file

`sample_compstatus_100.csv` covers all error categories using *Solo Leveling* character names on the `SOLO-LEVELING.COM` domain — **104 computers, 680 rows** across **17 subnets**.

| Subnet | Computers | Role |
|---|---|---|
| `10.0.0.x` | 5 | Domain Controllers |
| `10.0.1.x` | 19 | Core servers |
| `10.0.2.x` | 5 | App servers (AccessDenied) |
| `10.0.3.x` | 5 | Web servers (StatusAccessDenied) |
| `10.0.4.x` | 3 | Servers (RPCError) |
| `10.0.5.x` | 2 | Database servers (RegistryError) |
| `10.0.6.x` | 3 | Citrix (triple failure) |
| `172.16.1.x` | 17 | Site A workstations |
| `172.16.2–4.x` | 10 | Site A/B laptops |
| `172.16.5.x` | 10 | Virtual desktops |
| `192.168.10.x` | 2 | PortScanSkipped hosts |

Error scenarios covered: NotActive · PortNotOpen · ErrorAccessDenied · StatusAccessDenied · RPCError · RegistryError (with full embedded stack trace) · CollectorError · dual failure · triple failure · PortScanSkipped with full success · PortScanSkipped with partial failure.

File format matches SharpHound output exactly: UTF-8 BOM, CRLF line endings, space after comma delimiter, 5-column header.

---

## Requirements

| | |
|---|---|
| PowerShell 5.1+ | Standard on Windows 10 / Server 2016+ |
| `Microsoft.VisualBasic` assembly | Included in .NET Framework (standard on all Windows installs) |
| Browser | Chrome recommended for PDF export |
| Internet (browser) | Chart.js from `cdn.jsdelivr.net` — report is otherwise fully self-contained |

---

## File structure

```
├── Analyze-BHECompStatus.ps1     ← main script
├── sample_compstatus_100.csv     ← test data (all error categories, 17 subnets)
├── README.md
└── screenshots/
    ├── menu.png                  ← replace with your screenshot
    └── report.png                ← replace with your screenshot
```

---

*BHE Toolkit — BloodHound Enterprise*
