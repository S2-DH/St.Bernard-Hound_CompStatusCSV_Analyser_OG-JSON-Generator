[README.md](https://github.com/user-attachments/files/26242330/README.md)
[README.md](https://github.com/user-attachments/files/26242330/README.md)
[README.md](https://github.com/user-attachments/files/26242330/README.md)
# 🩸 BHE CompStatus Analyser

**BloodHound Enterprise — SharpHound Collection Status Analyser**  
SpecterOps TAM Toolkit · PowerShell 5.1+

Parses the `*_compstatus.csv` output from SharpHound Enterprise collection jobs and produces a fast, interactive HTML report. Identify which computers failed collection, the protocol involved, the affected subnet, and the remediation steps — without digging through raw CSV.

---

## 📸 Screenshots

### Interactive menu

<!-- Replace with: ![Menu](screenshots/menu.png) -->
> <img width="836" height="531" alt="image" src="https://github.com/user-attachments/assets/da7560bf-e928-4058-8dcc-ea6f2859b097" />
<img width="836" height="531" alt="image" src="https://github.com/user-attachments/assets/da7560bf-e928-4058-8dcc-ea6f2859b097" />
<img width="836" height="531" alt="image" src="https://github.com/user-attachments/assets/da7560bf-e928-4058-8dcc-ea6f2859b097" />


---

### HTML report

<!-- Replace with: ![Report](screenshots/report.png) -->
> <img width="1873" height="775" alt="image" src="https://github.com/user-attachments/assets/5d6a1d84-7ff6-4fda-b55a-5e938d3611e8" />
<img width="1873" height="775" alt="image" src="https://github.com/user-attachments/assets/5d6a1d84-7ff6-4fda-b55a-5e938d3611e8" />
<img width="1873" height="775" alt="image" src="https://github.com/user-attachments/assets/5d6a1d84-7ff6-4fda-b55a-5e938d3611e8" />


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
  |  SpecterOps TAM Toolkit                             |
  +------------------------------------------------------+

  [*] Found 3 compstatus file(s) in: C:\BHELogs

    [1]  2026-03-22-09-00-01_1413_compstatus.csv   (18 KB)
    [2]  2026-03-23-09-00-02_1413_compstatus.csv   (19 KB)
    [3]  2026-03-24-10-38-02_1413_compstatus.csv   (21 KB)

    [4]  Compare ALL 3 files — cross-run report

  Enter choice: _
```

Single file → **Single Run** report. Option `[N+1]` → **Multi-Run Comparison** with cross-run traffic lights per computer.

---

## Report sections

All sections are collapsible. A **↑ Top** button in the sticky search bar fades in once you scroll down, providing quick navigation back to the top of the page.

### 🩺 Remediation quick-reference
Sits above the summary. One card per failure category present in the data, showing occurrence count and a one-line description. Click any card to jump to the full guidance and highlight the matching section.

### 📊 Summary cards
Seven clickable stat cards — click to jump to the relevant section with all filters reset. Where applicable, clicking applies a filter automatically:

| Card | Destination | Filter applied |
|---|---|---|
| Total task results | Full Audit Log | None — all rows |
| Unique computers | Computers with Issues | None |
| Successful | Full Audit Log | Success rows only |
| Failed | All Failed Results | None |
| Not Active | Not Active section | — |
| Fully successful | Full Audit Log | Success rows only |
| Task-level errors | Computers with Issues | Only computers with non-availability failures |

When a filter is active the section heading shows a subtitle indicating what is being shown and how many rows match.

### 📈 Failure distribution chart
Donut chart with count and percentage per error category on hover.

### 🔍 Computer spotlight search
Sticky search bar pinned below the header, always visible while scrolling. Type any computer name — partial matches supported, comma-separate for multiple. Each result card shows:
- Traffic-light status · IP address · ok/fail counts · CSV line number(s)
- Error category badges · collection method badges
- Action links: **Issues Table** · **Audit Log** · **Failures Only**

Pressing **✕** or `Escape` clears the search and resets all table filters.

### 🖥️ Computers with Issues
One row per computer with at least one failure. Shows row count above the table, updated live as filters change.

**Filters:** free-text search · error category dropdown · failed method dropdown · subnet dropdown (see below) · Hide Unknown IP checkbox · sortable columns

**Columns:** Computer · IP · Tasks OK · Tasks Failed · Error Categories · Failed Methods · Status · File / Line(s)

### ❌ All Failed Results
Every failed row. Paginated — 100 rows per page. Same filter set as the Issues table. Computer name is shown only on the first row for each computer; subsequent rows are indented with a left border, and a task count badge shows how many tasks failed for that machine. Groups alternate background shade so each computer's rows are visually distinct.

**Columns:** Computer · Task · Category · Method · Data Collected · Status Detail · IP · File / Line

### 🔧 Remediation Guidance
One collapsible card per error category. Each card includes root cause, fix steps, and an **affected computers table** (Computer · IP · Failed Task(s) · Method) replacing the old comma-separated name list.

| Category | Typical cause |
|---|---|
| **NotActive** | Computer offline, VM powered down, or stale AD object |
| **PortNotOpen** | TCP 445 or TCP 135 blocked by firewall or host policy |
| **AccessDenied** | Service account lacks `NetWkstaUserEnum` rights |
| **StatusAccessDenied** | `SeSecurityPrivilege` missing for `LSAEnumerateAccountsWithUserRight` |
| **RPCError** | RPC Endpoint Mapper unreachable, Remote Registry stopped, or `StatusRpcServerUnavailable` |
| **RegistryError** | Remote Registry running but LSA key ACL denies read |
| **CollectorError** | Unhandled SharpHound exception or `StatusInvalidParameter` |
| **NonWindowsOS** | Linux/macOS detected — SharpHound skips SMB/RPC collection |
| **Timeout** | RPC/SMB call timed out (heavy load or network latency) |
| **NumericError** | Raw Win32/NTSTATUS code (53 = network path not found, 50 = not supported) |

### 💤 Not Active
Collapsible list of all computers that failed the availability check. Shows the total count and includes **Export CSV** and **Print / PDF** buttons.

### 📋 Full Audit Log
Every row from the source CSV. Paginated — 100 rows per page, grouped by computer with alternating row shading. Free-text searchable.

### 📤 Export and print
Every section includes:
- **Export CSV** — exports currently filtered rows (paginated tables export all filtered rows across all pages, not just the visible page)
- **Print / PDF** — expands the section and opens the browser print dialog (use *Save as PDF* in Chrome)
- **Export Full Report PDF** (Audit Log) — expands all sections then prints the whole report

---

## Collection method mapping

| Task | Protocol | Data collected |
|---|---|---|
| ComputerAvailability | TCP Port Scan | Reachability |
| NetWkstaUserEnum | SMB / NetWkstaUserEnum | Active sessions |
| GetMembersInAlias — * | SMB / SAMRPC | Local group members |
| OpenAlias — * | SMB / SAMRPC | Local group handle |
| SamConnect | SMB / SAMRPC | SAM connection |
| OpenDomain — * | SMB / SAMRPC | SAM domain handle |
| GetAliases — * | SMB / SAMRPC | Local group enumeration |
| GetDomains | SMB / SAMRPC | SAM domain enumeration |
| LSAEnumerateAccountsWithUserRight | RPC / LSARPC | Privileged rights |
| LSAOpenPolicy | RPC / LSARPC | LSA policy handle |
| ReadRegistrySettings — DotNetWmi | WMI | NTLM / registry config |
| ReadRegistrySettings — RemoteRegistry | Remote Registry (RRP) | NTLM / registry config |
| ReadComputerProperties / ReadUserProperties | LDAP | Computer / user attributes |

`PortScanSkipped` (SharpHound fast-path availability — port scan bypassed) is treated as `Success`.

---

## Subnet filter

The subnet dropdown in the Issues and Failures tables auto-populates with every distinct `/24` present in the data, sorted numerically. Two fixed options always appear at the top:

- **All Subnets** — show everything
- **Unknown IP** — show only computers where no IP was recorded

Selecting a real subnet (e.g. `172.16.1.x`) combined with a category or method filter lets you ask questions like *"which WMI failures are in the 10.0.3.x server subnet?"*

> **Note on Unknown IPs:**
> - **PortNotOpen with a real IP** — DNS resolved before the port check failed. These appear in the correct subnet bucket.
> - **PortNotOpen with Unknown IP** — DNS also failed. These appear only under *All Subnets* or *Unknown IP*.
> - **NotActive** — most entries show `Unknown` as the availability check failed before an IP was recorded.
> - The **Hide Unknown IP** checkbox and **Unknown IP** subnet option are mutually exclusive — selecting one disables the other.

---

## Multi-file comparison

Selecting *Compare ALL* produces a cross-run analysis with two additional sections:

**Files Analysed** — per-file row counts, success/fail, and traffic-light per file.

**All Computers — Cross-Run Status** — every unique computer listed once:

| | Meaning |
|---|---|
| 🟢 OK — All Files | Successful in every run |
| 🟠 Mixed | Succeeded in some runs, failed in others — intermittent |
| 🔴 Failed — All Files | Never succeeded across any analysed run |

File / Line(s) groups by file: `2026-03-24_compstatus.csv: 135, 136 | 2026-03-25_compstatus.csv: 141`.

---

## Performance — large datasets

The Failures and Full Audit Log tables use **virtual pagination**: row data is stored as a JavaScript array and only 100 rows are rendered into the DOM at a time. Filters run against the array rather than DOM nodes, so a 70,000-row dataset from a large environment opens and filters as fast as a 100-row file.

The Issues and Remediation tables render all rows directly — these are bounded by the number of unique computers with failures, typically far smaller than the total row count.

---

## Sample test file

`sample_compstatus_100.csv` — **116 unique computers · 725 rows · 18 subnets** — using *Solo Leveling* character names on the `SOLO-LEVELING.COM` domain.

**Error scenarios covered:**

| Scenario | Computers |
|---|---|
| Fully successful (DCs + servers) | 12 |
| NotActive with real IP | 58 |
| NotActive with Unknown IP | 3 |
| PortNotOpen with real IP | 6 |
| PortNotOpen with Unknown IP | 2 |
| ErrorAccessDenied (NetWkstaUserEnum) | 5 |
| StatusAccessDenied (LSA) | 5 |
| Dual denied (both NetWksta + LSA) | 7 |
| RPCError | 4 |
| RegistryError (with full embedded stack trace) | 2 |
| Triple failure combo | 3 |
| NonWindowsOS with real IP | 4 |
| NonWindowsOS with Unknown IP | 1 |
| PortScanSkipped + full success | 2 |
| PortScanSkipped + partial failure | 2 |
| Timeout (RPC/SMB call timed out) | 2 |
| StatusRpcServerUnavailable (NTSTATUS form) | 1 |
| Numeric error codes (53, 50) | 1 |
| StatusInvalidParameter | 1 |
| New SAM/LSA tasks (SamConnect, OpenAlias, LSAOpenPolicy etc.) | 1 |

File format matches SharpHound output exactly: UTF-8 BOM, CRLF line endings, space after comma delimiter, 5-column header.

---

## Requirements

| | |
|---|---|
| PowerShell 5.1+ | Standard on Windows 10 / Server 2016+ |
| `Microsoft.VisualBasic` assembly | Included in .NET Framework — present by default |
| Browser | Chrome recommended for PDF export |
| Internet (browser) | Chart.js from `cdn.jsdelivr.net` — report is otherwise fully self-contained |

---

## File structure

```
├── Analyze-BHECompStatus.ps1     ← main script
├── sample_compstatus_100.csv     ← test data (all error categories, 18 subnets)
├── README.md
└── screenshots/
    ├── menu.png                  ← replace with your screenshot
    └── report.png                ← replace with your screenshot
```

---

*SpecterOps TAM Toolkit — BloodHound Enterprise*
