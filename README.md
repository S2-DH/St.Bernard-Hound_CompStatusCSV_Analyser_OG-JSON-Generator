[SharpHound_CompstatusCSV_Analyser_README.md](https://github.com/user-attachments/files/26375123/SharpHound_CompstatusCSV_Analyser_README.md)

**# SharpHound Compstatus.csv Analyser**

> *Image: Freepik Premium resource. Free users must attribute: "Image by pch.vector on Freepik". Premium subscribers may use without attribution.*


**Project:** SharpHound_CompstatusCSV_Analyser  
**Version:** 3.0  
**Script:** `SharpHound_CompstatusCSV_Analyser.ps1`  
**Requires:** PowerShell 5.1+, BloodHound Enterprise or CE v8.0+ (PostgreSQL backend)

---

## Overview

SharpHound CompStatus CSV analyser extends to produce a **BloodHound OpenGraph JSON** from your SharpHound compstatus CSV data. Once ingested into BHE, it graphs every SharpHound collector-to-computer relationship with typed edges representing the specific collection failure (or success) — making collection coverage gaps and connectivity issues visible directly in the BHE Explore graph.

The graph model is:

```
(SBHCollector) ──[SBH_<ErrorType>]──► (SBHComputerOK | SBHComputerFail)
```

Custom Font Awesome icons visually distinguish node types at a glance:

| Node Kind | Icon | Colour | Meaning |
|---|---|---|---|
| `SBHCollector` | `house-signal` | Blue `#3b82f6` | The SharpHound collector host |
| `SBHComputerOK` | `house-circle-check` | Green `#22c55e` | All tasks succeeded |
| `SBHComputerFail` | `house-circle-xmark` | Red `#ef4444` | At least one task failed |
| `SBHComputerUnknown` | `skull-crossbones` | Dark slate `#1e293b` | No IP and no SID — identity unresolvable |

---

## Screenshots

### PowerShell Console Output
<img width="2945" height="1199" alt="image" src="https://github.com/user-attachments/assets/d036a114-8fcf-49bd-8d86-df2454d47a4c" />

*Console output from a full run with `-ExportOpenGraph -UploadIcons`. Shows export summary, edge type breakdown, Cypher query reference, and icon registration confirmation.*

### HTML Analysis Report
<img width="1863" height="910" alt="image" src="https://github.com/user-attachments/assets/9cc06660-b9bf-4698-a9b2-e91a8c1a4a76" />

*The HTML report generated alongside the OG JSON. Includes interactive filters, remediation guidance per failure category, and the computer spotlight search.*

### BHE Explore - Graph View
<img width="1510" height="1141" alt="image" src="https://github.com/user-attachments/assets/5391602c-d3c8-44a9-9216-3d10baf0133c" />

*After ingesting the OG JSON into BloodHound Explore. The collector node sits at the centre; green/red/skull icons show collection outcome per computer.*

### Custom Node Icons
<img width="297" height="75" alt="image" src="https://github.com/user-attachments/assets/4d84c957-9f81-4011-8517-103849c6809b" />


*Blue = collector
Green = full success
Red = at least one failure
Skull = no IP or SID resolved.*

*Note: Red nodes can show the EDGE "SBH_CollectionOK", this would imply Collection is possible, however there is also a failed call (In this instance "SBH_RPCError") - You would need to review the node to see the additional failed relationships.

**_Example:_**
<img width="1299" height="217" alt="image" src="https://github.com/user-attachments/assets/17573776-09f2-4b8e-868a-a0d71a77b51b" />

---

## Quick Start

```powershell
# 1. Export OpenGraph JSON (upload manually to BHE afterwards)
.\BHE_Analyse_CompStatusCSV.ps1 -ExportOpenGraph

# 2. Export + auto-upload icons to BHE in one step
.\BHE_Analyse_CompStatusCSV.ps1 -ExportOpenGraph -UploadIcons `
    -BHEUrl     "https://your-bhe-instance.local" `
    -BHETokenId "your-token-id" `
    -BHETokenKey "your-token-key"

# 3. Full run — no menu, named collector, separate output folder, icons uploaded
.\BHE_Analyse_CompStatusCSV.ps1 -NoMenu -ExportOpenGraph -UploadIcons `
    -CollectorName  "SH-SVC01" `
    -OGOutputFolder "C:\BHE\OpenGraph" `
    -BHEUrl         "https://your-bhe-instance.local" `
    -BHETokenId     "your-token-id" `
    -BHETokenKey    "your-token-key"

# 4. **Large environments ** — split the json into chunks when file exceeds ~10MB
.\SharpHound_CompstatusCSV_Analyser.ps1 -ExportOpenGraph -ChunkSize 500

Note: This Produces _part01.json, _part02.json etc. — Combine to a zip file to upload.
```

---

## New Parameters

| Parameter | Type | Description |
|---|---|---|
| `-ExportOpenGraph` | Switch | Generates the SharpHound JSON alongside the HTML report |
| `-CollectorName` | String | Label for the collector node. Defaults to `$env:COMPUTERNAME` |
| `-OGOutputFolder` | String | Output folder for JSON and Cypher pack. Defaults to the HTML report folder |
| `-UploadIcons` | Switch | Uploads custom node icons to BHE after export. Requires `-BHEUrl` + auth |
| `-BHEUrl` | String | Base URL of your BHE instance e.g. `https://sololeveling.bhe.local` |
| `-BHETokenId` | String | API Token ID from BHE Settings → API Keys |
| `-BHETokenKey` | String | API Token Key from BHE Settings → API Keys |
| `-BHEBearerToken` | String | JWT Bearer token (alternative to TokenId/Key — copy from API Explorer) |
| `-ChunkSize` | Int | Max computers per output JSON. Default `0` = single file. Use when file exceeds BHE's ~10MB upload limit. Example: `-ChunkSize 500` |

---

## Output Files

Each run with `-ExportOpenGraph` produces two files alongside the HTML report:

| File | Description |
|---|---|
| `SharpHound_CompstatusCSV_Analyser_OG_<timestamp>.json` | OpenGraph payload — upload to BHE via Explore → Upload Data |

---

## Ingesting Into BHE

### Step 1 — Upload the graph data

**BHE UI:** Explore → Upload Data → select `SharpHound_<timestamp>.json`

**API (PowerShell):**
```powershell
# Multipart upload via BHE API
$form = @{ file = Get-Item ".\SharpHound_2026-03-30.json" }
Invoke-RestMethod -Uri "https://your-bhe.local/api/v2/file-upload" `
    -Method Post -Headers $authHeaders -Form $form
```

### Step 2 — Register custom icons (once only)

Icons persist in BHE once registered. You only need to do this once per instance — not on every CSV run.

**Option A — Script (recommended):**
```powershell
.\BHE_Analyse_CompStatusCSV.ps1 -ExportOpenGraph -UploadIcons `
    -BHEUrl "https://your-bhe.local" -BHETokenId "..." -BHETokenKey "..."
```

**Option B — BHE API Explorer (no scripting needed):**
1. BHE menu → **API Explorer**
2. **Custom Node Management** → `POST /api/v2/custom-nodes` → **Try it out**
3. Paste the payload below → **Execute** → expect `201`

```json
{
  "custom_types": {
    "SBHCollector": {
      "icon": { "type": "font-awesome", "name": "house-signal", "color": "#3b82f6" }
    },
    "SBHComputerOK": {
      "icon": { "type": "font-awesome", "name": "house-circle-check", "color": "#22c55e" }
    },
    "SBHComputerFail": {
      "icon": { "type": "font-awesome", "name": "house-circle-xmark", "color": "#ef4444" }
    },
    "SBHComputerUnknown": {
      "icon": { "type": "font-awesome", "name": "skull-crossbones", "color": "#1e293b" }
    }
  }
}
```

### Step 3 — Refresh BHE Explore

Icons and new nodes appear after a page refresh.

---

## Edge Types

Each edge represents a specific SharpHound collection outcome. One edge per unique error category per computer.

| Edge Kind | Meaning | Key Tasks |
|---|---|---|
| `SBH_CollectionOK` | All tasks succeeded | All |
| `SBH_NotActive` | Computer offline / unreachable | `ComputerAvailability` |
| `SBH_PortNotOpen` | TCP 445 / 135 blocked | `ComputerAvailability` |
| `SBH_AccessDenied` | Insufficient privileges | `NetWkstaUserEnum`, `LSAEnumerateAccountsWithUserRight` |
| `SBH_RPCError` | RPC server unavailable | `SamConnect`, `LSAOpenPolicy`, RPC calls |
| `SBH_RegistryError` | Remote registry access denied | `ReadRegistrySettings` |
| `SBH_CollectorError` | SharpHound collector-side exception | Any |
| `SBH_NonWindowsOS` | Non-Windows OS, collection skipped | `ComputerAvailability` |
| `SBH_Timeout` | RPC / SMB operation timed out | `NetWkstaUserEnum`, `SamConnect`, `OpenAlias` |
| `SBH_NumericError` | Raw Win32 / NTSTATUS error code | Any |
| `SBH_Other` | Uncategorised / unmapped error | Any |

Each edge carries these properties:

| Property | Description |
|---|---|
| `category` | Error category name |
| `occurrence_count` | Number of CSV rows matching this category for this computer |
| `tasks_failed` | Comma-separated list of SharpHound task names |
| `collection_methods` | Protocols involved (SMB, RPC, WMI etc.) |
| `ip_address` | IP address of the target computer |
| `source` | Always `SharpHound` |
| `source_files` | CSV filename(s) — populated in multi-file mode |

---

## Node Properties

### SBHCollector

| Property | Description |
|---|---|
| `name` | Collector hostname (uppercase) |
| `displayname` | Collector hostname |
| `description` | `SharpHound Collector` |
| `generated_at` | UTC timestamp of JSON generation |
| `source` | `SharpHound` |

### SBHComputerOK / SBHComputerFail / SBHComputerUnknown

| Property | Description |
|---|---|
| `name` | Computer name from CSV (uppercase) |
| `displayname` | Computer name from CSV |
| `objectsid` | AD SID from CSV ObjectID column (if present) — for correlation with BHE AD data |
| `ipaddress` | IP address from CSV |
| `trafficlight` | `green`, `orange`, or `red` |
| `source` | `SharpHound` |

> **SBHComputerUnknown** is assigned when a computer has neither an IP address nor an AD SID in the CSV — SharpHound recorded the machine name but could not resolve anything further. These are the most invisible computers in your environment and typically the hardest to remediate. Common causes: stale AD objects, DNS failures, or machines in isolated network segments.

The `objectsid` property lets you correlate SharpHound nodes with existing BHE Computer nodes from SharpHound data:
```cypher
MATCH (sbh:SBHComputerFail), (ad:Computer)
WHERE sbh.objectsid = ad.objectid
RETURN sbh.name, ad.name, ad.operatingsystem
```

---

## Cypher Queries

All queries below are confirmed working against BHE self-hosted (AGE/CySQL backend).

```cypher
-- Show the collector node
MATCH (c:SBHCollector) RETURN c LIMIT 5

-- All paths from collector across all edge types
MATCH p=(c:SBHCollector)-[r:SBH_AccessDenied|SBH_CollectionOK|SBH_CollectorError|SBH_NonWindowsOS|SBH_NotActive|SBH_NumericError|SBH_PortNotOpen|SBH_RegistryError|SBH_RPCError|SBH_Timeout]->(comp) RETURN p

-- All computers with full successful collection (green house)
MATCH p=(c:SBHCollector)-[]->(comp:SBHComputerOK) RETURN p

-- All computers connected to collector regardless of edge type
MATCH p=(c:SBHCollector)-[]-() RETURN p

-- Computers where CollectionOK edge leads to a green node
MATCH p=(c:SBHCollector)-[:SBH_CollectionOK]->(comp:SBHComputerOK) RETURN p

-- All failed computers as standalone nodes (red house)
MATCH (c:SBHComputerFail) RETURN c

-- Access denied - collector account missing privileges
MATCH p=(c:SBHCollector)-[:SBH_AccessDenied]->() RETURN p

-- RPC unavailable - TCP 135 blocked or RPC service down
MATCH p=(c:SBHCollector)-[:SBH_RPCError]->() RETURN p

-- Collector exception - SharpHound threw an unhandled error
MATCH p=(c:SBHCollector)-[:SBH_CollectorError]->() RETURN p

-- Remote registry denied - RRP service or ACL issue
MATCH p=(c:SBHCollector)-[:SBH_RegistryError]->() RETURN p

-- Timeout - machine reachable but RPC/SMB call did not complete
MATCH p=(c:SBHCollector)-[:SBH_Timeout]->() RETURN p

-- Port not open - TCP 445/135 blocked at host or network level
MATCH p=(c:SBHCollector)-[:SBH_PortNotOpen]->() RETURN p

-- Non-Windows OS - SMB/RPC collection not applicable
MATCH p=(c:SBHCollector)-[:SBH_NonWindowsOS]->() RETURN p

-- Not active - machine did not respond to availability check
MATCH p=()-[:SBH_NotActive]->() RETURN p

-- Numeric error - raw Win32/NTSTATUS code, check Status in HTML report
MATCH p=()-[:SBH_NumericError]->() RETURN p

-- Check if any uncategorised errors exist (errors if no edges present in graph)
MATCH ()-[r:SBH_Other]->() RETURN count(r)

-- Unknown computers - no IP and no SID recorded by SharpHound
MATCH p=(c:SBHCollector)-[r]->(comp:SBHComputerUnknown) RETURN p
```


## Authentication — API Key Setup

Generate an API token in BHE for use with `-UploadIcons`:

1. BHE UI → **Settings → API Keys → Create API Key**  
   *or* top-right corner → **My Profile → API Key Management → Create Token**
2. Give it a descriptive name (e.g. `SharpHound`)
3. Save both the **Token ID** and **Token Key** — the key is shown only once
4. Pass them to the script as `-BHETokenId` and `-BHETokenKey`

Authentication uses BHE's standard three-step chained HMAC-SHA256 scheme:
```
Step 1: HMAC( tokenKey,  METHOD + ENDPOINT ) → hash1
Step 2: HMAC( hash1,     dateKey            ) → hash2   (dateKey = first 13 chars of timestamp)
Step 3: HMAC( hash2,     requestBody        ) → sig
```

Sent as three headers: `Authorization: bhesignature <tokenId>`, `RequestDate`, `Signature`.

---
## Large Environments — Chunking

BHE's UI upload has a file size limit of approximately 10MB. For large environments (thousands of computers) the generated JSON may exceed this. Use `-ChunkSize` to split the output into multiple smaller files.
```powershell
# Split into 500-computer chunks
.\SharpHound_CompstatusCSV_Analyser.ps1 -ExportOpenGraph -ChunkSize 500

# Adjust if files are still too large
.\SharpHound_CompstatusCSV_Analyser.ps1 -ExportOpenGraph -ChunkSize 200
```

The script will output each part file path in the console:
```
  OG JSON files (upload each separately):
    Part 01  : C:\...\SharpHound_CompstatusCSV_Analyser_OG_2026-03-30_part01.json
    Part 02  : C:\...\SharpHound_CompstatusCSV_Analyser_OG_2026-03-30_part02.json
```

Upload each file individually via **Explore -> Upload Data**. BHE merges them into the same graph. The collector node (`SBHCollector`) is included in every chunk so edges always resolve regardless of upload order. You can upload a subset to see a partial graph first — upload more chunks to expand it.

**Choosing a chunk size:** Start with `-ChunkSize 500`. If files are still over ~8MB reduce to `-ChunkSize 300`.
---

## Known Limitations

**AGE/CySQL (self-hosted BHE):**
- `STARTS WITH` on `type(r)` is unsupported — use explicit edge kind names
- Any edge kind referenced in a pipe list (`r:A|B|C`) must have at least one edge in the graph or the query fails — the script builds pipe lists dynamically per run to handle this

**OpenGraph:**
- SharpHound nodes (`SBHComputerOK`, `SBHComputerFail`) are separate from BHE's native SharpHound `Computer` nodes — they do not merge automatically
- Use the `objectsid` property to manually correlate with AD Computer nodes if needed
- Icons must be registered once via the API before they appear — they are not part of the graph JSON

**Re-ingesting:**
- Each JSON upload adds new nodes/edges. If you re-run and re-ingest, you may end up with duplicate SharpHound nodes from previous runs. Clear old data via Cypher before re-ingesting if needed:
```cypher
MATCH (n:SBHCollector) DETACH DELETE n
MATCH (n:SBHComputerOK) DETACH DELETE n
MATCH (n:SBHComputerFail) DETACH DELETE n
MATCH (n:SBHComputerUnknown) DETACH DELETE n
```

---

## Files Reference

| File | Description |
|---|---|
| `BHE_Analyse_CompStatusCSV.ps1` | Main script — SharpHoundHound CompStatusCSV Analyser v1 |
| `SharpHound_<timestamp>.json` | OpenGraph graph payload — upload to BHE |
| `SharpHound_CompstatusCSV_Analyser_Report_<mode>_<timestamp>.html` | HTML analysis report |

---

*SharpHound - CompStatus CSV Analyser & OG JSON Generator v1 — SDH / SpecterOps TAM*
