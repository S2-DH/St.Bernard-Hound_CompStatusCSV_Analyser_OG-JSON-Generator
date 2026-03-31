<#
.SYNOPSIS
    StBernard-SharpHound - compstatusCSV analyser
    Analyses BloodHound Enterprise SharpHound compstatus CSV files and produces
    a categorised HTML report and OpenGraph JSON for BloodHound ingest.

.DESCRIPTION
    Automatically discovers *_compstatus.csv files in the SearchFolder (defaults to
    the script's own directory). If multiple files are found, presents an interactive
    menu allowing you to analyse a single run or compare across all runs.

    Multi-file mode produces a unified computer list (no duplicates) with a traffic-
    light status per computer across every file analysed:
      Green   -  successful in every file it appeared in
      Orange  -  mixed results across files (some success, some fail)
      Red     -  failed in every file it appeared in

    Handles malformed CSV rows caused by long SharpHound error messages that contain
    embedded commas and quotes (common for registry/RPC exceptions).

.PARAMETER OutputFolder
    Folder where the HTML report will be written. Created if it does not exist.
    Defaults to a "Reports" subfolder in the script directory.

.PARAMETER SearchFolder
    Folder to search for *_compstatus.csv files.
    Defaults to the script's own directory.

.PARAMETER ReportTitle
    Optional title prefix for the report.

.PARAMETER NoMenu
    Skip the interactive menu and analyse all discovered CSV files immediately.

.PARAMETER ExportOpenGraph
    In addition to the HTML report, emit a StBernardHound OpenGraph JSON file
    that can be uploaded to BloodHound Enterprise or Community Edition to graph
    all SharpHound collector <-> computer connectivity edges.
    File is named StBernardHound_<timestamp>.json.

.PARAMETER CollectorName
    Friendly name for the SharpHound collector node in the OpenGraph output.
    Defaults to the local machine name ($env:COMPUTERNAME).

.PARAMETER OGOutputFolder
    Folder for the StBernardHound OpenGraph JSON output.
    Defaults to the same OutputFolder used by the HTML report.

.PARAMETER ChunkSize
    Maximum number of computers per output JSON file. Default 0 = single file.
    Use when large environments produce files that exceed BHE's UI upload limit
    (~10MB). Each chunk file is uploaded separately via Explore -> Upload Data
    and they all land in the same graph. Example: -ChunkSize 500

.PARAMETER UploadIcons
    After exporting the JSON, automatically upload the StBernardHound custom
    node icons to BHE via PUT /api/v2/custom-nodes. Requires -BHEUrl,
    -BHETokenId, and -BHETokenKey.

.PARAMETER BHEUrl
    Base URL of your BHE instance. Example: https://sololeveling.bhe.local

.PARAMETER BHETokenId
    BHE API Token ID. Used with -BHETokenKey to sign requests via HMAC.
    Generate under Settings -> API Keys in the BHE UI.

.PARAMETER BHETokenKey
    BHE API Token Key. Used with -BHETokenId to sign requests via HMAC.
    Shown once at creation time in Settings -> API Keys.

.PARAMETER BHEBearerToken
    BHE JWT Bearer Token. Simplest option  -  copy from BHE API Explorer
    (menu -> API Explorer -> Authorize). Valid for the duration of your session.

.EXAMPLE
    # Run interactively from script directory
    .\StBernard-SharpHound-compstatusCSV-analyser.ps1

.EXAMPLE
    # Specify folders explicitly
    .\BHE_Analyse_CompStatusCSV.ps1 -SearchFolder "C:\BHELogs" -OutputFolder "C:\Reports"

.EXAMPLE
    # Non-interactive - analyse all CSVs found, no prompts
    .\BHE_Analyse_CompStatusCSV.ps1 -NoMenu

.NOTES
    Author  : SDH / SpecterOps TAM
    Version : 3.0
    Project : St.Bernard-Hound - CompStatus CSV Analyser and OG JSON Generator v1
    Requires: PowerShell 5.1+
    Context : BloodHound Enterprise - session and local group collection diagnostics
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputFolder = '',

    [Parameter()]
    [string]$SearchFolder = '',

    [Parameter()]
    [string]$ReportTitle = 'St.Bernard-Hound - CompStatus CSV Analyser v1',

    [Parameter()]
    [switch]$NoMenu,

    # ---------------------------------------------------------------------------
    #  StBernardHound  -  OpenGraph export parameters
    # ---------------------------------------------------------------------------
    # Emit a StBernardHound OpenGraph JSON alongside the HTML report.
    # The JSON can be uploaded directly to BHE / BloodHound CE to graph all
    # collector <-> computer connectivity relationships.
    [Parameter()]
    [switch]$ExportOpenGraph,

    # Friendly name for the collector node written into the OpenGraph JSON.
    # Defaults to $env:COMPUTERNAME if not supplied.
    [Parameter()]
    [string]$CollectorName = '',

    # Folder where the StBernardHound OpenGraph JSON will be written.
    # Defaults to the same OutputFolder as the HTML report.
    [Parameter()]
    [string]$OGOutputFolder = '',

    # Maximum number of computers per output JSON file.
    # Use when large environments produce files that exceed BHE's upload limit.
    # Each chunk is uploaded separately via Explore -> Upload Data.
    # Set to 0 (default) to write a single file regardless of size.
    [Parameter()]
    [int]$ChunkSize = 0,

    # ---------------------------------------------------------------------------
    #  StBernardHound  -  Icon upload parameters
    #  Requires -ExportOpenGraph. Uploads the SBH custom node icons to BHE via
    #  the POST /api/v2/custom-nodes API endpoint. Supports Bearer token
    #  (from API Explorer) or HMAC-SHA256 key pair auth.
    # ---------------------------------------------------------------------------
    [Parameter()]
    [switch]$UploadIcons,

    # Base URL of your BHE instance, e.g. https://sololeveling.bhe.local
    [Parameter()]
    [string]$BHEUrl = '',

    # BHE JWT Bearer Token
    # Generate via: BHE UI -> API Explorer -> Authorize -> copy the token value
    # Or via: POST /api/v2/tokens with your API key credentials
    [Parameter()]
    [string]$BHETokenId = '',

    # BHE API Token Key (used to generate a Bearer token if -BHEBearerToken not supplied)
    [Parameter()]
    [string]$BHETokenKey = '',

    # BHE JWT Bearer Token (preferred  -  paste directly from API Explorer -> Authorize)
    [Parameter()]
    [string]$BHEBearerToken = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
#  DEFAULTS
# ---------------------------------------------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if (-not $SearchFolder) { $SearchFolder = $ScriptDir }
if (-not $OutputFolder)  { $OutputFolder = Join-Path $ScriptDir 'Reports' }

# ---------------------------------------------------------------------------
#  HELPERS
# ---------------------------------------------------------------------------

function HE([string]$s) {
    $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
}

function Get-StatusCategory([string]$Status) {
    $s = $Status.ToLower().Trim()
    if ($s -eq 'success')                        { return 'Success' }
    if ($s -eq 'portScanSkipped' -or
        $s -like '*portscanskip*')               { return 'Success' }   # port-scan optimisation  -  treat as success
    if ($s -eq 'notactive')                      { return 'NotActive' }
    if ($s -eq 'portnotopen')                    { return 'PortNotOpen' }
    if ($s -like '*accessdenied*' -or
        $s -like '*access denied*')              { return 'AccessDenied' }
    if ($s -like '*rpc server*')                 { return 'RPCError' }
    if ($s -like '*registry*')                   { return 'RegistryError' }
    if ($s -like '*collector failed*')           { return 'CollectorError' }
    if ($s -eq 'nonwindowsos')                   { return 'NonWindowsOS' }
    if ($s -like 'timeout after*')               { return 'Timeout' }
    if ($s -eq 'statusrpcserverunavailable')      { return 'RPCError' }   # NTSTATUS form  -  same bucket as Collector failed: RPC
    if ($s -eq 'statusinvalidparameter')          { return 'CollectorError' }
    if ($s -match '^-?[0-9]+$')                  { return 'NumericError' } # raw Win32/NTSTATUS code
    return 'Other'
}

# Returns the collection method/protocol for a given Task name
function Get-CollectionMethod([string]$Task) {
    $t = $Task.Trim()
    switch -Wildcard ($t) {
        'ComputerAvailability'                      { return 'TCP Port Scan' }
        'NetWkstaUserEnum'                          { return 'SMB / NetWkstaUserEnum' }
        'GetMembersInAlias*'                        { return 'SMB / SAMRPC' }
        'OpenAlias*'                                { return 'SMB / SAMRPC' }
        'SamConnect'                                { return 'SMB / SAMRPC' }
        'OpenDomain*'                               { return 'SMB / SAMRPC' }
        'GetAliases*'                               { return 'SMB / SAMRPC' }
        'GetDomains'                                { return 'SMB / SAMRPC' }
        'LSAEnumerateAccountsWithUserRight'         { return 'RPC / LSARPC' }
        'LSAOpenPolicy'                             { return 'RPC / LSARPC' }
        'ReadRegistrySettings - DotNetWmiRegistry*' { return 'WMI' }
        'ReadRegistrySettings - RemoteRegistry*'    { return 'Remote Registry (RRP)' }
        'ReadComputerProperties'                    { return 'LDAP' }
        'ReadUserProperties'                        { return 'LDAP' }
        default                                     { return 'Unknown' }
    }
}

# Returns the type of data being collected for a given Task name
function Get-DataType([string]$Task) {
    $t = $Task.Trim()
    switch -Wildcard ($t) {
        'ComputerAvailability'                      { return 'Reachability' }
        'NetWkstaUserEnum'                          { return 'Active Sessions' }
        'GetMembersInAlias*'                        { return 'Local Group Members' }
        'OpenAlias*'                                { return 'Local Group Handle' }
        'SamConnect'                                { return 'SAM Connection' }
        'OpenDomain*'                               { return 'SAM Domain Handle' }
        'GetAliases*'                               { return 'Local Group Enumeration' }
        'GetDomains'                                { return 'SAM Domain Enumeration' }
        'LSAEnumerateAccountsWithUserRight'         { return 'Privileged Rights' }
        'LSAOpenPolicy'                             { return 'LSA Policy Handle' }
        'ReadRegistrySettings*'                     { return 'NTLM / Registry Config' }
        'ReadComputerProperties'                    { return 'Computer Attributes' }
        'ReadUserProperties'                        { return 'User Attributes' }
        default                                     { return '' }
    }
}

# Returns a compact HTML badge for a method string
function Get-MethodBadge([string]$Method) {
    $colours = @{
        'TCP Port Scan'            = '#0369a1'
        'SMB / NetWkstaUserEnum'   = '#0f766e'
        'SMB / SAMRPC'             = '#0f766e'
        'RPC / LSARPC'             = '#7c3aed'
        'WMI'                      = '#b45309'
        'Remote Registry (RRP)'    = '#9a3412'
        'LDAP'                     = '#1d4ed8'
        'Unknown'                  = '#475569'
    }
    $c = if ($colours.ContainsKey($Method)) { $colours[$Method] } else { '#475569' }
    return "<span class='badge' style='background:$c;font-size:10px'>$(HE $Method)</span>"
}

$BadgeColour = @{
    Success        = '#22c55e'
    NotActive      = '#6b7280'
    PortNotOpen    = '#f97316'
    AccessDenied   = '#ef4444'
    RPCError       = '#a855f7'
    RegistryError  = '#ec4899'
    CollectorError = '#f59e0b'
    NonWindowsOS   = '#0891b2'
    Timeout        = '#dc2626'
    NumericError   = '#92400e'
    Other          = '#64748b'
}

function Get-Badge([string]$Cat, [string]$Label = '') {
    $text  = if ($Label) { $Label } else { $Cat }
    $color = if ($BadgeColour.ContainsKey($Cat)) { $BadgeColour[$Cat] } else { '#64748b' }
    return "<span class='badge' style='background:$color'>$(HE $text)</span>"
}

function Get-TLCell([string]$tl) {
    $colors = @{ green = '#22c55e'; orange = '#f97316'; red = '#ef4444' }
    $labels = @{ green = 'OK - All Files'; orange = 'Mixed'; red = 'Failed - All Files' }
    $c = $colors[$tl]
    $l = $labels[$tl]
    return "<span class='tl-badge' style='background:$c'>$l</span>"
}

function Get-TrafficLight($rows) {
    $ok   = @($rows | Where-Object { $_.Category -eq 'Success' }).Count
    $fail = @($rows | Where-Object { $_.Category -ne 'Success' }).Count
    if ($ok -gt 0 -and $fail -eq 0) { return 'green' }
    if ($ok -gt 0 -and $fail -gt 0) { return 'orange' }
    return 'red'
}

function Get-CanonicalName([string]$cn) {
    $cn = $cn.Trim()
    if ($cn -match '^(host|cifs)/(.+)$') { return $Matches[2].ToUpper() }
    return $cn.ToUpper()
}

$Remediation = @{
    NotActive      = '<b>Computer Offline / Unreachable</b><br>The machine did not respond to the availability check. Verify it is powered on, reachable from the collector, and correctly registered in DNS. Stale AD computer objects with no active host will always appear here. Consider scoping collection to active OUs only.'
    PortNotOpen    = '<b>Required Port Blocked</b><br>SharpHound cannot connect. Ensure <b>TCP 445 (SMB)</b> and <b>TCP 135 (RPC Endpoint Mapper)</b> are open from the collector host to the target. Check host-based Windows Firewall on the target, network ACLs, and any security group rules between the collector and target subnet.'
    AccessDenied   = '<b>Access Denied - Insufficient Privileges</b><br><ul><li><b>NetWkstaUserEnum (session data)</b> - requires Local Administrator or a specific grant on the SrvsvcSessionInfo registry ACL on the target machine.</li><li><b>LSAEnumerateAccountsWithUserRight</b> - requires SeSecurityPrivilege or Local Admin. Delegatable via GPO: Computer Configuration &gt; Windows Settings &gt; Security Settings &gt; User Rights Assignment.</li></ul>'
    RPCError       = '<b>RPC Server Unavailable</b><br>TCP 135 is blocked or the target RPC service is not responding. Check: (1) Remote Registry service is started and set to Automatic on the target, (2) TCP 135 is open from the collector, (3) Dynamic RPC ports 49152-65535 are not blocked by an intermediate firewall or Windows Firewall rule.'
    RegistryError  = '<b>Remote Registry Access Denied</b><br>SharpHound tried to read <code>SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0</code> via Remote Registry but was denied. Grant Read access to the collector account for that key via GPO (Security Settings &gt; Registry), or ensure the account is a Local Admin on the target. Also verify the Remote Registry service is running on the target.'
    CollectorError = '<b>Collector-side Exception</b><br>SharpHound threw an unhandled exception. Review the full error detail in the results table. Common causes: WMI timeouts, DNS resolution failures, .NET remoting issues. Ensure the collector host has TCP/UDP line-of-sight to the target on all required protocols.'
    Timeout        = '<b>RPC / SMB Operation Timed Out</b><br>SharpHound connected to the machine but a specific RPC or SMB call did not complete within the allowed time. Common causes: (1) heavy load on the target at collection time, (2) network latency between collector and target subnet, (3) a software firewall allowing initial connection but blocking or rate-limiting specific RPC calls. The timeout value in the status field (e.g. <code>Timeout after 338 ms</code>) indicates how long SharpHound waited. Consider re-running collection during a low-load window or increasing the SharpHound timeout configuration.'
    NumericError   = '<b>Raw Win32 / NTSTATUS Error Code</b><br>SharpHound received a numeric error code directly from the Windows RPC/SAM subsystem rather than a named status. Common codes: <code>53</code> = Network path not found (firewall or name resolution issue), <code>50</code> = Not supported (non-standard OS or service missing), <code>1745</code> = No more data. Check the Task column to identify which operation failed and correlate the code against Win32 error documentation. These are typically connectivity or service availability issues.'
    NonWindowsOS   = '<b>Non-Windows Operating System Detected</b><br>SharpHound identified this host as running a non-Windows OS (Linux, macOS, or similar). SharpHound cannot collect session or local group data from non-Windows hosts via SMB/RPC. If the machine is domain-joined (e.g. Linux with SSSD/Winbind), it will appear in BloodHound as a computer object but collection tasks will be skipped. No action is required unless the machine should be Windows  -  in that case verify the OS and AD computer object are in sync.'
    Other          = '<b>Uncategorised Error</b><br>Review the raw status message in the full results table. This may be a newer error type not yet mapped in this script.'
}

function Get-RemediationHtml([string]$Cat) {
    if ($Remediation.ContainsKey($Cat)) { return $Remediation[$Cat] }
    return '<b>No remediation tip available for this category.</b>'
}

# ---------------------------------------------------------------------------
#  STBERNARDHOUND  -  OPENGRAPH EXPORT FUNCTIONS
#  Project : StBernardHound
#  Purpose : Produces a BloodHound OpenGraph JSON representing all SharpHound
#             collector->computer connectivity relationships derived from the
#             compstatus CSV, using the following edge model:
#
#               (SBHCollector) --[SBH_<Category>]--> (Computer)
#
#             Edge kinds:
#               SBH_CollectionOK    -  all tasks succeeded
#               SBH_NotActive       -  computer offline / unreachable
#               SBH_PortNotOpen     -  TCP 445 / 135 blocked
#               SBH_AccessDenied    -  insufficient privilege (NetWksta / LSA)
#               SBH_RPCError        -  RPC server unavailable
#               SBH_RegistryError   -  remote registry access denied
#               SBH_CollectorError  -  SharpHound collector-side exception
#               SBH_NonWindowsOS    -  non-Windows OS, collection skipped
#               SBH_Timeout         -  RPC/SMB operation timed out
#               SBH_NumericError    -  raw Win32 / NTSTATUS error code
#               SBH_Other           -  uncategorised / unmapped error
#
#             When a computer has an AD SID (ObjectID field), the edge endpoint
#             uses property-matching to link directly to the existing BHE
#             Computer nodes are always created as new SBHComputer nodes.
#             The AD SID is stored as objectsid property for correlation.
# ---------------------------------------------------------------------------

function SBH-EscJson([string]$s) {
    $s.Replace('\', '\\').Replace('"', '\"').Replace("`n", ' ').Replace("`r", '').Replace("`t", ' ')
}

function SBH-BuildCollectorNodeJson {
    param([string]$NodeId, [string]$DisplayName, [string]$GeneratedAt)
    $id  = SBH-EscJson $NodeId
    $dn  = SBH-EscJson $DisplayName
    $nm  = SBH-EscJson $DisplayName.ToUpper()
    $gat = SBH-EscJson $GeneratedAt
    return '{"id":"' + $id + '","kinds":["SBHCollector"],"properties":{"name":"' + $nm + '","displayname":"' + $dn + '","description":"StBernardHound SharpHound Collector","source":"StBernardHound","generated_at":"' + $gat + '"}}'
}

function SBH-BuildComputerNodeJson {
    param([string]$NodeId, [string]$CompName, [string]$IpAddress, [string]$TrafficLight, [string]$Sid = '')
    $id  = SBH-EscJson $NodeId
    $nm  = SBH-EscJson $CompName.ToUpper()
    $dn  = SBH-EscJson $CompName
    $ip  = SBH-EscJson $IpAddress
    $tl  = SBH-EscJson $TrafficLight
    $sidBlock = if ($Sid) { ',"objectsid":"' + (SBH-EscJson $Sid) + '"' } else { '' }
    $ipBlock  = if ($ip)  { ',"ipaddress":"' + $ip + '"' } else { '' }
    # Kind split  -  drives the icon displayed in BHE Explore:
    #   SBHComputerUnknown  = skull-crossbones  no IP and no SID  -  identity unresolvable
    #   SBHComputerOK       = house-circle-check  all tasks succeeded
    #   SBHComputerFail     = house-circle-xmark  at least one failure
    $kind = if (-not $Sid -and -not $ip) {
        'SBHComputerUnknown'
    } elseif ($TrafficLight -eq 'green') {
        'SBHComputerOK'
    } else {
        'SBHComputerFail'
    }
    return '{"id":"' + $id + '","kinds":["' + $kind + '"],"properties":{"name":"' + $nm + '","displayname":"' + $dn + '"' + $sidBlock + $ipBlock + ',"trafficlight":"' + $tl + '","source":"StBernardHound"}}'
}

function SBH-BuildEndpointJson {
    param([bool]$BySid, [string]$Value)
    # SIDs are the native internal id in BHE for AD Computer nodes.
    # Use match_by:"id" for both SID nodes and synthetic nodes  -  this matches
    # the pattern used by all official OG extensions (e.g. ManagerOf).
    $sv = SBH-EscJson $Value
    return '{"match_by":"id","value":"' + $sv + '"}'
}

function SBH-BuildEdgeJson {
    param(
        [string]$EdgeKind,
        [string]$StartId,
        [string]$EndJson,
        [int]$OccurrenceCount,
        [string]$Category,
        [string]$Tasks,
        [string]$Methods,
        [string]$IpAddress,
        [string]$SourceFiles
    )
    $ek  = SBH-EscJson $EdgeKind
    $sid = SBH-EscJson $StartId
    $cat = SBH-EscJson $Category
    $tsk = SBH-EscJson $Tasks
    $mth = SBH-EscJson $Methods
    $ip  = SBH-EscJson $IpAddress
    $sf  = SBH-EscJson $SourceFiles

    $startJson = '{"match_by":"id","value":"' + $sid + '"}'
    $props     = '"occurrence_count":' + $OccurrenceCount + ',"category":"' + $cat + '","tasks_failed":"' + $tsk + '","collection_methods":"' + $mth + '","source":"StBernardHound"'
    if ($ip) { $props += ',"ip_address":"' + $ip + '"' }
    if ($sf) { $props += ',"source_files":"' + $sf + '"' }

    return '{"kind":"' + $ek + '","start":' + $startJson + ',"end":' + $EndJson + ',"properties":{' + $props + '}}'
}


function SBH-WriteChunkJson {
    # Writes a single OpenGraph JSON chunk to disk (no BOM).
    param(
        [string]$Path,
        [string]$CollectorNodeJson,       # the SBHCollector node JSON string
        [System.Collections.Generic.List[string]]$NodeList,
        [System.Collections.Generic.List[string]]$EdgeList
    )
    # Every chunk includes the collector node so BHE can always resolve the edge start
    $allNodes  = [System.Collections.Generic.List[string]]::new()
    $allNodes.Add($CollectorNodeJson)
    foreach ($n in $NodeList) { $allNodes.Add($n) }

    $nodesBlock = $allNodes -join ",`r`n    "
    $edgesBlock = $EdgeList -join ",`r`n    "

    $json = @"
{
  "metadata": {
    "source_kind": "SBHBase"
  },
  "graph": {
    "nodes": [
    $nodesBlock
    ],
    "edges": [
    $edgesBlock
    ]
  }
}
"@
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($Path, $json, $utf8NoBom)
}

function Export-StBernardHoundJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)] $CompMap,
        [Parameter(Mandatory=$true)] [string]$CollectorId,
        [Parameter(Mandatory=$true)] [string]$CollectorDisplayName,
        [Parameter(Mandatory=$true)] [string]$OutputPath,
        [Parameter(Mandatory=$true)] [bool]$IsMultiFile,
        [Parameter(Mandatory=$true)] [string]$GeneratedAt,
        [Parameter()]                [int]$ChunkSize = 0
    )

    # Category -> OpenGraph edge kind
    $EdgeKindMap = @{
        Success        = 'SBH_CollectionOK'
        NotActive      = 'SBH_NotActive'
        PortNotOpen    = 'SBH_PortNotOpen'
        AccessDenied   = 'SBH_AccessDenied'
        RPCError       = 'SBH_RPCError'
        RegistryError  = 'SBH_RegistryError'
        CollectorError = 'SBH_CollectorError'
        NonWindowsOS   = 'SBH_NonWindowsOS'
        Timeout        = 'SBH_Timeout'
        NumericError   = 'SBH_NumericError'
        Other          = 'SBH_Other'
    }

    # Build the collector node JSON once  -  reused in every chunk
    $collectorNodeJson = SBH-BuildCollectorNodeJson `
        -NodeId      $CollectorId `
        -DisplayName $CollectorDisplayName `
        -GeneratedAt $GeneratedAt

    # Sort all computers up front
    $sortedEntries = @($CompMap.GetEnumerator() | Sort-Object Name)
    $totalComputers = $sortedEntries.Count

    # Determine chunking
    $useChunks  = ($ChunkSize -gt 0 -and $totalComputers -gt $ChunkSize)
    $chunkCount = if ($useChunks) { [math]::Ceiling($totalComputers / $ChunkSize) } else { 1 }

    # Base path without extension for chunk naming
    $baseDir  = Split-Path $OutputPath -Parent
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
    $ext      = [System.IO.Path]::GetExtension($OutputPath)

    $writtenFiles  = [System.Collections.Generic.List[string]]::new()
    $totalNodes    = 0
    $totalEdges    = 0
    $chunkNodeList = [System.Collections.Generic.List[string]]::new()
    $chunkEdgeList = [System.Collections.Generic.List[string]]::new()
    $chunkIdx      = 1
    $compInChunk   = 0

    foreach ($entry in $sortedEntries) {
        $compName = $entry.Name
        $compRows = @($entry.Value)

        $ip = ($compRows | Select-Object -ExpandProperty IPAddress -Unique |
               Where-Object { $_ -and $_ -ne 'Unknown' } | Select-Object -First 1)
        if (-not $ip) { $ip = '' }

        $sid = ($compRows | Select-Object -ExpandProperty ObjectID -Unique |
                Where-Object { $_ -and $_ -ne '' } | Select-Object -First 1)
        if (-not $sid) { $sid = '' }

        $tl      = Get-TrafficLight $compRows
        $srcFiles = ($compRows | Select-Object -ExpandProperty SourceFile -Unique | Sort-Object) -join ', '
        $nodeId  = 'SBH-COMP-' + ($compName -replace '[^A-Za-z0-9\-]', '-').ToUpper()

        $chunkNodeList.Add((SBH-BuildComputerNodeJson `
            -NodeId       $nodeId `
            -CompName     $compName `
            -IpAddress    $ip `
            -TrafficLight $tl `
            -Sid          $sid))

        $endpointJson = SBH-BuildEndpointJson -BySid $false -Value $nodeId

        $allCats = @($compRows | Select-Object -ExpandProperty Category -Unique | Sort-Object)
        foreach ($cat in $allCats) {
            $ek      = if ($EdgeKindMap.ContainsKey($cat)) { $EdgeKindMap[$cat] } else { 'SBH_Other' }
            $catRows = @($compRows | Where-Object { $_.Category -eq $cat })
            $tasks   = ($catRows | Select-Object -ExpandProperty Task -Unique | Sort-Object) -join ', '
            $methods = (@($catRows | Select-Object -ExpandProperty Task -Unique |
                         ForEach-Object { Get-CollectionMethod $_ } | Sort-Object -Unique)) -join ', '
            $sfParam = if ($IsMultiFile) { $srcFiles } else { '' }

            $chunkEdgeList.Add((SBH-BuildEdgeJson `
                -EdgeKind        $ek `
                -StartId         $CollectorId `
                -EndJson         $endpointJson `
                -OccurrenceCount $catRows.Count `
                -Category        $cat `
                -Tasks           $tasks `
                -Methods         $methods `
                -IpAddress       $ip `
                -SourceFiles     $sfParam))
        }

        $compInChunk++
        $totalNodes++
        $totalEdges += $allCats.Count

        # Flush chunk when we hit ChunkSize or the last computer
        $isLastComp  = ($totalNodes -eq $totalComputers)
        $chunkFull   = ($useChunks -and $compInChunk -ge $ChunkSize)

        if ($chunkFull -or $isLastComp) {
            if ($useChunks) {
                $chunkPath = Join-Path $baseDir ("${baseName}_part${chunkIdx}${ext}")
            } else {
                $chunkPath = $OutputPath
            }
            SBH-WriteChunkJson `
                -Path              $chunkPath `
                -CollectorNodeJson $collectorNodeJson `
                -NodeList          $chunkNodeList `
                -EdgeList          $chunkEdgeList
            $writtenFiles.Add($chunkPath)
            $chunkIdx++
            $compInChunk   = 0
            $chunkNodeList = [System.Collections.Generic.List[string]]::new()
            $chunkEdgeList = [System.Collections.Generic.List[string]]::new()
        }
    }

    return [PSCustomObject]@{
        NodeCount  = $totalNodes
        EdgeCount  = $totalEdges
        ChunkCount = $writtenFiles.Count
        Files      = $writtenFiles
        Path       = if ($writtenFiles.Count -eq 1) { $writtenFiles[0] } else { $OutputPath }
    }
}

# ---------------------------------------------------------------------------
#  STBERNARDHOUND  -  ICON UPLOAD FUNCTION
# ---------------------------------------------------------------------------

function Invoke-SBHIconUpload {
    param(
        [Parameter(Mandatory=$true)]  [string]$BHEUrl,
        [Parameter()]                 [string]$BearerToken = '',
        [Parameter()]                 [string]$TokenId     = '',
        [Parameter()]                 [string]$TokenKey    = ''
    )

    # Icon definitions  -  one entry per SBH node kind.
    # PUT /api/v2/custom-nodes/{kind_name} updates an existing kind (idempotent).
    # POST /api/v2/custom-nodes creates a new kind (fails 409 if already exists).
    # We try PUT first; fall back to POST if the kind doesn't exist yet (404).
    $icons = @(
        @{ Kind = 'SBHCollector';       FA = 'house-signal';       Color = '#3b82f6' }
        @{ Kind = 'SBHComputerOK';      FA = 'house-circle-check'; Color = '#22c55e' }
        @{ Kind = 'SBHComputerFail';    FA = 'house-circle-xmark'; Color = '#ef4444' }
        @{ Kind = 'SBHComputerUnknown'; FA = 'skull-crossbones';   Color = '#1e293b' }
    )

    # -- TLS / cert setup (once, before any requests) --------------------------
    if (-not ([System.Management.Automation.PSTypeName]'TrustAllCerts').Type) {
        Add-Type @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCerts : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) { return true; }
}
'@
    }
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCerts
    [System.Net.ServicePointManager]::SecurityProtocol  = [System.Net.SecurityProtocolType]::Tls12

    # -- Inner helper  -  build HMAC headers for a given method + uri + body -----
    function Get-SBHHmacHeaders {
        param([string]$Method, [string]$Uri, [string]$Body)
        $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss+00:00')
        $dateKey   = $timestamp.Substring(0, 13)
        $hmac1 = New-Object System.Security.Cryptography.HMACSHA256
        $hmac1.Key = [System.Text.Encoding]::UTF8.GetBytes($TokenKey)
        $hash1 = $hmac1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$Method$Uri"))
        $hmac2 = New-Object System.Security.Cryptography.HMACSHA256
        $hmac2.Key = $hash1
        $hash2 = $hmac2.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($dateKey))
        $hmac3 = New-Object System.Security.Cryptography.HMACSHA256
        $hmac3.Key = $hash2
        $sig = [Convert]::ToBase64String($hmac3.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Body)))
        return @{
            'Authorization' = "bhesignature $TokenId"
            'RequestDate'   = $timestamp
            'Signature'     = $sig
            'Content-Type'  = 'application/json'
        }
    }

    # -- Process each kind -----------------------------------------------------
    $baseUrl = $BHEUrl.TrimEnd('/')
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($icon in $icons) {
        $kind      = $icon.Kind
        $kindUri   = "/api/v2/custom-nodes/$kind"
        $bulkUri   = '/api/v2/custom-nodes'
        $postPayload = '{"custom_types":{"' + $kind + '":{"icon":{"type":"font-awesome","name":"' + $icon.FA + '","color":"' + $icon.Color + '"}}}}'

        # Build auth headers  -  POST confirmed working, DELETE needed for idempotent re-upload
        if ($BearerToken) {
            $deleteHeaders = @{ 'Authorization' = "Bearer $BearerToken"; 'Content-Type' = 'application/json' }
            $postHeaders   = $deleteHeaders
        }
        elseif ($TokenId -and $TokenKey) {
            $deleteHeaders = Get-SBHHmacHeaders -Method 'DELETE' -Uri $kindUri   -Body ''
            $postHeaders   = Get-SBHHmacHeaders -Method 'POST'   -Uri $bulkUri   -Body $postPayload
        }
        else {
            return [PSCustomObject]@{ Success = $false; Error = 'No auth supplied. Provide -BHEBearerToken OR -BHETokenId + -BHETokenKey.' }
        }

        # Step 1: DELETE existing kind (ignore 404  -  fine if it doesn't exist yet)
        try {
            Invoke-RestMethod -Uri "$baseUrl$kindUri" -Method Delete -Headers $deleteHeaders | Out-Null
        }
        catch {
            $sc = 0
            if ($_.Exception.Response) { $sc = [int]$_.Exception.Response.StatusCode }
            if ($sc -ne 404) {
                # Non-404 delete failure  -  log but continue and try POST anyway
                Write-Verbose "  [~] DELETE $kind returned $sc  -  continuing to POST"
            }
        }

        # Step 2: POST to create fresh (known-good payload format)
        try {
            Invoke-RestMethod -Uri "$baseUrl$bulkUri" -Method Post -Headers $postHeaders -Body $postPayload -ContentType 'application/json' | Out-Null
            $results.Add([PSCustomObject]@{ Kind = $kind; Action = 'Registered (DELETE+POST)'; Success = $true })
        }
        catch {
            $results.Add([PSCustomObject]@{ Kind = $kind; Action = 'Failed'; Success = $false; Error = $_.Exception.Message })
        }
    }

    $anyFailed = @($results | Where-Object { -not $_.Success }).Count -gt 0
    return [PSCustomObject]@{
        Success = (-not $anyFailed)
        Results = $results
        Error   = if ($anyFailed) { 'One or more icon kinds failed  -  see Results for detail.' } else { '' }
    }
}

# ---------------------------------------------------------------------------
#  CSV PARSER  (robust - handles embedded commas/quotes in long error messages)
# ---------------------------------------------------------------------------

function Import-CompStatusCsv([string]$Path) {
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue
    $rawLines  = Get-Content -Path $Path -Encoding UTF8
    $srcFile   = Split-Path $Path -Leaf
    $results   = [System.Collections.Generic.List[PSCustomObject]]::new()

    for ($i = 1; $i -lt $rawLines.Count; $i++) {
        $line = $rawLines[$i].Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $sr     = New-Object System.IO.StringReader($line)
        $parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($sr)
        $parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
        $parser.SetDelimiters(',')
        $parser.HasFieldsEnclosedInQuotes = $true

        try {
            $fields = $parser.ReadFields()
            if ($null -eq $fields -or $fields.Count -lt 3) { continue }

            $obj = [PSCustomObject]@{
                ComputerName  = $fields[0].Trim()
                Task          = if ($fields.Count -gt 1) { $fields[1].Trim() } else { '' }
                Status        = if ($fields.Count -gt 2) { $fields[2].Trim() } else { '' }
                IPAddress     = if ($fields.Count -gt 3) { $fields[3].Trim() } else { '' }
                ObjectID      = if ($fields.Count -gt 4) { $fields[4].Trim() } else { '' }
                Category      = ''
                SourceFile    = $srcFile
                LineNumber    = $i + 1
            }
            $obj.Category = Get-StatusCategory -Status $obj.Status
            $results.Add($obj)
        }
        catch { }
        finally { $parser.Dispose() }
    }
    return ,$results
}

# ---------------------------------------------------------------------------
#  DISCOVER CSV FILES
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host "  +-----------------------------------------------------------------------+" -ForegroundColor Cyan
Write-Host "  |  St.Bernard-Hound - CompStatus CSV Analyser and OG JSON Generator v1 |" -ForegroundColor Cyan
Write-Host "  +-----------------------------------------------------------------------+" -ForegroundColor Cyan
Write-Host ''

$csvFiles = @(Get-ChildItem -Path $SearchFolder -Filter '*compstatus*.csv' -File |
              Sort-Object Name)

if ($csvFiles.Count -eq 0) {
    Write-Host "  [!] No *compstatus*.csv files found in: $SearchFolder" -ForegroundColor Red
    Write-Host "      Place your CSV files in the same folder as this script, or use -SearchFolder." -ForegroundColor Yellow
    exit 1
}

Write-Host "  [*] Found $($csvFiles.Count) compstatus file(s) in: $SearchFolder" -ForegroundColor Green
Write-Host ''

# ---------------------------------------------------------------------------
#  MENU
# ---------------------------------------------------------------------------

$selectedFiles = @()

if ($csvFiles.Count -eq 1 -or $NoMenu) {
    $selectedFiles = $csvFiles
    if ($csvFiles.Count -eq 1) {
        Write-Host "  [*] Single file found - running analysis automatically." -ForegroundColor Cyan
        Write-Host "      $($csvFiles[0].Name)" -ForegroundColor White
    }
    else {
        Write-Host "  [*] -NoMenu specified - analysing all $($csvFiles.Count) files." -ForegroundColor Cyan
    }
}
else {
    Write-Host '  Select an option:' -ForegroundColor Yellow
    Write-Host ''
    for ($m = 0; $m -lt $csvFiles.Count; $m++) {
        $f    = $csvFiles[$m]
        $size = '{0:N0} KB' -f [math]::Ceiling($f.Length / 1KB)
        Write-Host ("    [{0}]  {1}   ({2})" -f ($m + 1), $f.Name, $size) -ForegroundColor White
    }
    Write-Host ''
    Write-Host ("    [{0}]  Compare ALL {1} files - cross-run report" -f ($csvFiles.Count + 1), $csvFiles.Count) -ForegroundColor Cyan
    Write-Host ''

    $choice = 0
    do {
        $raw   = Read-Host '  Enter choice'
        $valid = [int]::TryParse($raw.Trim(), [ref]$choice) -and
                 $choice -ge 1 -and $choice -le ($csvFiles.Count + 1)
        if (-not $valid) {
            Write-Host "  [!] Invalid choice. Enter a number between 1 and $($csvFiles.Count + 1)." -ForegroundColor Red
        }
    } while (-not $valid)

    if ($choice -le $csvFiles.Count) {
        $selectedFiles = @($csvFiles[$choice - 1])
        Write-Host ''
        Write-Host "  [*] Analysing: $($selectedFiles[0].Name)" -ForegroundColor Cyan
    }
    else {
        $selectedFiles = $csvFiles
        Write-Host ''
        Write-Host "  [*] Multi-file comparison mode - $($csvFiles.Count) files" -ForegroundColor Cyan
    }
}

Write-Host ''

# ---------------------------------------------------------------------------
#  PARSE ALL SELECTED FILES
# ---------------------------------------------------------------------------

$allRows   = [System.Collections.Generic.List[PSCustomObject]]::new()
$fileStats = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($f in $selectedFiles) {
    Write-Host "  [>] Parsing: $($f.Name)" -ForegroundColor Gray
    $rows = Import-CompStatusCsv -Path $f.FullName
    $fileStats.Add([PSCustomObject]@{
        FileName    = $f.Name
        TotalRows   = $rows.Count
        SuccessRows = @($rows | Where-Object { $_.Category -eq 'Success' }).Count
        FailRows    = @($rows | Where-Object { $_.Category -ne 'Success' }).Count
    })
    foreach ($r in $rows) { $allRows.Add($r) }
}

$isMultiFile = ($selectedFiles.Count -gt 1)

# ---------------------------------------------------------------------------
#  ANALYSIS
# ---------------------------------------------------------------------------

$successRows = @($allRows | Where-Object { $_.Category -eq 'Success' })
$failRows    = @($allRows | Where-Object { $_.Category -ne 'Success' })
$totalRows   = $allRows.Count
$pctSuccess  = if ($totalRows -gt 0) { [math]::Round($successRows.Count / $totalRows * 100, 1) } else { 0 }
$pctFail     = if ($totalRows -gt 0) { [math]::Round($failRows.Count    / $totalRows * 100, 1) } else { 0 }

# Deduplicated computer map
$compMap = @{}
foreach ($r in $allRows) {
    $key = Get-CanonicalName $r.ComputerName
    if (-not $compMap.ContainsKey($key)) {
        $compMap[$key] = [System.Collections.Generic.List[PSCustomObject]]::new()
    }
    $compMap[$key].Add($r)
}

$uniqueComputers   = $compMap.Count
$notActiveOnly     = @($compMap.GetEnumerator() | Where-Object {
    $all = @($_.Value)
    $all.Count -eq 1 -and $all[0].Status -eq 'NotActive'
})
$taskFailComputers = @($compMap.GetEnumerator() | Where-Object {
    $fails = @($_.Value | Where-Object { $_.Task -ne 'ComputerAvailability' -and $_.Category -ne 'Success' })
    $fails.Count -gt 0
})
$fullyOkComputers  = @($compMap.GetEnumerator() | Where-Object {
    $fails = @($_.Value | Where-Object { $_.Category -ne 'Success' })
    $fails.Count -eq 0
})
$problemComputers  = @($compMap.GetEnumerator() | Where-Object {
    $fails = @($_.Value | Where-Object { $_.Category -ne 'Success' })
    $fails.Count -gt 0
} | Sort-Object Name)

$catGroups = $failRows | Group-Object Category | Sort-Object Count -Descending

# Build computer JSON data for spotlight search
$compJsonParts = foreach ($entry in $compMap.GetEnumerator()) {
    $jg    = @($entry.Value)
    $jok   = @($jg | Where-Object { $_.Category -eq 'Success' }).Count
    $jfail = @($jg | Where-Object { $_.Category -ne 'Success' }).Count
    $jcats = (@($jg | Select-Object -ExpandProperty Category -Unique | Sort-Object)) -join ','
    $jips  = (@($jg | Select-Object -ExpandProperty IPAddress -Unique | Where-Object { $_ -and $_ -ne 'Unknown' })) -join ','
    $jlines= (@($jg | Select-Object -ExpandProperty LineNumber | Sort-Object -Unique)) -join ','
    $jtl   = Get-TrafficLight $jg
    $jn    = $entry.Name.Replace('\','\\').Replace('"','\"')
    '{"n":"' + $jn + '","ip":"' + $jips + '","ok":' + $jok + ',"fail":' + $jfail + ',"cats":"' + $jcats + '","lines":"' + $jlines + '","tl":"' + $jtl + '"}'
}
$computerJsonData = '[' + ($compJsonParts -join ',') + ']'

# Build unique subnet lists from actual row data for the filter dropdowns
function Get-SubnetList([object[]]$rows, [int]$dummy) {
    $seen = @{}
    foreach ($r in $rows) {
        $ip = $r.IPAddress.Trim()
        # Skip blanks, Unknown, IPv6, and anything that isn't a clean IPv4 address
        if (-not $ip -or $ip -eq 'Unknown' -or $ip -like '*:*') { continue }
        # Validate strictly: must match x.x.x.x where each octet is 0-255
        if ($ip -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') { continue }
        $parts = $ip -split '\.'
        # Double-check each octet is a valid integer 0-255
        $valid = $true
        foreach ($p in $parts) {
            $n = 0
            if (-not [int]::TryParse($p, [ref]$n) -or $n -lt 0 -or $n -gt 255) { $valid = $false; break }
        }
        if (-not $valid) { continue }
        $sn = "$($parts[0]).$($parts[1]).$($parts[2]).x"
        $seen[$sn] = $true
    }
    # Sort numerically by octet value
    return @($seen.Keys | Sort-Object {
        $p = $_ -replace '\.x$','' -split '\.'
        $n = 0
        $ok0 = [int]::TryParse($p[0], [ref]$n); $o0 = $n
        $ok1 = [int]::TryParse($p[1], [ref]$n); $o1 = $n
        $ok2 = [int]::TryParse($p[2], [ref]$n); $o2 = $n
        $o0 * 65536 + $o1 * 256 + $o2
    })
}

$compSubnets = Get-SubnetList -rows @($compMap.GetEnumerator() | ForEach-Object {
    $_.Value | Select-Object -First 1
}) -dummy 0
$failSubnets = Get-SubnetList -rows @($failRows) -dummy 0

$compSubnetJs = ($compSubnets | ForEach-Object { "'" + $_ + "'" }) -join ','
$failSubnetJs  = ($failSubnets  | ForEach-Object { "'" + $_ + "'" }) -join ','

# ---------------------------------------------------------------------------
#  BUILD HTML SECTIONS
# ---------------------------------------------------------------------------

# File stats table (multi-file only)
$fileStatsHtml = ''
if ($isMultiFile) {
    $fsRowsHtml = foreach ($fs in $fileStats) {
        $pct = if ($fs.TotalRows -gt 0) { [math]::Round($fs.SuccessRows / $fs.TotalRows * 100, 1) } else { 0 }
        $tl  = if ($fs.FailRows -eq 0) { 'green' } elseif ($fs.SuccessRows -gt 0) { 'orange' } else { 'red' }
        $tlc = Get-TLCell $tl
        "<tr><td>$(HE $fs.FileName)</td><td style='text-align:center'>$($fs.TotalRows)</td><td style='text-align:center;color:#22c55e'>$($fs.SuccessRows)</td><td style='text-align:center;color:#ef4444'>$($fs.FailRows)</td><td style='text-align:center'>$pct%</td><td style='text-align:center'>$tlc</td></tr>"
    }
    $fileStatsHtml = "<section id='sec-files'><div class='sec-hdr' onclick=""toggleSec('sec-files')""><h2>&#128193; FILES ANALYSED ($($selectedFiles.Count))</h2><span class='collapse-btn' id='sec-files-btn'>&#9660;</span></div><div id='sec-files-body'><div class='table-wrap'><table><thead><tr><th>File</th><th>Total Rows</th><th>Success</th><th>Failed</th><th>Success %</th><th>Status</th></tr></thead><tbody>$($fsRowsHtml -join '')</tbody></table></div></div></section>"
}

# Computer summary rows
$compSummaryRows = foreach ($entry in $problemComputers) {
    $g      = @($entry.Value)
    $ok     = @($g | Where-Object { $_.Category -eq 'Success' }).Count
    $fail   = @($g | Where-Object { $_.Category -ne 'Success' }).Count
    $cats   = @($g | Where-Object { $_.Category -ne 'Success' } | Select-Object -ExpandProperty Category -Unique | Sort-Object)
    $ips    = @($g | Select-Object -ExpandProperty IPAddress -Unique | Where-Object { $_ -and $_ -ne 'Unknown' })
    $ip     = if ($ips) { ($ips | Sort-Object -Unique) -join ', ' } else { 'Unknown' }
    $tl     = Get-TrafficLight $g
    $tlCell = Get-TLCell $tl
    $badgesHtml = ($cats | ForEach-Object { Get-Badge $_ }) -join ' '
    # Group line numbers by source file for the cell display
    $lineNumsByFile = $g | Group-Object SourceFile | Sort-Object Name | ForEach-Object {
        $nums = (@($_.Group | Select-Object -ExpandProperty LineNumber | Sort-Object -Unique)) -join ', '
        "$($_.Name): $nums"
    }
    $lineNums = $lineNumsByFile -join ' | '
    $srcCol = ''
    if ($isMultiFile) {
        $fl = (@($g | Select-Object -ExpandProperty SourceFile -Unique | Sort-Object)) -join '<br>'
        $srcCol = "<td class='status-cell'>$fl</td>"
    }
    $cid = 'comp-' + ($entry.Name -replace '[^a-zA-Z0-9\-_]','-')
    $failMethods = (@($g | Where-Object { $_.Category -ne 'Success' } |
                     Select-Object -ExpandProperty Task -Unique |
                     ForEach-Object { Get-CollectionMethod $_ } |
                     Sort-Object -Unique) | ForEach-Object { Get-MethodBadge $_ }) -join ' '
    # Does this computer have any non-availability task failures?
    $hasTaskFail = (@($g | Where-Object { $_.Task -ne 'ComputerAvailability' -and $_.Category -ne 'Success' }).Count) -gt 0
    $taskFailAttr = if ($hasTaskFail) { 'data-taskfail="1"' } else { 'data-taskfail="0"' }
    "<tr id='$cid' $taskFailAttr><td class='cn-cell' title='$(HE $entry.Name)'>$(HE $entry.Name)</td><td>$(HE $ip)</td><td style='text-align:center'>$ok</td><td style='text-align:center'>$fail</td><td>$badgesHtml</td><td>$failMethods</td><td style='text-align:center'>$tlCell</td><td style='font-family:Consolas,monospace;font-size:11px;color:var(--muted)'>$(HE $lineNums)</td>$srcCol</tr>"
}
$compSrcHeader = if ($isMultiFile) { '<th>Source File(s)</th>' } else { '' }

# Failure rows  -  JSON array for virtual pagination (avoids rendering 50k+ DOM nodes)
function JE-F([string]$t){ $t.Replace('\','\\').Replace('"','\"').Replace("`n",' ').Replace("`r",'').Replace("'","\'") }
$failJsonParts = foreach ($r in ($failRows | Sort-Object Category, ComputerName)) {
    $statusShort = $r.Status.Substring(0, [Math]::Min($r.Status.Length, 300))
    $fcn         = Get-CanonicalName $r.ComputerName
    $fMethod     = Get-CollectionMethod $r.Task
    $fDataType   = Get-DataType $r.Task
    $srcVal      = if ($isMultiFile) { JE-F $r.SourceFile } else { '' }
    '{"cn":"' + (JE-F $fcn) + '","task":"' + (JE-F $r.Task) + '","cat":"' + $r.Category + '","catColor":"' + $(if ($BadgeColour.ContainsKey($r.Category)){$BadgeColour[$r.Category]}else{'#64748b'}) + '","method":"' + (JE-F $fMethod) + '","dtype":"' + (JE-F $fDataType) + '","status":"' + (JE-F $statusShort) + '","ip":"' + (JE-F $r.IPAddress) + '","src":"' + $srcVal + '","line":' + $r.LineNumber + '}'
}
$failJsonData  = '[' + ($failJsonParts -join ',') + ']'
$failTableRows = ''
$failSrcHeader = if ($isMultiFile) { '<th>Source File</th>' } else { '' }

# Remediation cards
$remCards = foreach ($cg in ($catGroups | Where-Object { $_.Name -ne 'Success' })) {
    $cat   = $cg.Name
    $color = if ($BadgeColour.ContainsKey($cat)) { $BadgeColour[$cat] } else { '#64748b' }
    $tip   = Get-RemediationHtml -Cat $cat

    # Build one row per unique computer affected by this category
    $affectedRows = $allRows | Where-Object { $_.Category -eq $cat } | Group-Object {
        Get-CanonicalName $_.ComputerName
    } | Sort-Object Name | ForEach-Object {
        $compName = $_.Name
        $grp      = @($_.Group)
        $ip       = ($grp | Select-Object -ExpandProperty IPAddress -Unique |
                     Where-Object { $_ -and $_ -ne 'Unknown' } | Select-Object -First 1)
        if (-not $ip) { $ip = 'Unknown' }
        $tasks    = ($grp | Select-Object -ExpandProperty Task -Unique | Sort-Object) -join '<br>'
        $methods  = (@($grp | Select-Object -ExpandProperty Task -Unique |
                       ForEach-Object { Get-CollectionMethod $_ } | Sort-Object -Unique) |
                     ForEach-Object { Get-MethodBadge $_ }) -join ' '
        "<tr><td class='cn-cell' style='font-family:Consolas,monospace;font-size:12px'>$(HE $compName)</td><td style='font-size:12px;color:var(--muted)'>$(HE $ip)</td><td style='font-size:12px;color:var(--muted)'>$tasks</td><td>$methods</td></tr>"
    }

    $affectedTable = "<div style='margin-top:10px;overflow-x:auto;border-radius:6px;border:1px solid var(--border)'>" +
        "<table style='width:100%;border-collapse:collapse'>" +
        "<thead><tr style='background:var(--surface2)'>" +
        "<th style='padding:7px 12px;text-align:left;font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;white-space:nowrap'>Computer</th>" +
        "<th style='padding:7px 12px;text-align:left;font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;white-space:nowrap'>IP Address</th>" +
        "<th style='padding:7px 12px;text-align:left;font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;white-space:nowrap'>Failed Task(s)</th>" +
        "<th style='padding:7px 12px;text-align:left;font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;white-space:nowrap'>Method</th>" +
        "</tr></thead>" +
        "<tbody style='font-size:13px'>$($affectedRows -join '')</tbody>" +
        "</table></div>"

    "<div class='remediation-card' id='rem-card-$(($cat -replace '[^a-zA-Z0-9]',"-"))' style='border-left:4px solid $color'>" +
        "<h3>$(Get-Badge $cat) &nbsp; $($cg.Count) occurrence(s)</h3>" +
        "<p style='margin-bottom:8px'>$tip</p>" +
        "<p style='font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px'>Affected computers ($(@($affectedRows).Count))</p>" +
        "$affectedTable" +
    "</div>"
}

# Not active
$notActiveHtml = ($notActiveOnly | Select-Object -ExpandProperty Name | Sort-Object) -join '<br>'

# Multi-file cross-run table
$multiCompTableHtml = ''
if ($isMultiFile) {
    $mcRows = foreach ($entry in ($compMap.GetEnumerator() | Sort-Object Name)) {
        $g      = @($entry.Value)
        $tl     = Get-TrafficLight $g
        $tlCell = Get-TLCell $tl
        $ips    = @($g | Select-Object -ExpandProperty IPAddress -Unique | Where-Object { $_ -and $_ -ne 'Unknown' })
        $ip     = if ($ips) { ($ips | Sort-Object -Unique) -join ', ' } else { 'Unknown' }
        $errFiles = @($g | Where-Object { $_.Category -ne 'Success' } |
                      Select-Object -ExpandProperty SourceFile -Unique | Sort-Object)
        $fileTagsHtml = if ($errFiles) {
            ($errFiles | ForEach-Object { "<span class='file-tag'>$(HE $_)</span>" }) -join ' '
        } else { '<span style="color:#22c55e">None - all clean</span>' }
        "<tr><td class='cn-cell' title='$(HE $entry.Name)'>$(HE $entry.Name)</td><td>$(HE $ip)</td><td style='text-align:center'>$tlCell</td><td>$fileTagsHtml</td></tr>"
    }
    $multiCompTableHtml = "<section id='sec-crossrun'><div class='sec-hdr' onclick=""toggleSec('sec-crossrun')""><h2>&#128201; ALL COMPUTERS - CROSS-RUN STATUS ($uniqueComputers unique)</h2><span class='collapse-btn' id='sec-crossrun-btn'>&#9660;</span></div><div id='sec-crossrun-body'><p style='color:var(--muted);font-size:13px;margin-bottom:12px'>Each computer listed once. Green = OK in all files. Orange = mixed results. Red = failed in every file it appeared in.</p><input class='table-search' type='text' id='mcSearch' placeholder='Filter computers...' oninput=""filterTable('mcTable','mcSearch')""><div class='table-wrap'><table id='mcTable'><thead><tr><th>Computer</th><th>IP Address</th><th>Status</th><th>Files Containing Errors</th></tr></thead><tbody>$($mcRows -join '')</tbody></table></div></div></section>"
}

# Full audit log  -  JSON array for virtual pagination
function JE-A([string]$t){ $t.Replace('\','\\').Replace('"','\"').Replace("`n",' ').Replace("`r",'').Replace("'","\'") }
$allJsonParts = foreach ($r in ($allRows | Sort-Object ComputerName, Task)) {
    $acn         = Get-CanonicalName $r.ComputerName
    $aMethod     = Get-CollectionMethod $r.Task
    $aDataType   = Get-DataType $r.Task
    $statusShort = $r.Status.Substring(0, [Math]::Min($r.Status.Length, 300))
    $srcVal      = if ($isMultiFile) { JE-A $r.SourceFile } else { '' }
    '{"cn":"' + (JE-A $acn) + '","task":"' + (JE-A $r.Task) + '","cat":"' + $r.Category + '","catColor":"' + $(if ($BadgeColour.ContainsKey($r.Category)){$BadgeColour[$r.Category]}else{'#64748b'}) + '","method":"' + (JE-A $aMethod) + '","dtype":"' + (JE-A $aDataType) + '","status":"' + (JE-A $statusShort) + '","ip":"' + (JE-A $r.IPAddress) + '","src":"' + $srcVal + '","line":' + $r.LineNumber + '}'
}
$allJsonData  = '[' + ($allJsonParts -join ',') + ']'
$allTableRows = ''
$allSrcHeader = if ($isMultiFile) { '<th>Source File</th>' } else { '' }

# Chart
$chartLabels = ($catGroups | ForEach-Object { "'" + (HE $_.Name) + "'" }) -join ','
$chartValues = ($catGroups | ForEach-Object { $_.Count }) -join ','
$chartColors = ($catGroups | ForEach-Object {
    "'" + $(if ($BadgeColour.ContainsKey($_.Name)) { $BadgeColour[$_.Name] } else { '#64748b' }) + "'"
}) -join ','

# ---------------------------------------------------------------------------
#  ASSEMBLE HTML
# ---------------------------------------------------------------------------

$reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$fileLabel  = if ($isMultiFile) {
    "$($selectedFiles.Count) files ($($selectedFiles[0].Name) to $($selectedFiles[-1].Name))"
} else { $selectedFiles[0].Name }
$modeLabel  = if ($isMultiFile) { 'Multi-Run Comparison' } else { 'Single Run' }
$fullTitle  = "$ReportTitle - $modeLabel"

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$fullTitle</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#0f172a;--surface:#1e293b;--surface2:#273449;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#38bdf8;--success:#22c55e;--danger:#ef4444;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6;}
a{color:var(--accent);}

/* Header */
header{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 32px;display:flex;align-items:center;gap:16px;}
.logo{font-size:30px;}
header h1{font-size:18px;font-weight:700;color:var(--accent);}
.meta{font-size:12px;color:var(--muted);margin-top:2px;}
.mode-pill{display:inline-block;padding:2px 9px;border-radius:10px;font-size:11px;font-weight:700;background:#1d4ed8;color:#fff;margin-left:8px;vertical-align:middle;}

/* Spotlight bar */
#spotlight-wrap{background:#162032;border-bottom:2px solid var(--accent);padding:10px 32px;position:sticky;top:0;z-index:200;}
.spotlight-inner{display:flex;align-items:center;gap:10px;max-width:100%;margin:0 auto;position:relative;}
.spotlight-label{font-size:12px;color:var(--accent);white-space:nowrap;font-weight:600;}
#spotlight-input{flex:1;max-width:580px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:7px 13px;font-size:13px;}
#spotlight-input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 2px rgba(56,189,248,.15);}
#sp-clear{background:none;border:none;color:var(--muted);cursor:pointer;font-size:18px;padding:0 4px;line-height:1;}
#sp-clear:hover{color:var(--text);}
.spotlight-hint{font-size:11px;color:var(--muted);white-space:nowrap;}
/* Results panel: absolute dropdown so it floats OVER page content, never inside sticky height */
#spotlight-results{
  position:absolute;
  top:calc(100% + 8px);
  left:0;right:0;
  background:#162032;
  border:1px solid var(--accent);
  border-radius:8px;
  padding:12px 14px;
  display:none;
  z-index:300;
  max-height:70vh;
  overflow-y:auto;
  box-shadow:0 8px 32px rgba(0,0,0,.6);
}
.sp-cards{display:flex;flex-direction:column;gap:10px;}
.sp-card{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px 15px;width:100%;}
.sp-card-hdr{display:flex;align-items:flex-start;justify-content:space-between;gap:8px;margin-bottom:6px;}
.sp-name{font-weight:700;font-size:13px;font-family:Consolas,monospace;color:var(--text);word-break:break-all;flex:1;}
.sp-card-meta{font-size:12px;color:var(--muted);margin-bottom:6px;display:flex;flex-direction:column;gap:3px;}
.sp-card-meta-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;}
.sp-card-meta code{background:var(--bg);padding:1px 5px;border-radius:3px;font-family:Consolas,monospace;}
.sp-card-cats{margin-bottom:8px;display:flex;flex-wrap:wrap;gap:4px;}
.sp-card-links{display:flex;gap:8px;flex-wrap:wrap;}
.sp-link{font-size:12px;padding:3px 10px;background:var(--surface);border:1px solid var(--border);border-radius:4px;color:var(--accent);text-decoration:none;cursor:pointer;}
.sp-link:hover{border-color:var(--accent);background:var(--surface2);}
.sp-notfound{color:#f59e0b;font-size:12px;padding:6px 0;font-style:italic;}

/* Layout */
.container{max-width:100%;margin:0 auto;padding:20px 32px;}
section{margin-bottom:28px;}

/* Collapsible sections */
.sec-hdr{display:flex;align-items:center;justify-content:space-between;cursor:pointer;padding-bottom:8px;border-bottom:1px solid var(--border);margin-bottom:14px;user-select:none;}
.sec-hdr h2{border-bottom:none;padding-bottom:0;margin-bottom:0;font-size:13px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.06em;}
.sec-subtitle{font-size:11px;font-weight:400;color:var(--muted);text-transform:none;letter-spacing:0;}
.sec-hdr:hover h2{color:var(--text);}
.sec-hdr-right{display:flex;align-items:center;gap:8px;}
.collapse-btn{color:var(--muted);font-size:11px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:2px 9px;font-family:Consolas,monospace;}
.sec-body{overflow:hidden;}

/* Stat cards */
.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:12px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px 16px;}
.stat-card .val{font-size:28px;font-weight:700;line-height:1.1;}
.stat-card .lbl{font-size:12px;color:var(--muted);margin-top:3px;}
.stat-card.success .val{color:var(--success);}
.stat-card.danger .val{color:var(--danger);}
.stat-card.warn .val{color:#f97316;}
.stat-card.info .val{color:var(--accent);}
.stat-card.clickable{cursor:pointer;transition:border-color .15s,transform .1s;}
.stat-card.clickable:hover{border-color:var(--accent);transform:translateY(-2px);}
.stat-card .lbl .arr{font-size:10px;opacity:.6;}

/* Chart */
.chart-wrap{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;display:flex;align-items:center;gap:32px;flex-wrap:wrap;}
.chart-wrap canvas{max-height:200px;max-width:200px;}
.chart-legend{display:flex;flex-direction:column;gap:9px;}
.chart-legend-item{display:flex;align-items:center;gap:8px;font-size:13px;}
.chart-legend-dot{width:11px;height:11px;border-radius:50%;flex-shrink:0;}

/* Tables */
.table-wrap{overflow-x:auto;border-radius:8px;border:1px solid var(--border);}
table{width:100%;border-collapse:collapse;}
thead th{background:var(--surface2);padding:9px 13px;text-align:left;font-size:11px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;white-space:nowrap;}
tbody tr{border-top:1px solid var(--border);}
tbody tr:hover td{filter:brightness(1.15);}
tbody td{padding:8px 13px;vertical-align:middle;}
.status-cell{font-size:12px;color:var(--muted);word-break:break-word;}
/* Computer name cell  -  never wraps, uses monospace, shrinks font slightly */
.cn-cell{font-family:Consolas,'Cascadia Code',monospace;font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:320px;}
.cn-cell:hover{white-space:normal;text-overflow:clip;overflow:visible;}
/* Method/datatype cells */
.method-cell{white-space:nowrap;}
.dt-cell{font-size:11px;color:var(--muted);white-space:nowrap;}

/* Badges */
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;color:#fff;white-space:nowrap;}
.tl-badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:12px;font-weight:700;color:#fff;}
.file-tag{display:inline-block;background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:1px 7px;font-size:11px;font-family:Consolas,monospace;margin:1px 2px;}

/* Remediation cards */
.remediation-card{background:var(--surface);border-radius:8px;padding:14px 18px;margin-bottom:11px;}
.remediation-card p,.remediation-card ul{color:var(--muted);font-size:13px;margin-bottom:5px;}
.remediation-card ul{margin-left:18px;}
.remediation-card code{background:var(--surface2);padding:1px 5px;border-radius:3px;font-family:Consolas,monospace;font-size:12px;word-break:break-all;}
.remediation-card table tbody tr{border-top:1px solid var(--border);}
.remediation-card table tbody tr:hover td{filter:brightness(1.15);}
.remediation-card table tbody td{padding:7px 12px;vertical-align:top;}

/* Not-active body */
.details-body{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:14px 18px;font-size:13px;color:var(--muted);line-height:1.9;}

/* Search */
.table-search{width:100%;max-width:280px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:7px 12px;font-size:13px;}
.table-search:focus{outline:none;border-color:var(--accent);}
.filter-bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px;padding:10px 12px;background:var(--surface);border:1px solid var(--border);border-radius:8px;}
.filter-select{background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:6px 10px;font-size:12px;cursor:pointer;}
.filter-select:focus{outline:none;border-color:var(--accent);}
.filter-toggle{font-size:12px;color:var(--muted);display:flex;align-items:center;gap:5px;cursor:pointer;white-space:nowrap;}
.filter-toggle input{cursor:pointer;accent-color:var(--accent);}
.filter-btn{background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--accent);padding:5px 12px;font-size:12px;cursor:pointer;white-space:nowrap;}
.filter-btn:hover{background:var(--surface);border-color:var(--accent);}
.sortable{cursor:pointer;user-select:none;}
.sortable:hover{color:var(--text);}
.sort-icon{opacity:.4;font-size:10px;}
.sort-asc .sort-icon::after{content:' ^';}
.sort-desc .sort-icon::after{content:' v';}
.sort-asc .sort-icon,.sort-desc .sort-icon{opacity:1;color:var(--accent);}
.num-col{text-align:center;}
.rem-pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:600;cursor:pointer;border:1px solid transparent;}
.rem-pill:hover{opacity:.85;}

/* Row highlight */
@keyframes rowFlash{0%{background:#1e3a5f;}60%{background:#1e3a5f;}100%{background:transparent;}}
.highlight-row td{animation:rowFlash 1.8s ease-out;}

footer{text-align:center;padding:22px;color:var(--muted);font-size:12px;border-top:1px solid var(--border);margin-top:36px;}
#back-to-top{
  background:none;border:1px solid var(--accent);border-radius:6px;
  color:var(--accent);padding:5px 12px;font-size:12px;font-weight:600;
  cursor:pointer;white-space:nowrap;margin-left:auto;flex-shrink:0;
  display:flex;align-items:center;gap:4px;
  opacity:0.25;pointer-events:auto;
  transition:opacity .2s,transform .2s;
}
#back-to-top:hover{background:rgba(56,189,248,.12);}
.pg-bar{display:flex;align-items:center;gap:4px;flex-wrap:wrap;margin-top:8px;}
.pg-btn{background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--text);padding:4px 9px;font-size:12px;cursor:pointer;min-width:32px;}
.pg-btn:hover:not(:disabled){border-color:var(--accent);color:var(--accent);}
.pg-btn:disabled{opacity:.35;cursor:default;}
.pg-active{background:var(--accent)!important;color:#000!important;border-color:var(--accent)!important;font-weight:700;}
.pg-ellipsis{color:var(--muted);padding:0 4px;font-size:12px;}
.row-count{font-size:12px;color:var(--muted);margin-left:auto;}
.pg-size-sel{background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--muted);padding:3px 6px;font-size:11px;cursor:pointer;margin-right:6px;}
.pg-size-sel:focus{outline:none;border-color:var(--accent);}

/* -- Filter bar -- */
.filter-bar{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-bottom:10px;}
.filter-select{background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--text);padding:6px 10px;font-size:12px;cursor:pointer;min-width:140px;}
.filter-select:focus{outline:none;border-color:var(--accent);}
.filter-toggle{display:flex;align-items:center;gap:5px;font-size:12px;color:var(--muted);cursor:pointer;padding:4px 8px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;user-select:none;}
.filter-toggle:has(input:disabled){opacity:.4;cursor:not-allowed;}
.filter-toggle input{accent-color:var(--accent);cursor:pointer;}
.filter-btn{background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--accent);padding:6px 12px;font-size:12px;cursor:pointer;white-space:nowrap;}
.filter-btn:hover{border-color:var(--accent);background:var(--surface);}
.filter-btn.export-pdf{color:#f59e0b;border-color:#f59e0b55;}
.filter-btn.export-pdf:hover{background:#422006;}
.filter-btn.export-full{color:#22c55e;border-color:#22c55e55;}
.filter-btn.export-full:hover{background:#052e16;}
.filter-reset{font-size:11px;color:var(--muted);cursor:pointer;padding:4px 8px;border-radius:4px;}
.filter-reset:hover{color:var(--text);}
/* Sortable headers */
th.sortable{cursor:pointer;user-select:none;}
th.sortable:hover{color:var(--text);}
.sort-icon{opacity:.4;font-size:10px;}
th.sort-asc .sort-icon::after{content:'\25B2';opacity:1;}
th.sort-desc .sort-icon::after{content:'\25BC';opacity:1;}
th.sort-asc .sort-icon, th.sort-desc .sort-icon{opacity:1;}
.num-col{text-align:center;}
/* Remediation quick-ref at top */
#rem-quickref{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin-bottom:14px;}
#rem-quickref h3{font-size:12px;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px;}
.rem-qr-grid{display:flex;flex-wrap:wrap;gap:8px;}
.rem-qr-card{background:var(--surface2);border-radius:6px;padding:8px 12px;flex:1;min-width:200px;cursor:pointer;border:1px solid var(--border);}
.rem-qr-card:hover{border-color:var(--accent);}
.rem-qr-card .rq-title{font-size:12px;font-weight:600;color:var(--text);margin-bottom:3px;}
.rem-qr-card .rq-desc{font-size:11px;color:var(--muted);line-height:1.4;}
/* Print styles */
@media print{
  #spotlight-wrap,.filter-bar,.filter-btn,.collapse-btn,.sec-hdr .sec-hdr-right,
  .filter-toggle,footer{display:none!important;}
  .sec-body{display:block!important;}
  body{background:#fff;color:#000;}
  header{background:#fff;border-bottom:1px solid #ccc;}
  .container{padding:0;}
  section{break-inside:avoid;margin-bottom:20px;}
  table{font-size:10px;}
  thead th{background:#f0f0f0;color:#000;}
  .badge{border:1px solid #ccc;color:#000!important;background:#eee!important;}
  .tl-badge{border:1px solid #ccc;color:#000!important;background:#eee!important;}
}
</style>
</head>
<body>

<header>
  <div class="logo">&#129405;</div>
  <div>
    <h1>$fullTitle <span class="mode-pill">$modeLabel</span></h1>
    <div class="meta">Source: <code>$fileLabel</code> &nbsp;|&nbsp; Generated: $reportDate &nbsp;|&nbsp; BloodHound Enterprise &#8212; SharpHound Collection Diagnostics</div>
  </div>
</header>

<!-- === SPOTLIGHT SEARCH === -->
<div id="spotlight-wrap">
  <div class="spotlight-inner">
    <span class="spotlight-label">&#128269; Computer Search</span>
    <input id="spotlight-input" type="text" placeholder="Type a computer name (comma-separate for multiple)  e.g.  DC01, SERVER02, WORKSTATION01" autocomplete="off">
    <button id="sp-clear" onclick="clearSpotlight()" title="Clear search">&#10005;</button>
    <span class="spotlight-hint">Comma-separate for multiple</span>
    <button id="back-to-top" onclick="window.scrollTo({top:0,behavior:'smooth'})" title="Back to top" style="background:none;border:1px solid var(--accent);border-radius:6px;color:var(--accent);padding:5px 12px;font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap;margin-left:auto;flex-shrink:0;opacity:0.25;transition:opacity .2s;">&#8679; Top</button>
    <!-- Dropdown panel is absolute child of .spotlight-inner so it floats over page -->
    <div id="spotlight-results"><div class="sp-cards" id="sp-cards"></div></div>
  </div>
</div>

<div class="container">

<!-- === REMEDIATION QUICK-REF === -->
<div id="rem-quickref">
  <h3>&#128295; Remediation Quick Reference &mdash; click any card to jump to full guidance</h3>
  <div class="rem-qr-grid" id="rem-qr-grid">
    <!-- populated by JS from COMP_DATA categories -->
  </div>
</div>

<!-- === SUMMARY === -->
<section id="sec-summary">
  <div class="sec-hdr" onclick="toggleSec('sec-summary')">
    <h2>&#128202; Summary</h2>
    <div class="sec-hdr-right"><span style="font-size:11px;color:var(--muted)">click to collapse</span><span class="collapse-btn" id="sec-summary-btn">&#9660;</span></div>
  </div>
  <div id="sec-summary-body">
    <div class="stat-grid">
      <div class="stat-card info clickable" onclick="cardJump('sec-audit',null,null)" title="Jump to Full Audit Log  -  all results">
        <div class="val">$totalRows</div><div class="lbl">Total task results <span class="arr">&#8599;</span></div>
      </div>
      <div class="stat-card info clickable" onclick="cardJump('sec-issues',null,null)" title="Jump to Computers with Issues">
        <div class="val">$uniqueComputers</div><div class="lbl">Unique computers <span class="arr">&#8599;</span></div>
      </div>
      <div class="stat-card success clickable" onclick="cardJump('sec-audit','all','Success')" title="Jump to Audit Log  -  filter to Successful only">
        <div class="val">$($successRows.Count)</div><div class="lbl">Successful ($pctSuccess%) <span class="arr">&#8599;</span></div>
      </div>
      <div class="stat-card danger clickable" onclick="cardJump('sec-failures',null,null)" title="Jump to All Failed Results">
        <div class="val">$($failRows.Count)</div><div class="lbl">Failed ($pctFail%) <span class="arr">&#8599;</span></div>
      </div>
      <div class="stat-card warn clickable" onclick="cardJump('sec-notactive',null,null)" title="Jump to Not Active list">
        <div class="val">$($notActiveOnly.Count)</div><div class="lbl">Not Active computers <span class="arr">&#8599;</span></div>
      </div>
      <div class="stat-card success clickable" onclick="cardJump('sec-audit','all','FullyOk')" title="Jump to Audit Log  -  filter to fully successful computers only">
        <div class="val">$($fullyOkComputers.Count)</div><div class="lbl">Fully successful <span class="arr">&#8599;</span></div>
      </div>
      <div class="stat-card danger clickable" onclick="cardJump('sec-issues','comp','taskfail')" title="Jump to Issues  -  filter to computers with task-level errors">
        <div class="val">$($taskFailComputers.Count)</div><div class="lbl">Task-level errors <span class="arr">&#8599;</span></div>
      </div>
    </div>
    <!-- Quick remediation pills under summary cards -->
    <div id="rem-quick" style="margin-top:14px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;">
      <span style="font-size:11px;color:var(--muted);font-weight:600;text-transform:uppercase;letter-spacing:.05em;">Quick Remediation:</span>
    </div>
  </div>
</section>

$fileStatsHtml

<!-- === CHART === -->
<section id="sec-chart">
  <div class="sec-hdr" onclick="toggleSec('sec-chart')">
    <h2>&#128200; Failure Distribution</h2>
    <span class="collapse-btn" id="sec-chart-btn">&#9660;</span>
  </div>
  <div id="sec-chart-body">
    <div class="chart-wrap">
      <canvas id="donut" width="200" height="200"></canvas>
      <div class="chart-legend" id="legend"></div>
    </div>
  </div>
</section>

$multiCompTableHtml

<!-- === COMPUTERS WITH ISSUES === -->
<section id="sec-issues">
  <div class="sec-hdr" onclick="toggleSec('sec-issues')">
    <h2>&#128421; Computers with Issues &#8212; Task Detail</h2>
    <span class="collapse-btn" id="sec-issues-btn">&#9660;</span>
  </div>
  <div id="sec-issues-body">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
      <span id="comp-count" class="row-count"></span>
    </div>
    <div class="filter-bar" id="comp-filter-bar">
      <input class="table-search" type="text" id="compSearch" placeholder="Filter computers..." oninput="applyCompFilters()">
      <select class="filter-select" id="comp-cat-filter" onchange="applyCompFilters()" title="Filter by error category">
        <option value="">All Categories</option>
      </select>
      <select class="filter-select" id="comp-method-filter" onchange="applyCompFilters()" title="Filter by failed method">
        <option value="">All Methods</option>
      </select>
      <select class="filter-select" id="comp-subnet-filter" onchange="applyCompFilters()" title="Filter by subnet">
        <option value="">All Subnets</option>
        <option value="__UNKNOWN__">Unknown IP</option>
      </select>
      <label class="filter-toggle" title="Hide/show computers with Unknown IP">
        <input type="checkbox" id="comp-hide-unknown" onchange="applyCompFilters()"> Hide Unknown IP
      </label>
      <button class="filter-btn" onclick="exportTable('compTable','issues')">&#128196; Export CSV</button>
      <button class="filter-btn" onclick="printSection('sec-issues')">&#128424; Print / PDF</button>
    </div>
    <div class="table-wrap">
    <table id="compTable">
    <thead><tr><th onclick="sortTable('compTable',0,this)" class="sortable">Computer <span class="sort-icon">&#8597;</span></th><th onclick="sortTable('compTable',1,this)" class="sortable">IP Address <span class="sort-icon">&#8597;</span></th><th onclick="sortTable('compTable',2,this)" class="sortable num-col">&#10004; OK <span class="sort-icon">&#8597;</span></th><th onclick="sortTable('compTable',3,this)" class="sortable num-col">&#10008; Failed <span class="sort-icon">&#8597;</span></th><th>Error Categories</th><th>Failed Methods</th><th onclick="sortTable('compTable',6,this)" class="sortable">Status <span class="sort-icon">&#8597;</span></th><th>File / Line(s)</th>$compSrcHeader</tr></thead>
    <tbody>$($compSummaryRows -join '')</tbody>
    </table>
    </div>
  </div>
</section>

<!-- === ALL FAILURES === -->
<section id="sec-failures">
  <div class="sec-hdr" onclick="toggleSec('sec-failures')">
    <h2>&#10060; All Failed Results ($($failRows.Count) rows, $(@($failRows | Select-Object -ExpandProperty ComputerName -Unique).Count) computers)</h2>
    <span class="collapse-btn" id="sec-failures-btn">&#9660;</span>
  </div>
  <div id="sec-failures-body">
    <div class="filter-bar">
      <input class="table-search" type="text" id="failSearch" placeholder="Filter by computer, task, or status..." oninput="applyFailFilters()">
      <select class="filter-select" id="fail-cat-filter" onchange="applyFailFilters()" title="Filter by category">
        <option value="">All Categories</option>
      </select>
      <select class="filter-select" id="fail-method-filter" onchange="applyFailFilters()" title="Filter by method">
        <option value="">All Methods</option>
      </select>
      <select class="filter-select" id="fail-subnet-filter" onchange="applyFailFilters()" title="Filter by subnet">
        <option value="">All Subnets</option>
        <option value="__UNKNOWN__">Unknown IP</option>
      </select>
      <label class="filter-toggle">
        <input type="checkbox" id="fail-hide-unknown" onchange="applyFailFilters()"> Hide Unknown IP
      </label>
      <button class="filter-btn" onclick="exportTable('failTable','failures')">&#128196; Export CSV</button>
      <button class="filter-btn" onclick="printSection('sec-failures')">&#128424; Print / PDF</button>
      <span style="width:1px;height:18px;background:var(--border);display:inline-block;margin:0 4px"></span>
      <button class="filter-btn" onclick="collapseAll('failTbody')" title="Collapse all computers">&#9654;&#9654; Collapse all</button>
      <button class="filter-btn" onclick="expandAll('failTbody')" title="Expand all computers">&#9660;&#9660; Expand all</button>
      <span id="fail-count" class="row-count"></span>
    </div>
    <div class="table-wrap">
    <table id="failTable">
    <thead><tr><th onclick="sortTable('failTable',0,this)" class="sortable">Computer <span class="sort-icon">&#8597;</span></th><th onclick="sortTable('failTable',1,this)" class="sortable">Task <span class="sort-icon">&#8597;</span></th><th onclick="sortTable('failTable',2,this)" class="sortable">Category <span class="sort-icon">&#8597;</span></th><th onclick="sortTable('failTable',3,this)" class="sortable">Method <span class="sort-icon">&#8597;</span></th><th>Data Collected</th><th onclick="sortTable('failTable',5,this)" class="sortable">Status Detail <span class="sort-icon">&#8597;</span></th><th onclick="sortTable('failTable',6,this)" class="sortable">IP <span class="sort-icon">&#8597;</span></th><th>File / Line</th>$failSrcHeader</tr></thead>
    <tbody id='failTbody'></tbody>
    </table>
    </div>
    <div class="pg-bar" id="fail-pagin"></div>
  </div>
</section>

<!-- === REMEDIATION === -->
<section id="sec-remediation">
  <div class="sec-hdr" onclick="toggleSec('sec-remediation')">
    <h2>&#128295; Remediation Guidance</h2>
    <span class="collapse-btn" id="sec-remediation-btn">&#9660;</span>
  </div>
  <div id="sec-remediation-body">
    $($remCards -join '')
  </div>
</section>

<!-- === NOT ACTIVE === -->
<section id="sec-notactive">
  <div class="sec-hdr" onclick="toggleSec('sec-notactive')">
    <h2>&#128164; Not Active Computers ($($notActiveOnly.Count))</h2>
    <span class="collapse-btn" id="sec-notactive-btn">&#9660;</span>
  </div>
  <div id="sec-notactive-body">
    <div class="filter-bar" style="margin-bottom:10px">
      <span class="row-count">$($notActiveOnly.Count) computers</span>
      <button class="filter-btn" onclick="exportNotActive()">&#128196; Export CSV</button>
      <button class="filter-btn" onclick="printSection('sec-notactive')">&#128424; Print / PDF</button>
    </div>
    <div class="details-body" id="notactive-list">$notActiveHtml</div>
  </div>
</section>

<!-- === FULL AUDIT LOG === -->
<section id="sec-audit">
  <div class="sec-hdr" onclick="toggleSec('sec-audit')">
    <h2>&#128203; Full Audit Log &#8212; All Results</h2>
    <span class="collapse-btn" id="sec-audit-btn">&#9660;</span>
  </div>
  <div id="sec-audit-body">
    <div class="filter-bar">
      <input class="table-search" type="text" id="allSearch" placeholder="Filter all results..." oninput="filterAllData()">
      <button class="filter-btn" onclick="exportTable('allTable','audit')">&#128196; Export CSV</button>
      <button class="filter-btn" onclick="printSection('sec-audit')">&#128424; Print / PDF</button>
      <button class="filter-btn" onclick="printFullReport()">&#128196; Export Full Report PDF</button>
      <span style="width:1px;height:18px;background:var(--border);display:inline-block;margin:0 4px"></span>
      <button class="filter-btn" onclick="collapseAll('allTbody')" title="Collapse all computers">&#9654;&#9654; Collapse all</button>
      <button class="filter-btn" onclick="expandAll('allTbody')" title="Expand all computers">&#9660;&#9660; Expand all</button>
    </div>
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
      <span id="all-count" class="row-count"></span>
    </div>
    <div class="table-wrap">
    <table id="allTable">
    <thead><tr><th onclick="sortTable('allTable',0,this)" class="sortable">Computer <span class="sort-icon">&#8597;</span></th><th onclick="sortTable('allTable',1,this)" class="sortable">Task <span class="sort-icon">&#8597;</span></th><th onclick="sortTable('allTable',2,this)" class="sortable">Category <span class="sort-icon">&#8597;</span></th><th onclick="sortTable('allTable',3,this)" class="sortable">Method <span class="sort-icon">&#8597;</span></th><th>Data Collected</th><th>Status Detail</th><th onclick="sortTable('allTable',6,this)" class="sortable">IP <span class="sort-icon">&#8597;</span></th><th>File / Line</th>$allSrcHeader</tr></thead>
    <tbody id='allTbody'></tbody>
    </table>
    </div>
    <div class="pg-bar" id="all-pagin"></div>
  </div>
</section>

</div>

<footer>BloodHound Enterprise &#8212; SharpHound CompStatus Analyser v1.0 &nbsp;|&nbsp; BHE Toolkit v1.0 &nbsp;|&nbsp; $reportDate</footer>

<script>
// -- Pre-built data from PowerShell (must come before load listener) -------
var COMP_SUBNETS=[$compSubnetJs];
var FAIL_DATA=$failJsonData;
var ALL_DATA=$allJsonData;
var FAIL_SUBNETS=[$failSubnetJs];

// -- Init on load ----------------------------------------------------------
// Single unified load listener  -  all init here
window.addEventListener('load',function(){

  // -- Virtual tables -------------------------------------------------------
  failFiltered=FAIL_DATA.slice();
  allFiltered=ALL_DATA.slice();
  initFilters();
  buildRemPills();
  renderFailPage(1);
  renderAllPage(1);

  // -- Issues table initial count -------------------------------------------
  var compRows=document.querySelectorAll('#compTable tbody tr').length;
  var cc=document.getElementById('comp-count');
  if(cc&&compRows>0) cc.textContent='Showing '+compRows+' of '+compRows+' computers';

  // -- Back to top button ---------------------------------------------------
  var bttBtn=document.getElementById('back-to-top');
  if(bttBtn){
    window.addEventListener('scroll',function(){
      bttBtn.style.opacity=window.pageYOffset>200?'1':'0.25';
    },{passive:true});
  }

});

// -- Chart ------------------------------------------------------------------
var chartLabels=[$chartLabels],chartValues=[$chartValues],chartColors=[$chartColors];
try{ new Chart(document.getElementById('donut'),{
  type:'doughnut',
  data:{labels:chartLabels,datasets:[{data:chartValues,backgroundColor:chartColors,borderWidth:2,borderColor:'#1e293b'}]},
  options:{cutout:'65%',plugins:{legend:{display:false},tooltip:{callbacks:{
    label:function(ctx){
      var total=chartValues.reduce(function(a,b){return a+b},0);
      return ' '+ctx.label+': '+ctx.raw+' ('+(ctx.raw/total*100).toFixed(1)+'%)';
    }
  }}}}
});
}catch(e){console.warn('Chart.js not available',e);}
var leg=document.getElementById('legend');
if(leg) chartLabels.forEach(function(l,i){
  var d=document.createElement('div');d.className='chart-legend-item';
  d.innerHTML='<div class="chart-legend-dot" style="background:'+chartColors[i]+'"></div><span><b>'+chartValues[i]+'</b> -- '+l+'</span>';
  leg.appendChild(d);
});

// -- Card jump  -  jump to section with optional pre-filter -----------------
// table: null=no filter, 'all'=allTable, 'comp'=compTable
// filter: null=clear all, 'Success'=filter audit to success,
//         'ok'=comp table show only ok-status, 'fail'=comp table show only fail-status
function setSecSubtitle(secId, text){
  // Add/update a small subtitle tag below the section h2 to show active filter context
  var hdr=document.querySelector('#'+secId+' .sec-hdr h2');
  if(!hdr) return;
  var existing=hdr.querySelector('.sec-subtitle');
  if(text){
    if(!existing){ existing=document.createElement('span'); existing.className='sec-subtitle'; hdr.appendChild(existing); }
    existing.innerHTML=' &#8212; <span style="font-weight:500">'+text+'</span>';
  } else {
    if(existing) existing.remove();
  }
}

function cardJump(secId, table, filter){
  clearAllTableFilters();

  if(table==='all' && filter==='Success'){
    allFiltered=ALL_DATA.filter(function(d){return d.cat==='Success';});
    allPage=1; renderAllPage(1);
    setSecSubtitle('sec-audit','Successful tasks only: '+allFiltered.length+' rows');

  } else if(table==='all' && filter==='AllFail'){
    allFiltered=ALL_DATA.filter(function(d){return d.cat!=='Success';});
    allPage=1; renderAllPage(1);
    setSecSubtitle('sec-audit','Failed only: '+allFiltered.length+' rows');

  } else if(table==='all' && filter==='FullyOk'){
    // Build set of computers that have ANY failure
    var failedComps={};
    ALL_DATA.forEach(function(d){ if(d.cat!=='Success') failedComps[d.cn]=1; });
    // Keep only rows for computers with ZERO failures (every task succeeded)
    allFiltered=ALL_DATA.filter(function(d){ return !failedComps[d.cn]; });
    allPage=1; renderAllPage(1);
    var okComps={};
    allFiltered.forEach(function(d){okComps[d.cn]=1;});
    var okCount=Object.keys(okComps).length;
    setSecSubtitle('sec-audit','fully successful computers only: '+okCount+' computer'+(okCount!==1?'s':'')+', '+allFiltered.length+' task rows');

  } else if(table==='comp' && filter==='taskfail'){
    var shown=0, total=0;
    document.querySelectorAll('#compTable tbody tr').forEach(function(r){
      var show=r.getAttribute('data-taskfail')==='1';
      r.style.display=show?'':'none';
      if(show) shown++; total++;
    });
    setSecSubtitle('sec-issues','task-level errors only');
    var cc=document.getElementById('comp-count');
    if(cc) cc.textContent='Showing '+shown+' of '+total+' computers';

  } else if(table==='fail' && filter){
    failFiltered=FAIL_DATA.filter(function(d){return d.cat===filter;});
    failPage=1; renderFailPage(1);
    setSecSubtitle('sec-failures','filtered to '+filter+' ('+failFiltered.length+' rows)');

  } else {
    // Clear any subtitle from previous card jump
    setSecSubtitle(secId, null);
  }

  jumpTo(secId);
}

// -- Section toggle ---------------------------------------------------------
function toggleSec(id){
  var body=document.getElementById(id+'-body');
  var btn=document.getElementById(id+'-btn');
  if(!body) return;
  if(body.style.display==='none'){body.style.display='';if(btn)btn.innerHTML='&#9660;';}
  else{body.style.display='none';if(btn)btn.innerHTML='&#9654;';}
}

function jumpTo(secId){
  var body=document.getElementById(secId+'-body');
  var btn=document.getElementById(secId+'-btn');
  if(body&&body.style.display==='none'){body.style.display='';if(btn)btn.innerHTML='&#9660;';}
  var el=document.getElementById(secId);
  if(!el)return;
  requestAnimationFrame(function(){requestAnimationFrame(function(){
    var stickyH=0,sw=document.getElementById('spotlight-wrap');
    if(sw)stickyH=sw.getBoundingClientRect().height;
    var rect=el.getBoundingClientRect();
    window.scrollTo({top:window.pageYOffset+rect.top-stickyH-12,behavior:'smooth'});
  });});
}

// -- Generic text filter ----------------------------------------------------
function filterTable(tid,sid){
  var q=document.getElementById(sid).value.toLowerCase();
  document.querySelectorAll('#'+tid+' tbody tr').forEach(function(r){
    r.style.display=r.textContent.toLowerCase().indexOf(q)>=0?'':'none';
  });
}

// -- Row highlight ----------------------------------------------------------
function highlightRow(rowId){
  var el=document.getElementById(rowId);
  if(!el)return;
  var sec=el.closest('section');
  if(sec){var body=document.getElementById(sec.id+'-body'),btn=document.getElementById(sec.id+'-btn');
    if(body&&body.style.display==='none'){body.style.display='';if(btn)btn.innerHTML='&#9660;';}
  }
  requestAnimationFrame(function(){requestAnimationFrame(function(){
    var stickyH=0,sw=document.getElementById('spotlight-wrap');
    if(sw)stickyH=sw.getBoundingClientRect().height;
    var rect=el.getBoundingClientRect();
    window.scrollTo({top:window.pageYOffset+rect.top-stickyH-40,behavior:'smooth'});
    el.classList.add('highlight-row');
    setTimeout(function(){el.classList.remove('highlight-row');},2000);
  });});
}

// -- Sort -------------------------------------------------------------------
var _sortState={};
function sortTable(tid,col,th){
  var tbl=document.getElementById(tid),tbody=tbl.tBodies[0];
  var key=tid+'-'+col;
  var asc=_sortState[key]!==true;
  _sortState[key]=asc;
  tbl.querySelectorAll('thead th').forEach(function(h){h.classList.remove('sort-asc','sort-desc');});
  th.classList.add(asc?'sort-asc':'sort-desc');
  var rows=Array.from(tbody.querySelectorAll('tr'));
  rows.sort(function(a,b){
    var av=(a.cells[col]||{}).textContent||'';
    var bv=(b.cells[col]||{}).textContent||'';
    var an=parseFloat(av),bn=parseFloat(bv);
    if(!isNaN(an)&&!isNaN(bn))return asc?an-bn:bn-an;
    return asc?av.localeCompare(bv):bv.localeCompare(av);
  });
  rows.forEach(function(r){tbody.appendChild(r);});
}

// -- Filter initialisation  -  populate dropdowns from live table data --------
function getUniqVals(tid,colIdx){
  var vals={};
  document.querySelectorAll('#'+tid+' tbody tr').forEach(function(r){
    var cell=r.cells[colIdx];
    if(!cell)return;
    // extract text from badges too
    cell.querySelectorAll('.badge').forEach(function(b){vals[b.textContent.trim()]=1;});
    var plain=cell.textContent.trim().replace(/\s+/g,' ');
    if(plain)plain.split(',').forEach(function(p){var v=p.trim();if(v&&v.length>1)vals[v]=1;});
  });
  return Object.keys(vals).sort();
}

function populateSelect(selId,vals){
  var sel=document.getElementById(selId);
  if(!sel)return;
  var cur=sel.value;
  while(sel.options.length>1)sel.remove(1);
  vals.forEach(function(v){
    var o=document.createElement('option');o.value=v;o.text=v;sel.appendChild(o);
  });
  sel.value=cur;
}

// Extract /24 subnet prefix from an IP string e.g. "10.0.2.42" -> "10.0.2.x"
// Returns null for Unknown / empty / IPv6 loopback
function subnetOf(ip){
  if(!ip) return null;
  ip=ip.trim();
  if(!ip||ip==='Unknown') return null;
  // Handle multi-IP cells (e.g. "10.0.1.5, 10.0.1.6") - use first IP only
  if(ip.indexOf(',')>=0) ip=ip.split(',')[0].trim();
  // Reject IPv6
  if(ip.indexOf(':')>=0) return null;
  var parts=ip.split('.');
  if(parts.length!==4) return null;
  // Validate each octet is a number
  for(var i=0;i<4;i++){ if(isNaN(parseInt(parts[i],10))) return null; }
  return parts[0]+'.'+parts[1]+'.'+parts[2]+'.x';
}

// Collect unique /24 subnets from a given IP column index in a table
function getUniqSubnets(tid, ipColIdx){
  var seen={};
  document.querySelectorAll('#'+tid+' tbody tr').forEach(function(r){
    var cell=r.cells[ipColIdx]; if(!cell) return;
    var sn=subnetOf(cell.textContent.trim());
    if(sn) seen[sn]=1;
  });
  return Object.keys(seen).sort(function(a,b){
    // sort numerically by octet
    var ap=a.split('.').map(Number), bp=b.split('.').map(Number);
    for(var i=0;i<3;i++){ if(ap[i]!==bp[i]) return ap[i]-bp[i]; }
    return 0;
  });
}

function initFilters(){
  // comp table: col 4 = error categories, col 5 = failed methods
  populateSelect('comp-cat-filter',    getUniqVals('compTable',4));
  populateSelect('comp-method-filter', getUniqVals('compTable',5));
  // Use pre-built subnet lists injected by PowerShell at generation time
  // (more reliable than DOM scanning which can pick up whitespace/newlines)
  populateSelect('comp-subnet-filter', COMP_SUBNETS);
  populateSelect('fail-cat-filter',    getUniqVals('failTable',2));
  populateSelect('fail-method-filter', getUniqVals('failTable',3));
  populateSelect('fail-subnet-filter', FAIL_SUBNETS);
}

// -- Compound filter for computers-with-issues table ------------------------
function applyCompFilters(){
  var q      =(document.getElementById('compSearch')||{value:''}).value.toLowerCase();
  var cat    =(document.getElementById('comp-cat-filter')||{value:''}).value.toLowerCase();
  var meth   =(document.getElementById('comp-method-filter')||{value:''}).value.toLowerCase();
  var subnet =(document.getElementById('comp-subnet-filter')||{value:''}).value;
  var hideEl=document.getElementById('comp-hide-unknown');
  // Disable "Hide Unknown IP" when "Unknown IP" subnet is selected  -  they conflict
  if(hideEl){ hideEl.disabled=(subnet==='__UNKNOWN__'); if(subnet==='__UNKNOWN__') hideEl.checked=false; }
  var hideU=(hideEl&&!hideEl.disabled)?hideEl.checked:false;
  document.querySelectorAll('#compTable tbody tr').forEach(function(r){
    var txt=r.textContent.toLowerCase();
    var ip=(r.cells[1]||{textContent:''}).textContent.trim();
    var show=true;
    if(q&&txt.indexOf(q)<0)show=false;
    if(cat&&txt.indexOf(cat)<0)show=false;
    if(meth&&txt.indexOf(meth)<0)show=false;
    if(subnet==='__UNKNOWN__'&&ip!=='Unknown')show=false;
    else if(subnet&&subnet!=='__UNKNOWN__'&&subnetOf(ip)!==subnet)show=false;
    if(hideU&&ip==='Unknown')show=false;
    r.style.display=show?'':'none';
  });
  // Update count label
  var visible=document.querySelectorAll('#compTable tbody tr:not([style*="display: none"])').length;
  var total=document.querySelectorAll('#compTable tbody tr').length;
  var cnt=document.getElementById('comp-count');
  if(cnt) cnt.textContent='Showing '+visible+' of '+total+' computers';
}

// -- Compound filter for failures table ------------------------------------
// -- Virtual pagination engine ----------------------------------------------
var PAGE_SIZE=100; // default, overridden per table
var failPageSize=25, allPageSize=25;
var failFiltered=[], failPage=1;
var allFiltered=[],  allPage=1;

var catColors={Success:'#22c55e',NotActive:'#6b7280',PortNotOpen:'#f97316',
  AccessDenied:'#ef4444',StatusAccessDenied:'#ef4444',RPCError:'#a855f7',
  RegistryError:'#ec4899',CollectorError:'#f59e0b',NonWindowsOS:'#0891b2',
  Timeout:'#dc2626',NumericError:'#92400e',Other:'#64748b'};
var methodColors={'TCP Port Scan':'#0369a1','SMB / NetWkstaUserEnum':'#0f766e',
  'SMB / SAMRPC':'#0f766e','RPC / LSARPC':'#7c3aed','WMI':'#b45309',
  'Remote Registry (RRP)':'#9a3412','LDAP':'#1d4ed8','Unknown':'#475569'};

function esc(v){ return v.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// Group colours  -  two alternating surface tones for computer groups
var GROUP_COLORS=['var(--surface)','var(--bg)'];

// Collapsed state: keyed by tbodyId|cn  -  persists across page turns
var collapsedGroups={};
function collapseAll(tbodyId){
  // Mark all current computers as collapsed then re-render
  var tbody=document.getElementById(tbodyId); if(!tbody) return;
  tbody.querySelectorAll('td.grp-toggle').forEach(function(td){
    var cn=td.getAttribute('data-cn');
    if(cn) collapsedGroups[tbodyId+'|'+cn]=true;
  });
  if(tbodyId==='failTbody') renderFailPage(failPage);
  else renderAllPage(allPage);
}

function expandAll(tbodyId){
  // Clear all collapse state for this tbody then re-render
  Object.keys(collapsedGroups).forEach(function(k){
    if(k.indexOf(tbodyId+'|')===0) delete collapsedGroups[k];
  });
  if(tbodyId==='failTbody') renderFailPage(failPage);
  else renderAllPage(allPage);
}

function toggleGroup(tbodyId,cn){
  var key=tbodyId+'|'+cn;
  collapsedGroups[key]=!collapsedGroups[key];
  if(tbodyId==='failTbody') renderFailPage(failPage);
  else if(tbodyId==='allTbody') renderAllPage(allPage);
}
// Event delegation  -  handles clicks on dynamically rendered grp-toggle cells
document.addEventListener('click',function(e){
  var cell=e.target.closest('.grp-toggle');
  if(!cell) return;
  var tbody=cell.getAttribute('data-tbody');
  var cn=cell.getAttribute('data-cn');
  if(tbody&&cn) toggleGroup(tbody,cn);
});

function rowHtml(d, multiFile, isFirstInGroup, groupIdx, groupSize, tbodyId){
  var catCol=d.catColor||(catColors[d.cat]||'#64748b');
  var methCol=methodColors[d.method]||'#475569';
  var srcCol=multiFile?'<td style="font-size:11px;color:var(--muted)">'+esc(d.src)+'</td>':'';
  var groupBg=GROUP_COLORS[groupIdx%2];
  var key=tbodyId+'|'+d.cn;
  var collapsed=!!collapsedGroups[key];
  if(isFirstInGroup){
    var arrow=collapsed?'&#9654;':'&#9660;';
    var badge=groupSize>1?'<span style="font-size:10px;color:var(--muted);margin-left:6px;background:var(--surface2);padding:1px 5px;border-radius:3px;">'+groupSize+' tasks</span>':'';
    // Use data attributes to avoid quote escaping issues in onclick
    var cnCell='<td class="cn-cell grp-toggle" data-tbody="'+esc(tbodyId)+'" data-cn="'+esc(d.cn)+'" style="vertical-align:top;cursor:pointer;user-select:none">'
      +'<span class="grp-arrow" style="font-size:10px;color:var(--muted);margin-right:4px;display:inline-block;width:10px">'+arrow+'</span>'
      +esc(d.cn)+badge+'</td>';
    return '<tr data-comp="'+esc(d.cn)+'" style="background:'+groupBg+';border-top:2px solid var(--border)">'
      +cnCell
      +'<td style="font-size:12px">'+esc(d.task)+'</td>'
      +'<td><span class="badge" style="background:'+catCol+'">'+esc(d.cat)+'</span></td>'
      +'<td class="method-cell"><span class="badge" style="background:'+methCol+';font-size:10px">'+esc(d.method)+'</span></td>'
      +'<td class="dt-cell">'+esc(d.dtype)+'</td>'
      +'<td class="status-cell">'+esc(d.status)+'</td>'
      +'<td style="font-size:12px">'+esc(d.ip)+'</td>'
      +'<td style="font-family:Consolas,monospace;font-size:11px;color:var(--muted)">'+(d.src?'<span style="color:#64748b">'+esc(d.src)+'</span><br>':'')+'L'+d.line+'</td>'
      +srcCol+'</tr>';
  } else {
    var disp=collapsed?'display:none;':'';
    return '<tr data-comp="'+esc(d.cn)+'" style="background:'+groupBg+';'+disp+'">'
      +'<td style="border-left:3px solid var(--border)"></td>'
      +'<td style="font-size:12px">'+esc(d.task)+'</td>'
      +'<td><span class="badge" style="background:'+catCol+'">'+esc(d.cat)+'</span></td>'
      +'<td class="method-cell"><span class="badge" style="background:'+methCol+';font-size:10px">'+esc(d.method)+'</span></td>'
      +'<td class="dt-cell">'+esc(d.dtype)+'</td>'
      +'<td class="status-cell">'+esc(d.status)+'</td>'
      +'<td style="font-size:12px">'+esc(d.ip)+'</td>'
      +'<td style="font-family:Consolas,monospace;font-size:11px;color:var(--muted)">'+(d.src?'<span style="color:#64748b">'+esc(d.src)+'</span><br>':'')+'L'+d.line+'</td>'
      +srcCol+'</tr>';
  }
}

function matchRow(d, q, cat, meth, subnet, hideU){
  var search=(d.cn+d.task+d.cat+d.method+d.dtype+d.status+d.ip+d.src).toLowerCase();
  if(q&&search.indexOf(q)<0) return false;
  if(cat&&d.cat.toLowerCase().indexOf(cat)<0) return false;
  if(meth&&d.method.toLowerCase().indexOf(meth)<0) return false;
  if(subnet==='__UNKNOWN__'&&d.ip!=='Unknown') return false;
  else if(subnet&&subnet!=='__UNKNOWN__'&&subnetOf(d.ip)!==subnet) return false;
  if(hideU&&d.ip==='Unknown') return false;
  return true;
}

function renderPage(data, page, tbodyId, countId, paginId, multiFile, pageSize){
  var ps=pageSize||PAGE_SIZE;
  var start=(page-1)*ps, end=Math.min(start+ps,data.length);
  var tbody=document.getElementById(tbodyId); if(!tbody) return;
  if(!data.length){
    tbody.innerHTML='<tr><td colspan="9" style="text-align:center;padding:20px;color:var(--muted)">No results match the current filters.</td></tr>';
  } else {
    // Computer-based paging: find the row range that covers exactly ps computers
    // Step 1: find start row index from page number (skip past previous pages' computers)
    var compsBefore=0, rowStart=0;
    var seenBefore={};
    if(page>1){
      for(var bi=0;bi<data.length;bi++){
        if(!seenBefore[data[bi].cn]){ seenBefore[data[bi].cn]=1; compsBefore++; }
        if(compsBefore>=(page-1)*ps){ rowStart=bi+1; break; }
      }
    }
    // Step 2: find how many rows cover ps computers from rowStart
    var compsSeen={}, compCount=0, rowEnd=rowStart;
    for(var ai=rowStart;ai<data.length;ai++){
      if(!compsSeen[data[ai].cn]){ compsSeen[data[ai].cn]=1; compCount++; }
      rowEnd=ai+1;
      if(compCount>=ps) break;
    }
    var slice=data.slice(rowStart,rowEnd);
    // Calculate group colour index (count distinct computers before this page)
    var groupIdx=0;
    var colourSeen={};
    for(var ci=0;ci<rowStart;ci++){
      if(!colourSeen[data[ci].cn]){colourSeen[data[ci].cn]=1;groupIdx++;}
    }
    // Build group size map for this page's slice
    var groupSizes={};
    for(var si=0;si<slice.length;si++){
      groupSizes[slice[si].cn]=(groupSizes[slice[si].cn]||0)+1;
    }
    var html='';
    var curCn=null, curGroupIdx=groupIdx;
    for(var i=0;i<slice.length;i++){
      var d=slice[i];
      var isFirst=(d.cn!==curCn);
      if(isFirst){ if(curCn!==null) curGroupIdx++; curCn=d.cn; }
      html+=rowHtml(d, multiFile, isFirst, curGroupIdx, groupSizes[d.cn], tbodyId);
    }
    tbody.innerHTML=html;
    // Update start/end for count label below
    start=rowStart; end=rowEnd;
  }
  // Update count: show computers and rows
  var cnt=document.getElementById(countId);
  if(cnt){
    var uniqueComps={};
    data.forEach(function(d){uniqueComps[d.cn]=1;});
    var compCount=Object.keys(uniqueComps).length;
    cnt.textContent=compCount+' computer'+(compCount!==1?'s':'')+' | '+data.length+' task row'+(data.length!==1?'s':'');
  }
  // Update pagination
  var pagin=document.getElementById(paginId); if(!pagin) return;
  // Total pages based on unique computer count, not row count
  var totalComps=(function(){ var u={}; data.forEach(function(d){u[d.cn]=1;}); return Object.keys(u).length; })();
  var totalPages=Math.ceil(totalComps/ps)||1;
  var html='';
  // Page size selector  -  calls setPageSize(tableId, value)
  var tblKey=paginId==='fail-pagin'?'fail':'all';
  var curPs=paginId==='fail-pagin'?failPageSize:allPageSize;
  var sizeSelector='<select class="pg-size-sel" onchange="setPageSize(\''+tblKey+'\',this.value)">'
    +'<option value="10"'+(curPs===10?' selected':'')+'>10</option>'
    +'<option value="25"'+(curPs===25?' selected':'')+'>25</option>'
    +'<option value="50"'+(curPs===50?' selected':'')+'>50</option>'
    +'<option value="100"'+(curPs===100?' selected':'')+'>100</option>'
    +'</select><span style="font-size:11px;color:var(--muted);margin-right:6px">computers / page</span>';
  html+=sizeSelector;
  html+='<button class="pg-btn" onclick="'+paginId.replace('-pagin','')+'GoPage('+Math.max(1,page-1)+')" '+(page<=1?'disabled':'')+'>&#8249; Prev</button>';
  // show up to 7 page buttons around current
  var start2=Math.max(1,page-3), end2=Math.min(totalPages,page+3);
  if(start2>1) html+='<button class="pg-btn" onclick="'+paginId.replace('-pagin','')+'GoPage(1)">1</button>'+(start2>2?'<span class="pg-ellipsis">&hellip;</span>':'');
  for(var p=start2;p<=end2;p++){
    html+='<button class="pg-btn'+(p===page?' pg-active':'')+'" onclick="'+paginId.replace('-pagin','')+'GoPage('+p+')">'+p+'</button>';
  }
  if(end2<totalPages) html+=(end2<totalPages-1?'<span class="pg-ellipsis">&hellip;</span>':'')+'<button class="pg-btn" onclick="'+paginId.replace('-pagin','')+'GoPage('+totalPages+')">'+totalPages+'</button>';
  html+='<button class="pg-btn" onclick="'+paginId.replace('-pagin','')+'GoPage('+Math.min(totalPages,page+1)+')" '+(page>=totalPages?'disabled':'')+'>Next &#8250;</button>';
  pagin.innerHTML=html;
}

var IS_MULTI=$($isMultiFile.ToString().ToLower());

function setPageSize(tbl, val){
  var n=parseInt(val)||25;
  if(tbl==='fail'){ failPageSize=n; failPage=1; renderFailPage(1); }
  else            { allPageSize=n;  allPage=1;  renderAllPage(1);  }
}

function filterFailData(){
  var q   =(document.getElementById('failSearch')||{value:''}).value.toLowerCase();
  var cat =(document.getElementById('fail-cat-filter')||{value:''}).value.toLowerCase();
  var meth=(document.getElementById('fail-method-filter')||{value:''}).value.toLowerCase();
  var sn  =(document.getElementById('fail-subnet-filter')||{value:''}).value;
  var huEl=document.getElementById('fail-hide-unknown');
  if(huEl){ huEl.disabled=(sn==='__UNKNOWN__'); if(sn==='__UNKNOWN__') huEl.checked=false; }
  var hu  =(huEl&&!huEl.disabled)?huEl.checked:false;
  failFiltered=FAIL_DATA.filter(function(d){return matchRow(d,q,cat,meth,sn,hu);});
  failPage=1; renderFailPage(1);
}
function renderFailPage(p){ failPage=p; renderPage(failFiltered,p,'failTbody','fail-count','fail-pagin',IS_MULTI,failPageSize); }
function failGoPage(p){ renderFailPage(p); }
function applyFailFilters(){ filterFailData(); }

function filterAllData(){
  var q=(document.getElementById('allSearch')||{value:''}).value.toLowerCase();
  allFiltered=ALL_DATA.filter(function(d){ return d.cn.toLowerCase().indexOf(q)>=0||d.task.toLowerCase().indexOf(q)>=0||d.status.toLowerCase().indexOf(q)>=0||d.ip.toLowerCase().indexOf(q)>=0||d.cat.toLowerCase().indexOf(q)>=0; });
  allPage=1; renderAllPage(1);
}
function renderAllPage(p){ allPage=p; renderPage(allFiltered,p,'allTbody','all-count','all-pagin',IS_MULTI,allPageSize); }
function allGoPage(p){ renderAllPage(p); }

function clearAllTableFilters(){
  var pairs=[['compSearch','compTable'],['failSearch','failTable'],['allSearch','allTable']];
  pairs.forEach(function(p){
    var inp=document.getElementById(p[0]);if(inp)inp.value='';
    document.querySelectorAll('#'+p[1]+' tbody tr').forEach(function(r){r.style.display='';});
  });
  ['comp-cat-filter','comp-method-filter','comp-subnet-filter',
   'fail-cat-filter','fail-method-filter','fail-subnet-filter'].forEach(function(id){
    var el=document.getElementById(id);if(el)el.value='';
  });
  ['comp-hide-unknown','fail-hide-unknown'].forEach(function(id){
    var el=document.getElementById(id);if(el)el.checked=false;
  });
  // Reset virtual pagination tables to show all data
  if(typeof FAIL_DATA!=='undefined'){ failFiltered=FAIL_DATA.slice(); failPage=1; renderFailPage(1); }
  if(typeof ALL_DATA!=='undefined'){  allFiltered=ALL_DATA.slice();  allPage=1;  renderAllPage(1);  }
  // Remove any active filter subtitles from section headers
  document.querySelectorAll('.sec-subtitle').forEach(function(el){el.remove();});
  // Reset comp-count synchronously  -  cardJump overwrites this immediately after
  var allCompRows=document.querySelectorAll('#compTable tbody tr');
  var cc=document.getElementById('comp-count');
  if(cc&&allCompRows.length>0) cc.textContent='Showing '+allCompRows.length+' of '+allCompRows.length+' computers';
}

// -- Export visible rows to CSV ---------------------------------------------
function exportTable(tid,name){
  // For paginated tables, export from data array not DOM
  if(tid==='failTable'||tid==='allTable'){
    var data=tid==='failTable'?failFiltered:allFiltered;
    var headers='"Computer","Task","Category","Method","Data Collected","Status","IP","Line"'+(IS_MULTI?',"Source File"':'');
    var rows=[headers];
    data.forEach(function(d){
      rows.push([d.cn,d.task,d.cat,d.method,d.dtype,d.status,d.ip,d.line].map(function(v){return '"'+String(v).replace(/"/g,'""')+'"';}).join(',')+(IS_MULTI?',"'+d.src.replace(/"/g,'""')+'"':''));
    });
    var blob=new Blob([rows.join('\r\n')],{type:'text/csv'});
    var a=document.createElement('a');a.href=URL.createObjectURL(blob);
    a.download='BHE-'+name+'-export-'+new Date().toISOString().slice(0,10)+'.csv';a.click();return;
  }
  var tbl=document.getElementById(tid);
  if(!tbl)return;
  var rows=[];
  // headers
  var ths=tbl.querySelectorAll('thead th');
  rows.push(Array.from(ths).map(function(h){return '"'+h.textContent.replace(/[▲▼↕]/g,'').trim()+'"';}).join(','));
  // visible data rows
  tbl.querySelectorAll('tbody tr').forEach(function(r){
    if(r.style.display==='none')return;
    var cols=Array.from(r.cells).map(function(c){
      return '"'+c.textContent.replace(/\s+/g,' ').trim().replace(/"/g,"'")+'"';
    });
    rows.push(cols.join(','));
  });
  var blob=new Blob([rows.join('\r\n')],{type:'text/csv'});
  var a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='BHE-'+name+'-'+new Date().toISOString().slice(0,10)+'.csv';
  a.click();
}

// -- Print section as PDF ---------------------------------------------------
function printSection(secId){
  var el=document.getElementById(secId);
  if(!el)return;
  var w=window.open('','_blank','width=1200,height=800');
  w.document.write('<html><head><title>BHE Report - '+secId+'</title>');
  w.document.write('<style>');
  w.document.write('body{font-family:Segoe UI,sans-serif;font-size:12px;color:#1e293b;background:#fff;}');
  w.document.write('table{width:100%;border-collapse:collapse;margin-top:12px;}');
  w.document.write('th{background:#f1f5f9;padding:7px 10px;text-align:left;font-size:10px;text-transform:uppercase;border:1px solid #cbd5e1;}');
  w.document.write('td{padding:6px 10px;border:1px solid #e2e8f0;vertical-align:top;font-size:11px;}');
  w.document.write('tr:nth-child(even){background:#f8fafc;}');
  w.document.write('.badge{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:700;color:#fff;margin:1px;}');
  w.document.write('h2{font-size:14px;font-weight:700;color:#0f172a;border-bottom:2px solid #0ea5e9;padding-bottom:4px;margin:0 0 12px;}');
  w.document.write('@media print{.filter-bar,.sec-hdr .collapse-btn{display:none;}}');
  w.document.write('</style></head><body>');
  w.document.write('<h2>BHE Collection Status  -  '+secId.replace('sec-','').replace(/-/g,' ').toUpperCase()+'</h2>');
  // clone just the table/content, not the filter bar controls
  var clone=el.cloneNode(true);
  var fb=clone.querySelector('.filter-bar');if(fb)fb.remove();
  var secHdr=clone.querySelector('.sec-hdr');if(secHdr)secHdr.remove();
  w.document.write(clone.innerHTML);
  w.document.write('</body></html>');
  w.document.close();
  w.focus();
  setTimeout(function(){w.print();},400);
}

// -- Print full report as PDF -----------------------------------------------
function printFullReport(){
  var w=window.open('','_blank','width=1200,height=900');
  w.document.write('<html><head><title>BHE Full Report</title>');
  w.document.write('<style>');
  w.document.write('body{font-family:Segoe UI,sans-serif;font-size:12px;color:#1e293b;background:#fff;margin:20px;}');
  w.document.write('table{width:100%;border-collapse:collapse;margin:8px 0 20px;}');
  w.document.write('th{background:#f1f5f9;padding:6px 9px;text-align:left;font-size:10px;text-transform:uppercase;border:1px solid #cbd5e1;}');
  w.document.write('td{padding:5px 9px;border:1px solid #e2e8f0;vertical-align:top;font-size:11px;}');
  w.document.write('tr:nth-child(even) td{background:#f8fafc;}');
  w.document.write('.badge{display:inline-block;padding:1px 5px;border-radius:3px;font-size:10px;font-weight:700;color:#fff;margin:1px;}');
  w.document.write('h1{font-size:18px;color:#0f172a;border-bottom:3px solid #0ea5e9;padding-bottom:6px;margin-bottom:16px;}');
  w.document.write('h2{font-size:13px;font-weight:700;color:#0f172a;border-bottom:1px solid #cbd5e1;padding:4px 0;margin:16px 0 8px;page-break-after:avoid;}');
  w.document.write('.stat-row{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px;}');
  w.document.write('.stat-box{border:1px solid #cbd5e1;border-radius:6px;padding:10px 14px;min-width:120px;}');
  w.document.write('.stat-box .v{font-size:22px;font-weight:700;}');
  w.document.write('.stat-box .l{font-size:11px;color:#64748b;margin-top:2px;}');
  w.document.write('@page{margin:15mm;}');
  w.document.write('@media print{.no-print{display:none;}}');
  w.document.write('</style></head><body>');
  // Title
  var hdr=document.querySelector('header h1');
  w.document.write('<h1>'+(hdr?hdr.textContent:'BHE Collection Status Report')+'</h1>');
  var metaEl=document.querySelector('header .meta');
  if(metaEl)w.document.write('<p style="font-size:11px;color:#64748b;margin-bottom:16px;">'+metaEl.textContent+'</p>');
  // Summary stats
  w.document.write('<h2>Summary</h2><div class="stat-row">');
  document.querySelectorAll('.stat-card').forEach(function(c){
    var val=c.querySelector('.val'),lbl=c.querySelector('.lbl');
    if(val&&lbl)w.document.write('<div class="stat-box"><div class="v">'+(val.textContent||'')+'</div><div class="l">'+(lbl.textContent||'')+'</div></div>');
  });
  w.document.write('</div>');
  // Each section
  var sections=['sec-issues','sec-failures','sec-remediation','sec-notactive','sec-audit'];
  sections.forEach(function(sid){
    var el=document.getElementById(sid);if(!el)return;
    var hdr2=el.querySelector('h2');
    w.document.write('<h2>'+(hdr2?hdr2.textContent.replace(/[▲▼↕⬇⬆]/g,'').trim():'')+'</h2>');
    var clone=el.cloneNode(true);
    var fb=clone.querySelector('.filter-bar');if(fb)fb.remove();
    var sh=clone.querySelector('.sec-hdr');if(sh)sh.remove();
    w.document.write(clone.innerHTML);
  });
  w.document.write('</body></html>');
  w.document.close();w.focus();
  setTimeout(function(){w.print();},600);
}

// -- Remediation quick pills in summary ------------------------------------
var REM_DESCS={
  NotActive:     'Computer offline, stale AD object, or unreachable from collector.',
  PortNotOpen:   'TCP 445/135 blocked by host firewall or network ACL.',
  AccessDenied:  'Service account missing NetWkstaUserEnum or LSA rights.',
  StatusAccessDenied: 'SeSecurityPrivilege required for LSAEnumerateAccountsWithUserRight.',
  RPCError:      'RPC Endpoint Mapper (TCP 135) unreachable or Remote Registry stopped.',
  RegistryError: 'Remote Registry running but LSA key ACL denies read access.',
  CollectorError:'SharpHound exception. Review full error in audit log.',
  Timeout:       'RPC/SMB call timed out. Heavy load, network latency, or a firewall rate-limiting specific RPC ports. Re-run during low-load window.',
  NumericError:  'Raw Win32/NTSTATUS error code. Code 53=Network path not found, 50=Not supported, 1745=No more data. Check Task column for context.',
  NonWindowsOS:  'Linux/macOS detected  -  SharpHound skips SMB/RPC collection. No action needed unless the host should be Windows.',
  Other:         'Uncategorised error. Review raw status in audit log.'
};

function jumpToRemCard(cat, colour){
  // Expand remediation section if collapsed
  var body=document.getElementById('sec-remediation-body');
  var btn=document.getElementById('sec-remediation-btn');
  if(body && body.style.display==='none'){
    body.style.display=''; if(btn) btn.innerHTML='&#9660;';
  }
  // Build the card id the same way PS does: non-alphanumeric -> dash
  var cardId='rem-card-'+cat.replace(/[^a-zA-Z0-9]/g,'-');
  var card=document.getElementById(cardId);
  if(!card){
    // Fallback: find by text content
    document.querySelectorAll('.remediation-card').forEach(function(rc){
      if(rc.textContent.indexOf(cat)>=0) card=rc;
    });
  }
  if(!card) return;
  requestAnimationFrame(function(){ requestAnimationFrame(function(){
    var stickyH=0, sw=document.getElementById('spotlight-wrap');
    if(sw) stickyH=sw.getBoundingClientRect().height;
    var rect=card.getBoundingClientRect();
    var scrollTop=window.pageYOffset||document.documentElement.scrollTop;
    window.scrollTo({top:scrollTop+rect.top-stickyH-16,behavior:'smooth'});
    card.style.outline='2px solid '+colour;
    setTimeout(function(){card.style.outline='';},2000);
  });});
}

function buildRemPills(){
  var wrap=document.getElementById('rem-quick');
  var grid=document.getElementById('rem-qr-grid');
  var catColors={
    NotActive:'#6b7280',PortNotOpen:'#f97316',AccessDenied:'#ef4444',
    StatusAccessDenied:'#ef4444',RPCError:'#a855f7',RegistryError:'#ec4899',
    CollectorError:'#f59e0b',Other:'#64748b'
  };
  chartLabels.forEach(function(cat,i){
    if(cat==='Success') return;
    var col=chartColors[i]||catColors[cat]||'#64748b';

    // -- Mini pills (inside summary section) --------------------------------
    if(wrap){
      var pill=document.createElement('span');
      pill.className='rem-pill';
      pill.style.background=col+'22';
      pill.style.borderColor=col;
      pill.style.color=col;
      pill.innerHTML='<b>'+chartValues[i]+'</b>&nbsp;'+cat;
      pill.title='Click to jump to remediation for '+cat;
      pill.onclick=(function(c,cl){ return function(){
        jumpToRemCard(c,cl);
      };})(cat,col);
      wrap.appendChild(pill);
    }

    // -- Rich cards (top quick-ref panel) -----------------------------------
    if(grid){
      var desc=REM_DESCS[cat]||'Review the full guidance in the Remediation section.';
      var card=document.createElement('div');
      card.className='rem-qr-card';
      card.style.borderLeft='3px solid '+col;
      card.title='Click to jump to full remediation guidance';
      card.innerHTML='<div class="rq-title"><span class="badge" style="background:'+col+';font-size:10px">'+cat+'</span>'
        +'<span style="font-size:10px;color:var(--muted);margin-left:6px">'+chartValues[i]+' occurrence'+(chartValues[i]===1?'':'s')+'</span></div>'
        +'<div class="rq-desc">'+desc+'</div>';
      card.onclick=(function(c,cl){ return function(){
        jumpToRemCard(c,cl);
      };})(cat,col);
      grid.appendChild(card);
    }
  });
  if(grid && !grid.children.length){
    grid.innerHTML='<span style="color:var(--muted);font-size:12px">No failure categories found.</span>';
  }
}

// -- Spotlight computer search ----------------------------------------------
var COMP_DATA=$computerJsonData;
var compIdx={};
for(var i=0;i<COMP_DATA.length;i++){ compIdx[COMP_DATA[i].n.toUpperCase()]=COMP_DATA[i]; }

var spotTimer;
document.getElementById('spotlight-input').addEventListener('input',function(){
  clearTimeout(spotTimer);
  spotTimer=setTimeout(runSpotlight,220);
});
document.getElementById('spotlight-input').addEventListener('keydown',function(e){
  if(e.key==='Escape') clearSpotlight();
});

function runSpotlight(){
  var raw=document.getElementById('spotlight-input').value;
  var terms=raw.split(',').map(function(s){return s.trim().toUpperCase();}).filter(function(s){return s.length>0;});
  var panel=document.getElementById('spotlight-results');
  var cards=document.getElementById('sp-cards');
  if(terms.length===0){ panel.style.display='none'; cards.innerHTML=''; return; }

  var matches=[]; var notFound=[];
  var keys=Object.keys(compIdx);
  for(var t=0;t<terms.length;t++){
    var term=terms[t];
    if(compIdx[term]){ matches.push(compIdx[term]); continue; }
    // partial / contains search
    var found=null;
    for(var k=0;k<keys.length;k++){
      if(keys[k].indexOf(term)>=0){ found=compIdx[keys[k]]; break; }
    }
    if(found) matches.push(found);
    else notFound.push(terms[t]);
  }

  // deduplicate matches
  var seen={};
  var uniq=matches.filter(function(m){ if(seen[m.n]) return false; seen[m.n]=1; return true; });

  var html='';
  for(var i=0;i<uniq.length;i++) html+=renderSpCard(uniq[i]);
  if(notFound.length>0) html+='<div class="sp-notfound">Not found: '+notFound.join(', ')+'</div>';
  cards.innerHTML=html;
  panel.style.display='block';
}

function catColor(cat){
  var m={Success:'#22c55e',NotActive:'#6b7280',PortNotOpen:'#f97316',AccessDenied:'#ef4444',RPCError:'#a855f7',RegistryError:'#ec4899',CollectorError:'#f59e0b',Other:'#64748b'};
  return m[cat.trim()]||'#64748b';
}

function renderSpCard(c){
  var tlColor={green:'#22c55e',orange:'#f97316',red:'#ef4444'}[c.tl]||'#6b7280';
  var tlLabel={green:'All OK',orange:'Mixed',red:'All Failed'}[c.tl]||c.tl;
  var catHtml='';
  if(c.cats){
    var cl=c.cats.split(',').filter(function(x){return x.trim();});
    for(var i=0;i<cl.length;i++) catHtml+='<span class="badge" style="background:'+catColor(cl[i].trim())+'">'+cl[i].trim()+'</span> ';
  }
  var n=c.n;
  var ns=n.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
  return '<div class="sp-card">'
    +'<div class="sp-card-hdr">'
    +'<span class="sp-name">'+n+'</span>'
    +'<span class="tl-badge" style="background:'+tlColor+'">'+tlLabel+'</span>'
    +'</div>'
    +'<div class="sp-card-meta">'
    +'<div class="sp-card-meta-row">'
    +(c.ip?'<span>IP: <code>'+c.ip+'</code></span>':'<span style="color:#6b7280">IP: Unknown</span>')
    +'<span style="color:#22c55e">&#10004; '+c.ok+' ok</span>'
    +'<span style="color:#ef4444">&#10008; '+c.fail+' failed</span>'
    +'</div>'
    +(c.lines?'<div class="sp-card-meta-row"><span style="color:#94a3b8">CSV line(s): <code>'+c.lines+'</code></span></div>':'')
    +'</div>'
    +(catHtml?'<div class="sp-card-cats">'+catHtml+'</div>':'')
    +'<div class="sp-card-links">'
    +'<a class="sp-link" href="#" onclick="spJumpIssues(\''+ns+'\');return false;">&#128421; Issues Table</a>'
    +'<a class="sp-link" href="#" onclick="spJumpAudit(\''+ns+'\');return false;">&#128203; Audit Log</a>'
    +'<a class="sp-link" href="#" onclick="spJumpFailures(\''+ns+'\');return false;">&#10060; Failures Only</a>'
    +'</div>'
    +'</div>';
}

function spJumpIssues(name){
  jumpTo('sec-issues');
  var inp=document.getElementById('compSearch');
  inp.value=name; applyCompFilters();
  return false;
}
function spJumpAudit(name){
  jumpTo('sec-audit');
  var inp=document.getElementById('allSearch');
  inp.value=name; filterAllData();
  return false;
}
function spJumpFailures(name){
  jumpTo('sec-failures');
  var inp=document.getElementById('failSearch');
  inp.value=name; applyFailFilters();
  return false;
}

function clearSpotlight(){
  document.getElementById('spotlight-input').value='';
  document.getElementById('spotlight-results').style.display='none';
  document.getElementById('sp-cards').innerHTML='';
}

// Close spotlight when clicking anywhere outside the spotlight bar
document.addEventListener('click',function(e){
  var wrap=document.getElementById('spotlight-wrap');
  if(wrap && !wrap.contains(e.target)){
    document.getElementById('spotlight-results').style.display='none';
  }
});

// -- Back to top  -  always slightly visible, fully opaque after 200px scroll -


// -- Export Not Active computers as CSV -----------------------------------
function exportNotActive(){
  var el=document.getElementById('notactive-list');
  if(!el) return;
  var names=el.innerText.split('\n').map(function(n){return n.trim();}).filter(function(n){return n.length>0;});
  var csv='Computer\r\n'+names.map(function(n){return '"'+n.replace(/"/g,'""')+'"';}).join('\r\n');
  var blob=new Blob([csv],{type:'text/csv'});
  var a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download='BHE-NotActive-'+new Date().toISOString().slice(0,10)+'.csv';
  a.click();
}

document.addEventListener('click',function(e){
  var wrap=document.getElementById('spotlight-wrap');
  if(wrap&&!wrap.contains(e.target)){
    var p=document.getElementById('spotlight-results');
    if(p){ p.style.display='none'; }
    var c=document.getElementById('sp-cards'); if(c) c.innerHTML='';
  }
});
</script>
</body>
</html>
"@


# ---------------------------------------------------------------------------
#  WRITE OUTPUT
# ---------------------------------------------------------------------------

if (-not (Test-Path $OutputFolder)) {
    New-Item -Path $OutputFolder -ItemType Directory | Out-Null
    Write-Host "  [*] Created output folder: $OutputFolder" -ForegroundColor Green
}

$timestamp   = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$modeTag     = if ($isMultiFile) { 'MultiRun' } else { 'SingleRun' }
$outFileName = "StBernardHound-CompStatus-${modeTag}_${timestamp}.html"
$outPath     = Join-Path $OutputFolder $outFileName

$html | Out-File -FilePath $outPath -Encoding UTF8 -Force

Write-Host ''
Write-Host '  +-------------------------------------------------------------+' -ForegroundColor Green
Write-Host '  |  St.Bernard-Hound - Report written successfully             |' -ForegroundColor Green
Write-Host '  +-------------------------------------------------------------+' -ForegroundColor Green
Write-Host "     $outPath" -ForegroundColor White
Write-Host ''
Write-Host '  QUICK SUMMARY' -ForegroundColor Yellow
Write-Host "    Mode               : $modeLabel"
Write-Host "    Files analysed     : $($selectedFiles.Count)"
Write-Host "    Total rows         : $totalRows"
Write-Host "    Unique computers   : $uniqueComputers"
Write-Host "    Successful results : $($successRows.Count) ($pctSuccess%)"
Write-Host "    Failed results     : $($failRows.Count) ($pctFail%)"
Write-Host "    Not Active         : $($notActiveOnly.Count) computers"
Write-Host "    Task-level errors  : $($taskFailComputers.Count) computers"
Write-Host ''
Write-Host '  FAILURE BREAKDOWN' -ForegroundColor Yellow
foreach ($cg in $catGroups) {
    Write-Host ("    {0,-22} : {1}" -f $cg.Name, $cg.Count)
}
Write-Host ''

# ---------------------------------------------------------------------------
#  STBERNARDHOUND OPENGRAPH EXPORT  (only runs when -ExportOpenGraph is set)
# ---------------------------------------------------------------------------

if ($ExportOpenGraph) {

    $ogFolder    = if ($OGOutputFolder) { $OGOutputFolder } else { $OutputFolder }
    $collName    = if ($CollectorName)  { $CollectorName  } else { $env:COMPUTERNAME }
    $collId      = 'SBH-COLLECTOR-' + ($collName -replace '[^A-Za-z0-9\-]', '-').ToUpper()
    $ogTimestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $ogFile      = "StBernardHound-OG_${ogTimestamp}.json"
    $ogPath      = Join-Path $ogFolder $ogFile
    $genAt       = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    if (-not (Test-Path $ogFolder)) {
        New-Item -Path $ogFolder -ItemType Directory | Out-Null
    }

    Write-Host ''
    Write-Host '  +-------------------------------------------------------------+' -ForegroundColor Magenta
    Write-Host '  |  St.Bernard-Hound - OpenGraph Export                        |' -ForegroundColor Magenta
    Write-Host '  +-------------------------------------------------------------+' -ForegroundColor Magenta
    Write-Host ''
    Write-Host '  [*] Building OpenGraph payload...' -ForegroundColor Cyan

    $ogResult = Export-StBernardHoundJson `
        -CompMap              $compMap `
        -CollectorId          $collId `
        -CollectorDisplayName $collName `
        -OutputPath           $ogPath `
        -IsMultiFile          $isMultiFile `
        -GeneratedAt          $genAt `
        -ChunkSize            $ChunkSize


    Write-Host ''
    Write-Host '  STBERNARDHOUND EXPORT SUMMARY' -ForegroundColor Magenta
    Write-Host "    Project            : St.Bernard-Hound - CompStatus CSV Analyser and OG JSON Generator v1"
    Write-Host "    Collector node     : $collName"
    Write-Host "    Collector ID       : $collId"
    Write-Host "    Nodes written      : $($ogResult.NodeCount)"
    Write-Host "    Edges written      : $($ogResult.EdgeCount)"
    Write-Host "    Output files       : $($ogResult.ChunkCount)"
    Write-Host ''
    if ($ogResult.ChunkCount -eq 1) {
        Write-Host "    OG JSON            : $($ogResult.Files[0])"
    } else {
        Write-Host '    OG JSON files (upload each separately):' -ForegroundColor Yellow
        $partNum = 1
        foreach ($f in $ogResult.Files) {
            Write-Host ("      Part {0:D2}  : {1}" -f $partNum, $f)
            $partNum++
        }
    }
    Write-Host ''
    Write-Host '  EDGE TYPES IN THIS PAYLOAD' -ForegroundColor Yellow
    Write-Host '    SBH_CollectionOK    - All tasks succeeded'
    Write-Host '    SBH_NotActive       - Computer offline / unreachable'
    Write-Host '    SBH_PortNotOpen     - TCP 445 / 135 blocked'
    Write-Host '    SBH_AccessDenied    - Insufficient privileges (NetWksta/LSA)'
    Write-Host '    SBH_RPCError        - RPC server unavailable'
    Write-Host '    SBH_RegistryError   - Remote registry access denied'
    Write-Host '    SBH_CollectorError  - SharpHound collector-side exception'
    Write-Host '    SBH_NonWindowsOS    - Non-Windows OS, collection skipped'
    Write-Host '    SBH_Timeout         - RPC/SMB operation timed out'
    Write-Host '    SBH_NumericError    - Raw Win32 / NTSTATUS error code'
    Write-Host '    SBH_Other           - Uncategorised / unmapped error'
    Write-Host ''
    Write-Host '  HOW TO INGEST INTO BLOODHOUND' -ForegroundColor Yellow
    Write-Host '    BHE / CE UI  :  Explore -> Upload Data -> select the .json file'
    Write-Host '    API upload   :  POST /api/v2/file-upload (multipart/form-data)'
    Write-Host ''
    Write-Host '  CYPHER QUERIES (Explore -> Cypher after ingest)' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  -- Show the collector node'
    Write-Host '     MATCH (c:SBHCollector) RETURN c LIMIT 5'
    Write-Host ''
    Write-Host '  -- All paths from collector across all edge types'
    Write-Host '     MATCH p=(c:SBHCollector)-[r:SBH_AccessDenied|SBH_CollectionOK|SBH_CollectorError|SBH_NonWindowsOS|SBH_NotActive|SBH_NumericError|SBH_PortNotOpen|SBH_RegistryError|SBH_RPCError|SBH_Timeout]->(comp) RETURN p'
    Write-Host ''
    Write-Host '  -- All computers with full successful collection (green house)'
    Write-Host '     MATCH p=(c:SBHCollector)-[]->(comp:SBHComputerOK) RETURN p'
    Write-Host ''
    Write-Host '  -- All computers connected to collector regardless of edge type'
    Write-Host '     MATCH p=(c:SBHCollector)-[]-() RETURN p'
    Write-Host ''
    Write-Host '  -- Computers where CollectionOK edge leads to a green node'
    Write-Host '     MATCH p=(c:SBHCollector)-[:SBH_CollectionOK]->(comp:SBHComputerOK) RETURN p'
    Write-Host ''
    Write-Host '  -- All computers connected via any edge to the collector'
    Write-Host '     MATCH p=(c:SBHCollector)-[]->(comp:SBHComputerOK) RETURN p'
    Write-Host ''
    Write-Host '  -- All failed computers (red house) as standalone nodes'
    Write-Host '     MATCH (c:SBHComputerFail) RETURN c'
    Write-Host ''
    Write-Host '  -- Access denied  -  collector account missing privileges'
    Write-Host '     MATCH p=(c:SBHCollector)-[:SBH_AccessDenied]->() RETURN p'
    Write-Host ''
    Write-Host '  -- RPC unavailable  -  TCP 135 blocked or RPC service down'
    Write-Host '     MATCH p=(c:SBHCollector)-[:SBH_RPCError]->() RETURN p'
    Write-Host ''
    Write-Host '  -- Collector exception  -  SharpHound threw an unhandled error'
    Write-Host '     MATCH p=(c:SBHCollector)-[:SBH_CollectorError]->() RETURN p'
    Write-Host ''
    Write-Host '  -- Remote registry denied  -  RRP service or ACL issue'
    Write-Host '     MATCH p=(c:SBHCollector)-[:SBH_RegistryError]->() RETURN p'
    Write-Host ''
    Write-Host '  -- Timeout  -  machine reachable but RPC/SMB call did not complete'
    Write-Host '     MATCH p=(c:SBHCollector)-[:SBH_Timeout]->() RETURN p'
    Write-Host ''
    Write-Host '  -- Port not open  -  TCP 445/135 blocked at host or network level'
    Write-Host '     MATCH p=(c:SBHCollector)-[:SBH_PortNotOpen]->() RETURN p'
    Write-Host ''
    Write-Host '  -- Non-Windows OS  -  SMB/RPC collection not applicable'
    Write-Host '     MATCH p=(c:SBHCollector)-[:SBH_NonWindowsOS]->() RETURN p'
    Write-Host ''
    Write-Host '  -- Not active  -  machine did not respond to availability check'
    Write-Host '     MATCH p=()-[:SBH_NotActive]->() RETURN p'
    Write-Host ''
    Write-Host '  -- Numeric error  -  raw Win32/NTSTATUS code, check Status in HTML report'
    Write-Host '     MATCH p=()-[:SBH_NumericError]->() RETURN p'
    Write-Host ''
    Write-Host '  -- Check if any uncategorised errors exist (errors if no edges present)'
    Write-Host '     MATCH ()-[r:SBH_Other]->() RETURN count(r)'
    Write-Host ''
    Write-Host '  -- Unknown computers  -  no IP and no SID recorded by SharpHound'
    Write-Host '     MATCH p=(c:SBHCollector)-[r]->(comp:SBHComputerUnknown) RETURN p'
    Write-Host ''

    # -- Optional icon upload -------------------------------------------------
    if ($UploadIcons) {
        $hasAuth = $BHEBearerToken -or ($BHETokenId -and $BHETokenKey)
        if (-not $BHEUrl -or -not $hasAuth) {
            Write-Host '  [!] -UploadIcons requires -BHEUrl plus one of:' -ForegroundColor Red
            Write-Host '        -BHEBearerToken  (paste JWT from BHE API Explorer -> Authorize)' -ForegroundColor Yellow
            Write-Host '        -BHETokenId + -BHETokenKey  (API key pair from Settings -> API Keys)' -ForegroundColor Yellow
            Write-Host '      Skipping icon upload.' -ForegroundColor Yellow
        }
        else {
            Write-Host '  +-------------------------------------------------------------+' -ForegroundColor Blue
            Write-Host '  |  St.Bernard-Hound - Uploading Custom Node Icons             |' -ForegroundColor Blue
            Write-Host '  +-------------------------------------------------------------+' -ForegroundColor Blue
            Write-Host ''
            Write-Host '  [*] Uploading icons to BHE...' -ForegroundColor Cyan
            Write-Host "      URL      : $BHEUrl/api/v2/custom-nodes"
            Write-Host "      TokenId  : $BHETokenId"
            Write-Host "      Kinds    : SBHCollector, SBHComputerOK, SBHComputerFail, SBHComputerUnknown"
            Write-Host ''

            # Prefer Bearer token; fall back to HMAC if TokenId/Key supplied
            $iconResult = Invoke-SBHIconUpload `
                -BHEUrl       $BHEUrl `
                -BearerToken  $BHEBearerToken `
                -TokenId      $BHETokenId `
                -TokenKey     $BHETokenKey

            if ($iconResult.Success) {
                Write-Host '  [OK] All icons registered successfully.' -ForegroundColor Green
                Write-Host ''
                Write-Host '  ICON MAPPING' -ForegroundColor Blue
                foreach ($r in $iconResult.Results) {
                    Write-Host ("    {0,-22} -> {1}" -f $r.Kind, $r.Action) -ForegroundColor Green
                }
                Write-Host ''
                Write-Host '    SBHCollector        ->  house-signal       (Blue       #3b82f6)'
                Write-Host '    SBHComputerOK       ->  house-circle-check (Green      #22c55e)'
                Write-Host '    SBHComputerFail     ->  house-circle-xmark (Red        #ef4444)'
                Write-Host '    SBHComputerUnknown  ->  skull-crossbones   (Dark slate #1e293b)'
                Write-Host ''
                Write-Host '  NOTE: Icons appear in BHE Explore after a page refresh.' -ForegroundColor Yellow
            }
            else {
                Write-Host '  [!] One or more icon kinds failed:' -ForegroundColor Red
                foreach ($r in $iconResult.Results) {
                    if (-not $r.Success) {
                        Write-Host ("    [FAIL] {0} : {1}" -f $r.Kind, $r.Error) -ForegroundColor Red
                    } else {
                        Write-Host ("    [ OK ] {0} : {1}" -f $r.Kind, $r.Action) -ForegroundColor Green
                    }
                }
                Write-Host '      Check -BHEUrl, -BHETokenId, -BHETokenKey and that the API key has admin rights.' -ForegroundColor Yellow
            }
            Write-Host ''
        }
    }
    else {
        Write-Host '  TIP: Re-run with -UploadIcons -BHEUrl <url> plus one of:' -ForegroundColor DarkGray
        Write-Host '         -BHEBearerToken <jwt>                       (from API Explorer -> Authorize)' -ForegroundColor DarkGray
        Write-Host '         -BHETokenId <id> -BHETokenKey <key>         (from Settings -> API Keys)' -ForegroundColor DarkGray
        Write-Host '       to automatically push the custom node icons to BHE.' -ForegroundColor DarkGray
        Write-Host '  TIP: Or use the BHE API Explorer directly (no script needed):' -ForegroundColor DarkGray
        Write-Host '       Menu -> API Explorer -> POST /api/v2/custom-nodes -> Try it out' -ForegroundColor DarkGray
        Write-Host ''
    }
}
