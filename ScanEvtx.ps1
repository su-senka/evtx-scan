#requires -Version 5.1
<#
.SYNOPSIS
  Single-threaded (PS 5.1) EVTX scan with streamed reads, XML sanitization, and CSV output.

.PARAMETER Root
  Folder containing .evtx files (recurses).

.PARAMETER EventId
  Event ID to filter (e.g., 4663).

.PARAMETER Prefix
    Case-insensitive starts-with filter for ObjectName. Mutually exclusive with -Contains.

.PARAMETER Contains
    Case-insensitive substring filter for ObjectName. Mutually exclusive with -Prefix.

.PARAMETER StartTime
    Optional filter: only events on/after this timestamp.

.PARAMETER EndTime
    Optional filter: only events on/before this timestamp.

.PARAMETER ProviderName
    Optional filter: only events from this provider within the EVTX.

.PARAMETER IncludePattern
    Optional case-insensitive regex(es). Event message must match at least one.

.PARAMETER ExcludePattern
    Optional case-insensitive regex(es). If the message matches any, the event is skipped.

.PARAMETER OutputCsv
  Path to output CSV (default: .\evtx_matches.csv)

.PARAMETER LogFile
    Optional path to a text file where the script will log status and errors.

.PARAMETER PassThru
    Also emit matched rows to the pipeline (in addition to CSV, unless -NoCsv).

.PARAMETER NoCsv
    Do not write CSV; only emit to pipeline if -PassThru is set.

.NOTES
  - Progress is per-file + overall.
  - XML sanitizer avoids crashes on illegal characters (e.g., ADS junk) in ObjectName.
  - Positional fallback in Get-EventField matches the 4663 schema.
#>

[CmdletBinding(DefaultParameterSetName='PrefixSet')]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Root,

    [Parameter(Mandatory=$true)]
    [ValidateRange(1,2147483647)]
    [int]$EventId,

    [Parameter(ParameterSetName='PrefixSet', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Prefix,

    [Parameter(ParameterSetName='ContainsSet', Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Contains,

        [datetime]$StartTime,
        [datetime]$EndTime,
        [string]$ProviderName,
        [string[]]$IncludePattern,
        [string[]]$ExcludePattern,

    [string]$OutputCsv = ".\evtx_matches.csv",
    [string]$LogFile,
        [switch]$PassThru,
        [switch]$NoCsv
)

# --- Validation ---
if (-not (Test-Path -LiteralPath $Root)) {
    throw "Root folder not found: $Root"
}
$files = Get-ChildItem -LiteralPath $Root -Recurse -File -Filter *.evtx
if ($files.Count -eq 0) {
    throw "No .evtx files found under: $Root"
}
if (-not $NoCsv) {
    if (Test-Path -LiteralPath $OutputCsv) {
        Remove-Item -LiteralPath $OutputCsv -Force
    }
}

# --- Logging ---
function Write-Log {
    param([Parameter(Mandatory)][string]$Message)
    if (-not $LogFile) { return }
    try {
        $ts = Get-Date -Format o
        Add-Content -LiteralPath $LogFile -Value "[$ts] $Message" -Encoding UTF8
    } catch {
        Write-Warning ("Log write failed for '{0}': {1}" -f $LogFile, $_.Exception.Message)
    }
}
if ($LogFile) {
    try {
        $logDir = Split-Path -Parent -Path $LogFile
        if ($logDir -and -not (Test-Path -LiteralPath $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        if (Test-Path -LiteralPath $LogFile) { Remove-Item -LiteralPath $LogFile -Force }
        New-Item -ItemType File -Path $LogFile -Force | Out-Null
        Write-Log "ScanEvtx start | Root='$Root' | Files=$($files.Count) | EventId=$EventId | ParamSet='$($PSCmdlet.ParameterSetName)'"
    } catch {
        Write-Warning ("Could not initialize log file '{0}': {1}" -f $LogFile, $_.Exception.Message)
    }
}

# --- Helpers: XML sanitization + safe field extraction ---
function ConvertTo-XmlSafe {
    param([Parameter(Mandatory)][string]$XmlText)
    # Remove characters illegal in XML 1.0 (preserve tab, LF, CR)
    [regex]::Replace($XmlText, '[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]', '')
}

function Get-EventField {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Diagnostics.Eventing.Reader.EventRecord]$Event,
        [Parameter(Mandatory)][string]$Name
    )
    # 1) Try sanitized XML (works for any Event ID)
    try {
        $xmlText = ConvertTo-XmlSafe -XmlText ($Event.ToXml())
        $xml = [xml]$xmlText
        $val = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1).'#text'
        if ($val) { return $val }
    } catch { }

    # 2) Fallback to positional Properties (layout for 4663)
    # 0 SubjectUserSid
    # 1 SubjectUserName
    # 2 SubjectDomainName
    # 3 SubjectLogonId
    # 4 ObjectServer
    # 5 ObjectType
    # 6 ObjectName
    # 7 HandleId
    # 8 AccessList
    # 9 AccessMask
    # 10 ProcessId
    # 11 ProcessName
    # 12 ResourceAttributes
    $p = $Event.Properties
    switch ($Name) {
        'SubjectUserName' { if ($p.Count -gt 1) { return $p[1].Value } }
        'TargetUserName'  { if ($p.Count -gt 1) { return $p[1].Value } }
        'ObjectName'      { if ($p.Count -gt 6) { return $p[6].Value } }
        default           { return $null }
    }
}

function Get-EventMessage {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Diagnostics.Eventing.Reader.EventRecord]$Event)
    try {
        $msg = $Event.FormatDescription()
        if ([string]::IsNullOrWhiteSpace($msg)) {
            throw 'No message'
        }
        return $msg
    } catch {
        try {
            # Fallback to sanitized XML text
            return (ConvertTo-XmlSafe -XmlText ($Event.ToXml()))
        } catch {
            # Last resort: join property values
            return ($Event.Properties | ForEach-Object { $_.Value } | Where-Object { $_ } | ForEach-Object { $_.ToString() } -join ' ')
        }
    }
}

# --- CSV header control ---
$csvHeaderWritten = $false

# --- Overall progress ---
$totalFiles = $files.Count
$fileIndex  = 0

# Decide which name filter to apply
$usePrefix = $PSBoundParameters.ContainsKey('Prefix')
$useContains = $PSBoundParameters.ContainsKey('Contains')

foreach ($evtx in $files) {
    $fileIndex++
    $processed = 0
    $matched   = 0

    Write-Progress -Activity "Scanning EVTX files" `
        -Status "File $fileIndex of $totalFiles : $($evtx.Name)" `
        -PercentComplete (($fileIndex / $totalFiles) * 100)
    Write-Log "START file: $($evtx.FullName)"

    try {
        # Build filter hashtable dynamically
        $fh = @{ Path = $evtx.FullName; Id = $EventId }
        if ($PSBoundParameters.ContainsKey('ProviderName') -and $ProviderName) { $fh['ProviderName'] = $ProviderName }
        if ($PSBoundParameters.ContainsKey('StartTime') -and $StartTime) { $fh['StartTime'] = $StartTime }
        if ($PSBoundParameters.ContainsKey('EndTime') -and $EndTime) { $fh['EndTime'] = $EndTime }

        Get-WinEvent -FilterHashtable $fh -ErrorAction Stop |
        ForEach-Object {
            $processed++

            if (($processed % 10000) -eq 0) {
                Write-Progress -Activity "Scanning EVTX files" `
                    -Status "File $fileIndex/$totalFiles : $($evtx.Name) | Processed: $processed  Matched: $matched" `
                    -PercentComplete (($fileIndex / $totalFiles) * 100)
            }

            $obj = Get-EventField -Event $_ -Name 'ObjectName'
            if (-not $obj) { return }

          if ( ($usePrefix -and $obj.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) -or
              ($useContains -and $obj.IndexOf($Contains, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) ) {
                # Message include/exclude filtering (only when patterns provided)
                $msg = $null
                $needsMsg = ($IncludePattern -and $IncludePattern.Count -gt 0) -or ($ExcludePattern -and $ExcludePattern.Count -gt 0)
                if ($needsMsg) { $msg = Get-EventMessage -Event $_ }

                if ($IncludePattern -and $IncludePattern.Count -gt 0) {
                    $incHit = $false
                    foreach ($pat in $IncludePattern) {
                        if ([string]::IsNullOrEmpty($pat)) { continue }
                        if ($msg -match $pat) { $incHit = $true; break }
                    }
                    if (-not $incHit) { return }
                }

                if ($ExcludePattern -and $ExcludePattern.Count -gt 0) {
                    foreach ($pat in $ExcludePattern) {
                        if ([string]::IsNullOrEmpty($pat)) { continue }
                        if ($msg -match $pat) { return }
                    }
                }

                $acct = Get-EventField -Event $_ -Name 'SubjectUserName'
                if (-not $acct) { $acct = Get-EventField -Event $_ -Name 'TargetUserName' }

                $row = [pscustomobject]@{
                    Folder      = $evtx.DirectoryName
                    Evtx        = $evtx.Name
                    Logged      = $_.TimeCreated
                    AccountName = $acct
                    ObjectName  = $obj
                    Message     = $msg
                }

                if ($PassThru) { $row }
                if (-not $NoCsv) {
                    if (-not $csvHeaderWritten) {
                        $row | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $OutputCsv
                        $csvHeaderWritten = $true
                    } else {
                        $row | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -LiteralPath $OutputCsv
                    }
                }

                $matched++
            }
        }
    } catch {
        $msg = "Failed to read '$($evtx.FullName)': $($_.Exception.Message)"
        Write-Warning $msg
        Write-Log $msg
        continue
    }

    Write-Host ("DONE {0} | Processed: {1}  Matched: {2}" -f $evtx.Name, $processed, $matched)
    Write-Log  ("DONE {0} | Processed: {1}  Matched: {2}" -f $evtx.FullName, $processed, $matched)
}

if (-not $NoCsv) {
    if (-not (Test-Path -LiteralPath $OutputCsv)) {
    Write-Warning "No matches found. No CSV produced."
    Write-Log    "No matches found. No CSV produced."
    } else {
    Write-Host "All done. Output: $OutputCsv"
    Write-Log  "All done. Output: $OutputCsv"
    }
}
