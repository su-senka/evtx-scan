#requires -Version 7.0
<#
.SYNOPSIS
  Parallel EVTX scan (PS 7+): streamed reads, XML sanitization, UTF-8 CSV merge.

.PARAMETER Root
  Folder containing .evtx files (recurses).

.PARAMETER EventId
  Event ID to filter (e.g., 4663).

.PARAMETER Prefix
  Case-insensitive "starts-with" filter for ObjectName. Mutually exclusive with -Contains.

.PARAMETER Contains
  Case-insensitive "substring" filter for ObjectName. Mutually exclusive with -Prefix.

.PARAMETER StartTime
  Optional: only events on/after this timestamp.

.PARAMETER EndTime
  Optional: only events on/before this timestamp.

.PARAMETER ProviderName
  Optional: only events from this provider within each EVTX file.

.PARAMETER IncludePattern
  Optional regex(es). Event message must match at least one (case-insensitive).

.PARAMETER ExcludePattern
  Optional regex(es). If event message matches any, it's excluded.

.PARAMETER OutputCsv
  Final merged CSV path (UTF-8). Default: .\evtx_matches.csv

.PARAMETER ThrottleLimit
  Max parallel workers. Default: logical CPU count.

.PARAMETER TempDir
  Optional temp folder for per-file CSVs; created if missing.

.PARAMETER PassThru
  Also emit matched rows to the pipeline (in addition to CSV unless -NoCsv).

.PARAMETER NoCsv
  Do not write CSV; only emit to pipeline if -PassThru is set.

.PARAMETER LogFile
  Optional path to a text file where the script will log status and errors.
#>

[CmdletBinding(DefaultParameterSetName='PrefixSet')]
param(
  [Parameter(Mandatory)][string]$Root,
  [Parameter(Mandatory)][int]$EventId,
  [Parameter(ParameterSetName='PrefixSet', Mandatory=$true)][string]$Prefix,
  [Parameter(ParameterSetName='ContainsSet', Mandatory=$true)][string]$Contains,
  [datetime]$StartTime,
  [datetime]$EndTime,
  [string]$ProviderName,
  [string[]]$IncludePattern,
  [string[]]$ExcludePattern,
  [string]$OutputCsv = ".\evtx_matches.csv",
  [ValidateRange(1,256)][int]$ThrottleLimit = [Environment]::ProcessorCount,
  [string]$TempDir,
  [switch]$PassThru,
  [switch]$NoCsv,
  [string]$LogFile
)

# --- Validation & setup ---
if (-not (Test-Path -LiteralPath $Root)) { throw "Root not found: $Root" }
$files = Get-ChildItem -LiteralPath $Root -Recurse -File -Filter *.evtx
if ($files.Count -eq 0) { throw "No .evtx files under: $Root" }

if (-not $NoCsv) { if (Test-Path -LiteralPath $OutputCsv) { Remove-Item -LiteralPath $OutputCsv -Force } }
if (-not $TempDir) { $TempDir = Join-Path $env:TEMP ("evtx_scan_" + [guid]::NewGuid().ToString("N")) }
if (-not (Test-Path -LiteralPath $TempDir)) { New-Item -ItemType Directory -Path $TempDir | Out-Null }

Write-Host ("Found {0} .evtx files | ThrottleLimit={1}" -f $files.Count, $ThrottleLimit)
Write-Host "Temp per-file CSVs: $TempDir"
$sw = [System.Diagnostics.Stopwatch]::StartNew()

# Decide which name filter to apply
$usePrefix = $PSBoundParameters.ContainsKey('Prefix')
$useContains = $PSBoundParameters.ContainsKey('Contains')

# Logging setup (shared mutex name derived from log path)
$logFile = $LogFile
$logMutexName = if ($logFile) { "Global:EVTX_SCAN_LOG_" + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($logFile))).TrimEnd('=') } else { $null }
if ($logFile) {
  try {
    if (Test-Path -LiteralPath $logFile) { Remove-Item -LiteralPath $logFile -Force }
    New-Item -ItemType File -Path $logFile -Force | Out-Null
  } catch { }
}

# --- Parallel processing ---
$files | ForEach-Object -Parallel {
  # capture outer vars
  $eventId = $using:EventId
  $prefix  = $using:Prefix
  $contains = $using:Contains
  $tmpDir  = $using:TempDir
  $provider = $using:ProviderName
  $startT = $using:StartTime
  $endT   = $using:EndTime
  $incPat = $using:IncludePattern
  $excPat = $using:ExcludePattern
  $emit   = $using:PassThru
  $noCsv  = $using:NoCsv
  $usePrefix = $using:usePrefix
  $useContains = $using:useContains
  $logFile = $using:logFile
  $logMutexName = $using:logMutexName

  function Write-Log([string]$Message) {
    if (-not $logFile) { return }
    $ts = Get-Date -Format o
    $line = "[$ts] $Message"
    if ($logMutexName) {
      $created = $false
      $mtx = New-Object System.Threading.Mutex($true, $logMutexName, [ref]$created)
      try {
        [void]$mtx.WaitOne()
        Add-Content -LiteralPath $logFile -Value $line
      } catch {
      } finally {
        $mtx.ReleaseMutex() | Out-Null
        $mtx.Dispose()
      }
    } else {
      Add-Content -LiteralPath $logFile -Value $line
    }
  }

  # helpers
  function ConvertTo-XmlSafe([string]$x) {
    [regex]::Replace($x,'[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]','')
  }
  function Get-EventField(
    [Parameter(Mandatory)][System.Diagnostics.Eventing.Reader.EventRecord]$Event,
    [Parameter(Mandatory)][string]$Name
  ) {
    try {
      $xml = [xml](ConvertTo-XmlSafe ($Event.ToXml()))
      $v = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq $Name } | Select-Object -First 1).'#text'
      if ($v) { return $v }
    } catch { }
    $p = $Event.Properties
    switch ($Name) {
      'SubjectUserName' { if ($p.Count -gt 1) { return $p[1].Value } }
      'TargetUserName'  { if ($p.Count -gt 1) { return $p[1].Value } }
      'ObjectName'      { if ($p.Count -gt 6) { return $p[6].Value } }
    }
  }

  function Get-EventMessage([System.Diagnostics.Eventing.Reader.EventRecord]$Event) {
    try { $m = $Event.FormatDescription(); if ($m) { return $m } } catch {}
    try { return (ConvertTo-XmlSafe ($Event.ToXml())) } catch {}
    return ($Event.Properties | ForEach-Object { $_.Value } | Where-Object { $_ } | ForEach-Object { $_.ToString() } -join ' ')
  }

  $evtx = $_
  $rows = New-Object System.Collections.Generic.List[object]
  $processed = 0; $matched = 0

  try {
    Write-Log "START file: $($evtx.FullName)"
    $fh = @{ Path = $evtx.FullName; Id = $eventId }
    if ($provider) { $fh['ProviderName'] = $provider }
    if ($startT) { $fh['StartTime'] = $startT }
    if ($endT)   { $fh['EndTime'] = $endT }

    Get-WinEvent -FilterHashtable $fh -ErrorAction Stop |
    ForEach-Object {
      $processed++
      $obj = Get-EventField -Event $_ -Name 'ObjectName'
      if (-not $obj) { return }
  if ( ($usePrefix -and $obj.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) -or
       ($useContains -and $obj.Contains($contains, [System.StringComparison]::OrdinalIgnoreCase)) ) {
        $msg = $null
        $needsMsg = ($incPat -and $incPat.Count -gt 0) -or ($excPat -and $excPat.Count -gt 0)
        if ($needsMsg) { $msg = Get-EventMessage $_ }
        if ($incPat -and $incPat.Count -gt 0) {
          $hit = $false
          foreach ($p in $incPat) { if ([string]::IsNullOrEmpty($p)) { continue }; if ($msg -match $p) { $hit=$true; break } }
          if (-not $hit) { return }
        }
        if ($excPat -and $excPat.Count -gt 0) {
          foreach ($p in $excPat) { if ([string]::IsNullOrEmpty($p)) { continue }; if ($msg -match $p) { return } }
        }
        $acct = (Get-EventField -Event $_ -Name 'SubjectUserName')
        if (-not $acct) { $acct = Get-EventField -Event $_ -Name 'TargetUserName' }
        $rows.Add([pscustomobject]@{
          Folder      = $evtx.DirectoryName
          Evtx        = $evtx.Name
          Logged      = $_.TimeCreated
          AccountName = $acct
          ObjectName  = $obj
          Message     = $msg
        }) | Out-Null
        if ($emit) { $rows[$rows.Count-1] }
        $matched++
      }
    }
  } catch {
  $emsg = "Failed: $($evtx.FullName) :: $($_.Exception.Message)"
  Write-Warning $emsg
  Write-Log $emsg
  }

  if ($rows.Count -gt 0 -and -not $noCsv) {
    $out = Join-Path $tmpDir ($evtx.BaseName + ".csv")
    try {
      $rows | Sort-Object Logged | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $out
    } catch {
      $emsg = "CSV write failed for $($evtx.Name): $($_.Exception.Message)"
      Write-Warning $emsg
      Write-Log $emsg
    }
  }

  Write-Host ("DONE {0} | Processed:{1} Matched:{2}" -f $evtx.Name, $processed, $matched)
  Write-Log  ("DONE {0} | Processed:{1} Matched:{2}" -f $evtx.FullName, $processed, $matched)
} -ThrottleLimit $ThrottleLimit

# --- Merge step ---
if (-not $NoCsv) {
  $parts = Get-ChildItem -LiteralPath $TempDir -Filter *.csv | Sort-Object Name
  if ($parts.Count -eq 0) {
    Write-Warning "No matches found. No CSV produced."
    $sw.Stop()
    Write-Host ("Elapsed: {0}" -f $sw.Elapsed)
  if ($logFile) { Add-Content -LiteralPath $logFile -Value ("[{0}] No matches found. No CSV produced." -f (Get-Date -Format o)) }
    return
  }

  $first = $true
  foreach ($pf in $parts) {
    if ($first) {
      Import-Csv -LiteralPath $pf.FullName | Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath $OutputCsv
      $first = $false
    } else {
      Import-Csv -LiteralPath $pf.FullName | Export-Csv -NoTypeInformation -Encoding UTF8 -Append -LiteralPath $OutputCsv
    }
  }

  $sw.Stop()
  Write-Host "Merged $($parts.Count) partial CSVs into: $OutputCsv"
  Write-Host ("Elapsed: {0}" -f $sw.Elapsed)
  Write-Host "Temp kept at: $TempDir (delete when done)"
  if ($logFile) {
    Add-Content -LiteralPath $logFile -Value ("[{0}] Merged {1} partial CSVs into: {2}" -f (Get-Date -Format o), $parts.Count, $OutputCsv)
    Add-Content -LiteralPath $logFile -Value ("[{0}] Elapsed: {1}" -f (Get-Date -Format o), $sw.Elapsed)
    Add-Content -LiteralPath $logFile -Value ("[{0}] Temp kept at: {1}" -f (Get-Date -Format o), $TempDir)
  }
} else {
  $sw.Stop()
  Write-Host ("Elapsed: {0}" -f $sw.Elapsed)
  Write-Host "NoCsv set: skipped merge step. Temp kept at: $TempDir"
  if ($logFile) {
    Add-Content -LiteralPath $logFile -Value ("[{0}] Elapsed: {1}" -f (Get-Date -Format o), $sw.Elapsed)
    Add-Content -LiteralPath $logFile -Value ("[{0}] NoCsv set: skipped merge step. Temp kept at: {1}" -f (Get-Date -Format o), $TempDir)
  }
}

