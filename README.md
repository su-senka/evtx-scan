# EVTX Scan Scripts

Lightweight PowerShell utilities to scan .evtx files for specific events with practical filters. One version targets Windows PowerShell 5.1 (single-threaded), and another targets PowerShell 7+ (parallel processing).

## Scripts
- ScanEvtx.ps1 — PS 5.1 single-threaded scan with streamed reads and XML sanitization.
- ScanEvtxParallel.ps1 — PS 7+ parallel scan with per-file merges.

## Requirements
- Windows with access to .evtx files (uses Get-WinEvent).
- PowerShell 5.1 for ScanEvtx.ps1.
- PowerShell 7+ for ScanEvtxParallel.ps1.

## Common parameters
- -Root (string, required): Folder containing .evtx files (recurses).
- -EventId (int, required): Event ID to filter (e.g., 4663).
- Name filter (choose one):
	- -Prefix (string): Case-insensitive starts-with for ObjectName.
	- -Contains (string): Case-insensitive substring for ObjectName.
- -StartTime/-EndTime (datetime, optional): Time window filters.
- -ProviderName (string, optional): Filter by provider within each EVTX (e.g., "Microsoft-Windows-Security-Auditing").
- -IncludePattern/-ExcludePattern (string[], optional): Case-insensitive regex filters on the formatted message; include must match at least one; exclude drops if matches any.
- -OutputCsv (string): Output CSV path; default .\evtx_matches.csv.
- -PassThru (switch): Also emit matched rows to the pipeline.
- -NoCsv (switch): Do not write CSV (use with -PassThru to only pipe results).
- -LogFile (string): Optional path for a text log with status and errors.

Rows contain: Folder, Evtx, Logged, AccountName, ObjectName, Message.

## Examples

### Single-thread (PS 5.1)

Prefix match with logging, time window, and message filters (writes CSV and to pipeline):

```powershell
ScanEvtx.ps1 -Root 'C:\Logs' -EventId 4663 -Prefix 'C:\Sensitive' -ProviderName 'Microsoft-Windows-Security-Auditing' -StartTime (Get-Date).AddDays(-7) -IncludePattern 'DELETE|WRITE' -ExcludePattern 'System Volume Information' -OutputCsv '.\matches.csv' -LogFile '.\scan.log' -PassThru
```

Substring match, pipe-only (no CSV):

```powershell
ScanEvtx.ps1 -Root 'C:\Logs' -EventId 4663 -Contains '\\Reports\\FY25' -NoCsv -PassThru | Select-Object -First 10
```

### Parallel (PS 7+)

Parallel run with throttle and temp directory using prefix filter:

```powershell
ScanEvtxParallel.ps1 -Root 'C:\Logs' -EventId 4663 -Prefix 'C:\Sensitive' -StartTime (Get-Date).AddDays(-3) -ThrottleLimit 8 -TempDir 'C:\Temp\evtx_parts' -OutputCsv '.\matches.csv' -LogFile '.\scan_parallel.log'
```

Parallel, substring match pipe-only:

```powershell
ScanEvtxParallel.ps1 -Root 'C:\Logs' -EventId 4663 -Contains '\\.xlsx$' -NoCsv -PassThru | Export-Csv '.\pipe_only.csv' -NoTypeInformation -Encoding UTF8
```

## Notes
- These scripts sanitize XML to avoid crashes on illegal characters in ObjectName.
- ProviderName, StartTime, EndTime are applied via the Get-WinEvent filter hashtable for speed.
- Message filters use the formatted description when available, otherwise sanitized XML text.

## License
Pick a permissive license (MIT/Apache-2.0) before publishing.
