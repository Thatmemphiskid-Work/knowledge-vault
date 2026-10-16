# Benign interpreter execution and endpoint visibility

## Prerequisites

Approved Windows bench session, an owner-confirmed logging policy and access to the relevant source/collector logs. Process-creation events and command-line fields exist only if the corresponding auditing is configured; do not silently enable it.

## Launch a print-only child interpreter

```powershell
$start = Get-Date
$marker = 'ASSESSMENT-TRAINING-' + [guid]::NewGuid().ToString()
powershell.exe -NoProfile -NonInteractive -Command "Write-Output '$marker'"
$end = Get-Date
$start.ToUniversalTime().ToString('o')
$end.ToUniversalTime().ToString('o')
$marker
```

Runs a child process that only prints a unique marker. It does not change policy, download code, create a task or persist. Preserve marker/time without secrets.

## Read event metadata for the same window

```powershell
# Run in the same shell so $start and $end are defined. Security log access may be denied.
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$start.AddSeconds(-5); EndTime=$end.AddSeconds(5)} | Select-Object TimeCreated,Id,RecordId
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; StartTime=$start.AddSeconds(-5); EndTime=$end.AddSeconds(5)} | Select-Object TimeCreated,Id,RecordId
```

Metadata listing identifies candidate events, not the marker or parent relationship. In the authorized event viewer/collector inspect the matching executable, principal and parent; command-line/PowerShell detail depends on policy. Do not export unrelated secret-bearing message bodies.

## Operator and defender walkthrough

1. Run the print-only action once and record marker, principal and UTC window.
2. Locate the exact child-process event in source logs or the owner EDR console. Retain event ID, parent/child identity and available marker evidence; do not count every event in the window as this action.
3. Find the same event in the collector using asset, time and event ID. Record ingestion delay and completeness.
4. If an approved detection is expected, record query/rule version, alert time and routing. Ordinary PowerShell use may not warrant an alert.
5. Missing source event: investigate audit policy/access/retention. Source present but collector absent: investigate forwarding. Collector present but intended alert absent: investigate query/rule. Repeat after repair.

## Expected result

A traceable harmless process event, or a precisely located visibility gap. An observed process is not automatically an intrusion.

## What this does not prove

Validates benign execution visibility only; not injection, proxy execution, evasion or malicious script coverage.

[[Analyst Training]]