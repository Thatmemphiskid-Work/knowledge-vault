# Create inert fixtures and detect a provenance/integrity change

## Prerequisites

PowerShell and permission to create a new directory in the user's temporary area. Only the newly generated directory is written. Fixture paths are not service/startup paths. Preserve the files until review, then remove only that named disposable directory through normal file management.

## Generate and compare known harmless content

```powershell
$lab = Join-Path $env:TEMP ('assessment-training-' + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $lab -ErrorAction Stop | Out-Null
$good = Join-Path $lab 'approved.txt'
$changed = Join-Path $lab 'changed.txt'
Set-Content -LiteralPath $good -Value 'TRAINING ONLY: approved amount=10'
Set-Content -LiteralPath $changed -Value 'TRAINING ONLY: changed amount=11'
Get-FileHash -LiteralPath $good,$changed -Algorithm SHA256 | Select-Object Path,Hash
Get-Acl -LiteralPath $lab | Format-List Owner,AccessToString
$lab
```

Two deliberately different inert text files should have different hashes. This demonstrates content identity, not authenticity: the baseline must itself be trusted. ACL output is not a complete effective-access calculation.

## Operator and defender walkthrough

1. Run once, record the generated directory and designate approved.txt as the instructor baseline.
2. Compare hashes and contents in that directory only. Explain why familiar filenames or signatures alone cannot prove approval.
3. Defender: correlate any available file-create/integrity telemetry with this directory and window. File auditing is policy-dependent; lack of an alert is not evidence of malicious stealth.
4. For supply-chain/persistence/escalation topics, apply the same reasoning to provided manifests/ACL exports, not actual service binaries. Identify who can publish/write and which trusted consumer uses the artifact.
5. For data manipulation, independently reconcile the fictional amount values. This is not ransomware, disk wiping or compromise of a live artifact.

## Expected result

Different content yields different hashes; permission and publisher evidence must be assessed separately. A trusted hash baseline plus provenance can identify an unexpected change.

## What this does not prove

Only instructor-created text fixtures are written. No live application modification, persistence installation, privilege escalation or destructive testing.

[[Analyst Training]]