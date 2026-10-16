# Runnable offline telemetry-gap and policy-decision exercise

## Prerequisites

PowerShell, the bundled assessment/training_fixtures.json file and no target connectivity. Run from the assessment folder. These are fictional records, not Windows events or a live SIEM adapter; no fixture is automatically submitted to any collector.

## Classify source, ingestion, alert and containment gaps

```powershell
$events = Get-Content -LiteralPath '.\training_fixtures.json' -Raw | ConvertFrom-Json
$events | ForEach-Object {
  $verdict = if (-not $_.sourcePresent) { 'SOURCE GAP' }
  elseif (-not $_.collected) { 'INGESTION GAP' }
  elseif ($_.expectedAlert -and -not $_.alerted) { 'ALERT GAP' }
  elseif ($_.expectedContainment -and -not $_.contained) { 'CONTAINMENT GAP' }
  elseif (-not $_.expectedAlert -and $_.alerted) { 'UNEXPECTED ALERT' }
  else { 'EXPECTED OBSERVATION' }
  [pscustomobject]@{Case=$_.case; Scenario=$_.scenario; Verdict=$verdict}
}
```

Cases A-H independently exercise different outcomes. This simple priority classifier finds the first failed milestone; inspect all fields for multiple gaps. It does not simulate malware or validate production detection coverage.

## Compare per-event and aggregate policy decisions on fictional bytes

```powershell
# Offline arithmetic only; creates no connections or data transfers.
$events = Get-Content -LiteralPath '.\training_fixtures.json' -Raw | ConvertFrom-Json
$case = $events | Where-Object case -eq 'H'
$total = ($case.transferBytes | Measure-Object -Sum).Sum
$largest = ($case.transferBytes | Measure-Object -Maximum).Maximum
[pscustomobject]@{TotalBytes=$total; LargestEventBytes=$largest; Threshold=$case.policyThresholdBytes; AggregateExceeds=($total -gt $case.policyThresholdBytes); SingleEventExceeds=($largest -gt $case.policyThresholdBytes)}
```

Independent expected result: total 2400, largest event 600, threshold 2000, AggregateExceeds=True, SingleEventExceeds=False. A rule using only individual event size would miss this fictional aggregate policy violation. This is a defender query lesson, not a transfer tool.

## Operator and defender walkthrough

1. Run the classifier and compare with the independent answer key: A=EXPECTED OBSERVATION, B=SOURCE GAP, C=INGESTION GAP, D=ALERT GAP, E=CONTAINMENT GAP, F=EXPECTED OBSERVATION, G=UNEXPECTED ALERT, H=ALERT GAP.
2. Explain why F is healthy without an alert: collection was expected, alerting was not. Explain why E is incomplete despite an alert: expected containment did not occur.
3. Inspect H's fictional transfer metadata: four 600-byte transfers total 2400 bytes versus a fictional 2000-byte policy threshold. This tests aggregation logic in a classroom, not how to evade a detector.
4. Defender: translate the relevant fields into your organization's isolated test-query schema with the owner, and test known expected outcomes. Fixture replay can validate parsing/rule logic but not live sensor capture.
5. Record failed milestone, owner, correction and repeat result. Never generate the real harmful behavior to obtain a matching event.

## Expected result

Eight deterministic verdicts match the answer key; users distinguish source, forwarding, rule and response defects from normal no-alert behavior.

## What this does not prove

Entirely offline synthetic exercise. Cannot prove resistance to credential theft, stealth, C2, data theft, ransomware or destructive attacks.

[[Analyst Training]]