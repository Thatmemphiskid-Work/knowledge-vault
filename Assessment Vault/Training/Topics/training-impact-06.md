# Disk Wipe — Impact

## Understand the behavior

Low-level storage writes can make data and systems unavailable.

## Find / assess evidence

Review raw disk/destructive permissions and independent storage alerts.

## Prevent / remediate

Restrict destructive device access and protect continuity procedures.

## Safe exercise

Run a fictional disk-loss tabletop; no format or raw writes.

## Full procedure and result interpretation

## Impact workflow

Defensive analyst training and harmless validation, not an attack execution manual. Use owner-provisioned identities, inert files and approved lab endpoints. Never collect real credentials or private communications. No snapshot/reset dependency. Commands are reference text and are not executed by the app.

Assess resilience, permissions and response to damaging outcomes through read-only checks and tabletops, not destruction, ransomware, flooding or firmware changes.

### Read approved service availability metadata

```powershell
# Authorized host, read-only. Does not stop or restart anything.
Get-Service | Select-Object Name,Status,StartType
```

Service state is a point-in-time availability clue, not proof of root cause or recovery readiness. Recovery arrangements remain with the team's existing procedures.

### Verify

1. Identify critical services/data, authorized operators, dependency owners and approved incident contacts. Use existing recovery evidence rather than adding snapshot/reset procedures.
2. Review destructive-action permissions, independent availability telemetry and owner-provided recovery exercise records. No deletion, encryption, disk/firmware write, flooding or production control changes.
3. Run a hypothetical incident with synthetic events: identify impact, authorize containment, notify owners and demonstrate decisions. Mark tabletop results separately from executed recovery or live detection.

### Fix / prevent

1. Restrict destructive management actions, separate critical administration and preserve independent incident evidence.
2. Maintain supported systems, resource limits and owner-tested recovery/service continuity procedures; protect those procedures from unauthorized changes.

### Retest

1. Repeat the failed permission or tabletop decision check and confirm responsible staff can follow it.
2. Review evidence from existing owner-run continuity exercises; do not claim recovery was tested when only a tabletop was performed.

### Detection evidence

1. Correlate destructive API/change requests, integrity changes, resource saturation and service loss with independent telemetry. An outage is not automatically malicious, and an alert does not demonstrate recovery.

### Decision branches

- **If Evidence or authority is incomplete:** Mark not tested or a coverage gap; do not invent a result.
- **If Expected deny/control fails:** Record the exact boundary and escalate to its owner; do not expand access.
- **If Expected collection/alert/containment is missing:** Locate the failed milestone using Analyst Training outcome branches and repeat after repair.



## Runnable labs and limits

- [[training-lab-artifact-integrity|Create inert fixtures and detect a provenance/integrity change]]
- [[training-lab-pipeline-fixtures|Runnable offline telemetry-gap and policy-decision exercise]]

These are control-validation labs, not instructions to execute this harmful technique. Refer to each lab's stated limits.

[[training-group-impact]] · [[Analyst Training]]