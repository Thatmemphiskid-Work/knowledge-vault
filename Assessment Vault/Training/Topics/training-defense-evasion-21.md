# Network Boundary Flyby — Defense Evasion

## Understand the behavior

Unexpected protocol paths can violate intended boundary policy.

## Find / assess evidence

Review actual application/protocol identity and allowed flows, not just ports.

## Prevent / remediate

Use explicit egress/ingress policy and application-aware monitoring.

## Safe exercise

Analyze a synthetic unexpected protocol/port event; no bypass traffic.

## Full procedure and result interpretation

## Defense Evasion workflow

Defensive analyst training and harmless validation, not an attack execution manual. Use owner-provisioned identities, inert files and approved lab endpoints. Never collect real credentials or private communications. No snapshot/reset dependency. Commands are reference text and are not executed by the app.

Find visibility, integrity and control gaps using harmless fixtures and evidence review, without teaching concealment or disabling defenses.

### Read security posture and recent event metadata

```powershell
# Read-only Windows inspection; available features and privileges vary.
Get-NetFirewallProfile | Select-Object Name,Enabled
Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 20 | Select-Object TimeCreated,Id,ProviderName
```

Local state/events do not prove central visibility or enforcement. Access errors and missing events need diagnosis. Do not change firewall, logging or security-agent settings.

### Verify

1. Define the expected sensor and integrity source for each surface, including cloud regions, control-plane changes, endpoint processes and boot components.
2. Use a supplied inert event/trace to test a query, or perform a normal authorized action with a fixed marker. Record whether this validates source collection, ingestion, rule matching or response; replay is not live attack validation.
3. Compare approved security posture and trusted inventories with retained change history. Missing telemetry is a gap, not proof of successful stealth or absence of activity.

### Fix / prevent

1. Repair collection health, restrict changes to security controls and protect logs and trusted software paths.
2. Use vendor-supported application, identity, boot and endpoint controls. Validate signed code provenance; signatures alone do not guarantee benign behavior.

### Retest

1. Repeat the identical harmless event or posture review and verify source-to-collector completeness and intended alert routing.
2. Confirm legitimate actions still work. Record coverage limits instead of claiming all evasion variants are detected.

### Detection evidence

1. Distinguish source absence, forwarding loss, retention loss, query error and missed alert. Track security-control tampering with an independent telemetry source; never demonstrate by disabling defenses.

### Decision branches

- **If Evidence or authority is incomplete:** Mark not tested or a coverage gap; do not invent a result.
- **If Expected deny/control fails:** Record the exact boundary and escalate to its owner; do not expand access.
- **If Expected collection/alert/containment is missing:** Locate the failed milestone using Analyst Training outcome branches and repeat after repair.



## Runnable labs and limits

- [[training-lab-benign-execution|Benign interpreter execution and endpoint visibility]]
- [[training-lab-artifact-integrity|Create inert fixtures and detect a provenance/integrity change]]
- [[training-lab-cloud-container-read|Read-only cloud and container control-plane checks]]
- [[training-lab-pipeline-fixtures|Runnable offline telemetry-gap and policy-decision exercise]]

These are control-validation labs, not instructions to execute this harmful technique. Refer to each lab's stated limits.

[[training-group-defense-evasion]] · [[Analyst Training]]