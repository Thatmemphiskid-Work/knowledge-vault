# Office Application Startup — Persistence

## Understand the behavior

Templates and add-ins may activate on application launch.

## Find / assess evidence

Review approved add-in/template paths, signatures and policy.

## Prevent / remediate

Restrict trusted locations and unsigned or unnecessary add-ins.

## Safe exercise

Inspect an exported add-in inventory; no macro or template injection.

## Full procedure and result interpretation

## Persistence workflow

Defensive analyst training and harmless validation, not an attack execution manual. Use owner-provisioned identities, inert files and approved lab endpoints. Never collect real credentials or private communications. No snapshot/reset dependency. Commands are reference text and are not executed by the app.

Review mechanisms that survive sessions or restarts without installing persistent access or modifying firmware.

### Read Windows startup and scheduler metadata

```powershell
# Authorized host; these commands enumerate, not create, persistence.
Get-CimInstance Win32_StartupCommand | Select-Object Name,Location,User
Get-ScheduledTask | Select-Object TaskName,TaskPath,State
```

These views are incomplete and may need additional permissions. Review actions, principals and trusted artifacts in approved owner exports; empty results do not rule out persistence.

### Verify

1. Compare account/session grants, startup, tasks, services, extensions and server components against an owner-approved baseline.
2. For unexpected items, record creator, action/target, effective permissions, artifact provenance and triggering conditions without activating them.
3. Verify legitimacy with the owner and retained audit history. For boot, hypervisor or firmware concerns use specialist supplier evidence; OS inventory alone cannot exclude them.

### Fix / prevent

1. After preserving required evidence, remove unauthorized grants/components through approved response procedures and rotate or revoke affected access.
2. Protect startup/service/task writers and trusted deployment paths; patch supported software and use vendor-supported boot integrity controls.

### Retest

1. Re-enumerate the same mechanism and verify baseline and effective permissions agree.
2. Confirm normal restart/session behavior using existing lab procedures; do not install a backdoor to prove removal.

### Detection evidence

1. Track creation and modification events for long-lived access and activation surfaces, including cloud grants. A baseline difference is an investigation lead, not automatic malware attribution.

### Decision branches

- **If Evidence or authority is incomplete:** Mark not tested or a coverage gap; do not invent a result.
- **If Expected deny/control fails:** Record the exact boundary and escalate to its owner; do not expand access.
- **If Expected collection/alert/containment is missing:** Locate the failed milestone using Analyst Training outcome branches and repeat after repair.



## Runnable labs and limits

- [[training-lab-artifact-integrity|Create inert fixtures and detect a provenance/integrity change]]
- [[training-lab-pipeline-fixtures|Runnable offline telemetry-gap and policy-decision exercise]]

These are control-validation labs, not instructions to execute this harmful technique. Refer to each lab's stated limits.

[[training-group-persistence]] · [[Analyst Training]]