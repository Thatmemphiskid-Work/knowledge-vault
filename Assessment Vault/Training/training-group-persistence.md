# Persistence training

Review mechanisms that survive sessions or restarts without installing persistent access or modifying firmware.

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



## Hands-on labs

- [[training-lab-artifact-integrity|Create inert fixtures and detect a provenance/integrity change]]
- [[training-lab-pipeline-fixtures|Runnable offline telemetry-gap and policy-decision exercise]]

## Topics

- [[training-persistence-01|Account Manipulation]]
- [[training-persistence-02|BITS Jobs]]
- [[training-persistence-03|Boot or Logon Autostart Execution]]
- [[training-persistence-04|Boot or Logon Initialization Scripts]]
- [[training-persistence-05|Browser Extensions]]
- [[training-persistence-06|Compromise Client Software Binary]]
- [[training-persistence-07|Create Account]]
- [[training-persistence-08|Create or Modify System Process]]
- [[training-persistence-09|Event Triggered Execution]]
- [[training-persistence-10|External Remote Services]]
- [[training-persistence-11|Hijack Execution Flow]]
- [[training-persistence-12|Hypervisor]]
- [[training-persistence-13|Office Application Startup]]
- [[training-persistence-14|Pre-OS Boot]]
- [[training-persistence-15|Scheduled Task/Job]]
- [[training-persistence-16|Server Software Component]]
- [[training-persistence-17|Traffic Signaling]]
- [[training-persistence-18|Valid Accounts]]

[[Analyst Training]]