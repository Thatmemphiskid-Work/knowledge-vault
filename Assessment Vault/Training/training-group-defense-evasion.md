# Defense Evasion training

Find visibility, integrity and control gaps using harmless fixtures and evidence review, without teaching concealment or disabling defenses.

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



## Hands-on labs

- [[training-lab-benign-execution|Benign interpreter execution and endpoint visibility]]
- [[training-lab-artifact-integrity|Create inert fixtures and detect a provenance/integrity change]]
- [[training-lab-cloud-container-read|Read-only cloud and container control-plane checks]]
- [[training-lab-pipeline-fixtures|Runnable offline telemetry-gap and policy-decision exercise]]

## Topics

- [[training-defense-evasion-01|Abuse Elevation Control Mechanism]]
- [[training-defense-evasion-02|Access Token Manipulation]]
- [[training-defense-evasion-03|ASLR/DEP Bypass]]
- [[training-defense-evasion-04|Build Image on Host]]
- [[training-defense-evasion-05|Clear Windows Event Logs / Linux History]]
- [[training-defense-evasion-06|Debugger Evasion]]
- [[training-defense-evasion-07|Deobfuscate/Decode Files or Information]]
- [[training-defense-evasion-08|Deploy Container]]
- [[training-defense-evasion-09|Direct Volume Access]]
- [[training-defense-evasion-10|Execution Guardrails]]
- [[training-defense-evasion-11|Exploitation for Defense Evasion]]
- [[training-defense-evasion-12|File and Directory Permissions Modification]]
- [[training-defense-evasion-13|Hide Artifacts]]
- [[training-defense-evasion-14|Hijack Execution Flow]]
- [[training-defense-evasion-15|Impair Defenses]]
- [[training-defense-evasion-16|Indicator Removal]]
- [[training-defense-evasion-17|Masquerading]]
- [[training-defense-evasion-18|Modify Authentication Process]]
- [[training-defense-evasion-19|Modify Cloud Compute Infrastructure]]
- [[training-defense-evasion-20|Modify System Image]]
- [[training-defense-evasion-21|Network Boundary Flyby]]
- [[training-defense-evasion-22|Obfuscated Files or Information]]
- [[training-defense-evasion-23|Plc/Firmware Modification]]
- [[training-defense-evasion-24|Pre-OS Boot]]
- [[training-defense-evasion-25|Process Injection]]
- [[training-defense-evasion-26|Rootkit]]
- [[training-defense-evasion-27|Subvert Trust Controls]]
- [[training-defense-evasion-28|System Binary Proxy Execution]]
- [[training-defense-evasion-29|Traffic Signaling]]
- [[training-defense-evasion-30|Trusted Developer Utilities Proxy Execution]]
- [[training-defense-evasion-31|Unused/Unsupported Cloud Regions]]
- [[training-defense-evasion-32|Use Alternate Authentication Material]]
- [[training-defense-evasion-33|Valid Accounts]]
- [[training-defense-evasion-34|Virtualization/Sandbox Evasion]]

[[Analyst Training]]