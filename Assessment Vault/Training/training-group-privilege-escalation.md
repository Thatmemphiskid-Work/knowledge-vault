# Privilege Escalation training

Establish lower-to-higher privilege trust failures through permission, configuration and patch evidence, not elevation payloads.

## Privilege Escalation workflow

Defensive analyst training and harmless validation, not an attack execution manual. Use owner-provisioned identities, inert files and approved lab endpoints. Never collect real credentials or private communications. No snapshot/reset dependency. Commands are reference text and are not executed by the app.

Establish lower-to-higher privilege trust failures through permission, configuration and patch evidence, not elevation payloads.

### Read current identity and an approved ACL

```powershell
# Authorized session. Output contains identity metadata; protect it.
whoami /user
whoami /groups
Get-Acl -LiteralPath 'C:\ApprovedAssessment\service-config.example' | Format-List Owner,AccessToString
```

Replace the path with an approved artifact. Group membership and displayed ACLs are not a complete effective-access calculation. Do not execute or modify the service artifact.

### Verify

1. Name the starting principal, permitted actions and higher-privilege consumer. Separate administrator-only evidence from ordinary-user capability.
2. Review effective writers of privileged artifacts and directories, task/service identities, policy and vendor patch prerequisites.
3. Confirm each alleged trust failure using owner-approved permission evaluation or existing regression evidence; do not steal tokens, inject processes or trigger kernel exploits.

### Fix / prevent

1. Reduce excessive grants and protect artifacts consumed by privileged processes, including parent-directory rights.
2. Patch affected hosts/runtimes and enforce supported container/VM isolation and elevation policies.

### Retest

1. Re-evaluate effective access for the original lower-privilege role and verify it cannot control the privileged artifact.
2. Confirm expected service and user workflows still work and capture revised build/configuration evidence.

### Detection evidence

1. Correlate identity/group changes, privileged execution and artifact writes. A high-privilege service by itself is not an escalation finding.

### Decision branches

- **If Evidence or authority is incomplete:** Mark not tested or a coverage gap; do not invent a result.
- **If Expected deny/control fails:** Record the exact boundary and escalate to its owner; do not expand access.
- **If Expected collection/alert/containment is missing:** Locate the failed milestone using Analyst Training outcome branches and repeat after repair.



## Hands-on labs

- [[training-lab-artifact-integrity|Create inert fixtures and detect a provenance/integrity change]]
- [[training-lab-cloud-container-read|Read-only cloud and container control-plane checks]]

## Topics

- [[training-privilege-escalation-01|Abuse Elevation Control Mechanism]]
- [[training-privilege-escalation-02|Access Token Manipulation]]
- [[training-privilege-escalation-03|Boot or Logon Autostart Execution]]
- [[training-privilege-escalation-04|Boot or Logon Initialization Scripts]]
- [[training-privilege-escalation-05|Create or Modify System Process]]
- [[training-privilege-escalation-06|Escape to Host]]
- [[training-privilege-escalation-07|Exploitation for Privilege Escalation]]
- [[training-privilege-escalation-08|Hijack Execution Flow]]
- [[training-privilege-escalation-09|Process Injection]]
- [[training-privilege-escalation-10|Scheduled Task/Job]]
- [[training-privilege-escalation-11|Valid Accounts]]

[[Analyst Training]]