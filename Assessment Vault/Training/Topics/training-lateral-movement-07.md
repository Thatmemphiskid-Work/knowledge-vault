# Software Deployment Tools — Lateral Movement

## Understand the behavior

Deployment authority can reach many destinations.

## Find / assess evidence

Review package approval, operator and target-group changes.

## Prevent / remediate

Protect orchestration roles and require scope approval.

## Safe exercise

Inspect a fictional deployment for unauthorized destination expansion.

## Full procedure and result interpretation

## Lateral Movement workflow

Defensive analyst training and harmless validation, not an attack execution manual. Use owner-provisioned identities, inert files and approved lab endpoints. Never collect real credentials or private communications. No snapshot/reset dependency. Commands are reference text and are not executed by the app.

Validate internal identity and network boundaries using supplied test principals and inert content, without pivoting or session theft.

### Verify

1. Create a source-principal/destination/service matrix with expected allowed and denied paths. Scope every destination explicitly; internal location is not authorization.
2. Use existing route/access evidence or one normal approved request with supplied identities. Capture source/destination and authentication/application result; a port connection is not successful lateral access.
3. Correlate both ends and central identity events. For exploitable services, establish CVE applicability separately; do not use stolen sessions, hashes or tickets.

### Fix / prevent

1. Segment unnecessary peer access, narrow remote administration/deployment rights and patch exposed internal services.
2. Protect session material and shared executable content; revoke unauthorized grants through incident procedures.

### Retest

1. Repeat original matrix cells with fresh synthetic identities and verify required workflows still work.
2. Confirm denied paths produce expected evidence and response, and document untested destinations.

### Detection evidence

1. Join source endpoint, destination authentication, application and network events. A local test event alone does not prove end-to-end lateral detection.

### Decision branches

- **If Evidence or authority is incomplete:** Mark not tested or a coverage gap; do not invent a result.
- **If Expected deny/control fails:** Record the exact boundary and escalate to its owner; do not expand access.
- **If Expected collection/alert/containment is missing:** Locate the failed milestone using Analyst Training outcome branches and repeat after repair.



## Runnable labs and limits

- [[training-lab-bounded-discovery|Bounded port discovery and defender correlation]]
- [[training-lab-authorization-matrix|Test synthetic-account authorization, logout and containment]]

These are control-validation labs, not instructions to execute this harmful technique. Refer to each lab's stated limits.

[[training-group-lateral-movement]] · [[Analyst Training]]