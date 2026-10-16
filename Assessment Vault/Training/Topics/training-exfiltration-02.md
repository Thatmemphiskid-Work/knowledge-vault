# Data Transfer Size Limits — Exfiltration

## Understand the behavior

Volume-only detections can miss aggregate behavior across events.

## Find / assess evidence

Review synthetic cumulative transfer totals against classification and destination policy.

## Prevent / remediate

Use identity/classification context and appropriate aggregation rather than volume alone.

## Safe exercise

Test a query on provided small-transfer records; no chunking/evasion implementation.

## Full procedure and result interpretation

## Exfiltration workflow

Defensive analyst training and harmless validation, not an attack execution manual. Use owner-provisioned identities, inert files and approved lab endpoints. Never collect real credentials or private communications. No snapshot/reset dependency. Commands are reference text and are not executed by the app.

Validate data-loss policy and egress evidence with synthetic metadata or a small explicitly approved inert transfer, never real sensitive data or stealth channels.

### Verify

1. Name source classification, approved destination, identity and expected data-loss policy. Choose instructor-owned inert text or synthetic transfer records only.
2. Prefer an offline policy/query fixture. If the owner separately approves an actual transfer, fix the destination, small size and ordinary supported protocol; do not split, hide or tunnel data.
3. Record source/destination audit, policy decision, alert/ticket and confirmed denial/containment. Do not equate a dashboard alert with prevention of transfer.

### Fix / prevent

1. Restrict excessive export/sharing and unapproved destinations; enforce supported classification and data-loss controls.
2. Repair policy and telemetry gaps across cloud, endpoint and physical transfer paths with accountable owners.

### Retest

1. Repeat the same inert policy fixture or separately approved transfer and verify actual allow/deny outcome plus expected alert.
2. Confirm authorized sharing works and document blind spots and privacy limits.

### Detection evidence

1. Join file/object access and export/egress evidence with identity, classification and destination. Small or scheduled transfers are not guaranteed to evade controls; test timing with synthetic logs rather than operational stealth.

### Decision branches

- **If Evidence or authority is incomplete:** Mark not tested or a coverage gap; do not invent a result.
- **If Expected deny/control fails:** Record the exact boundary and escalate to its owner; do not expand access.
- **If Expected collection/alert/containment is missing:** Locate the failed milestone using Analyst Training outcome branches and repeat after repair.



## Runnable labs and limits

- [[training-lab-authorization-matrix|Test synthetic-account authorization, logout and containment]]
- [[training-lab-pipeline-fixtures|Runnable offline telemetry-gap and policy-decision exercise]]

These are control-validation labs, not instructions to execute this harmful technique. Refer to each lab's stated limits.

[[training-group-exfiltration]] · [[Analyst Training]]