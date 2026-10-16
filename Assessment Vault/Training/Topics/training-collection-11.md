# Screen Capture — Collection

## Understand the behavior

Screen images can contain sensitive information outside file controls.

## Find / assess evidence

Review approved application capture rights and device policy.

## Prevent / remediate

Limit capture/sharing and protect interactive sessions.

## Safe exercise

Use a fictional screenshot-permission record; no user screen capture.

## Full procedure and result interpretation

## Collection workflow

Defensive analyst training and harmless validation, not an attack execution manual. Use owner-provisioned identities, inert files and approved lab endpoints. Never collect real credentials or private communications. No snapshot/reset dependency. Commands are reference text and are not executed by the app.

Assess data access and collection controls with inert instructor-owned data, never private conversations, credentials or real employee content.

### Inspect explicitly approved inert fixture metadata

```powershell
# Replace with a directory containing instructor-owned non-sensitive fixtures only.
Get-ChildItem -LiteralPath 'C:\ApprovedAssessment\Fixtures' -File | Select-Object Name,Length,LastWriteTimeUtc
```

This is a bounded metadata listing, not recursive collection or proof of data access outside the fixture directory. Do not point it at real user profiles or sensitive repositories.

### Verify

1. Assign owners and sensitivity classes to data stores and map roles to expected reads/exports. Use only instructor-created non-sensitive fixtures.
2. Review access, export, staging and capture permissions; compare one approved fixture access event with expected audit fields.
3. Use policy review or a supplied synthetic denied-access case for unauthorized paths. Do not capture audio/video, mailbox contents or keyboard input.

### Fix / prevent

1. Reduce excessive read/export rights and enforce supported data classification and access controls.
2. Protect export/staging locations and restrict unattended collection and capture features.

### Retest

1. Repeat fixture access with the same roles and verify allow/deny and audit outcomes.
2. Confirm legitimate collaboration works and no sensitive content appears in training evidence.

### Detection evidence

1. Correlate object access, export operations and new staging artifacts with principal and business purpose. Routine reads are not necessarily malicious collection.

### Decision branches

- **If Evidence or authority is incomplete:** Mark not tested or a coverage gap; do not invent a result.
- **If Expected deny/control fails:** Record the exact boundary and escalate to its owner; do not expand access.
- **If Expected collection/alert/containment is missing:** Locate the failed milestone using Analyst Training outcome branches and repeat after repair.



## Runnable labs and limits

- [[training-lab-artifact-integrity|Create inert fixtures and detect a provenance/integrity change]]
- [[training-lab-authorization-matrix|Test synthetic-account authorization, logout and containment]]

These are control-validation labs, not instructions to execute this harmful technique. Refer to each lab's stated limits.

[[training-group-collection]] · [[Analyst Training]]