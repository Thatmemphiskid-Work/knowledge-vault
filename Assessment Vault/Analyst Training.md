# Analyst Training

Defensive analyst training and harmless validation, not an attack execution manual. Use owner-provisioned identities, inert files and approved lab endpoints. Never collect real credentials or private communications. No snapshot/reset dependency. Commands are reference text and are not executed by the app.

This curriculum preserves the user's 14 groups and topic names. It is not an exact current ATT&CK matrix or a sequence that every incident follows. The official Enterprise tactics page reviewed on 2026-10-09 lists 15 tactics, including Stealth and Defense Impairment rather than a single Defense Evasion group. No technique-ID equivalence is asserted.

## How to use this curriculum

1. Start with the group overview, then the topic-specific evidence and control checks.
2. Choose a linked hands-on lab. Read prerequisites and replace placeholders before running commands. The app never runs commands on your behalf.
3. Separate configuration review, live harmless activity, offline fixture replay and tabletop results. They prove different things; none is automatically an exploit reproduction.
4. Record asset, test principal/vantage, UTC window, exact method, expected result, observed result, source event, collector event, alert and containment evidence.
5. Close a training exercise only when the trainee can explain the boundary, identify a legitimate comparison case, locate the failed milestone and retest after correction.

## Outcome branches

- Missing authority, prerequisite or source evidence: stop that case and mark **not tested / coverage gap**.
- Approved activity occurs but required source evidence is missing: investigate audit policy/visibility.
- Source evidence exists but central evidence is missing: investigate collection/retention.
- Central evidence exists but the intended alert is absent: investigate the rule/query; do not count silence as proof of absence.
- Alert exists but expected access denial/containment did not occur: response remains unverified.
- No alert was intended: evaluate collection only; ordinary administration should not automatically be labeled malicious.
- All expected observations match: record the specific tested control and mode, not universal attack resistance.

## Hands-on labs
- [[training-lab-bounded-discovery|Bounded port discovery and defender correlation]]
- [[training-lab-benign-execution|Benign interpreter execution and endpoint visibility]]
- [[training-lab-artifact-integrity|Create inert fixtures and detect a provenance/integrity change]]
- [[training-lab-authorization-matrix|Test synthetic-account authorization, logout and containment]]
- [[training-lab-cloud-container-read|Read-only cloud and container control-plane checks]]
- [[training-lab-pipeline-fixtures|Runnable offline telemetry-gap and policy-decision exercise]]

## All requested groups and topics

- [[training-group-reconnaissance|Reconnaissance]] — 8 topics
- [[training-group-resource-development|Resource Development]] — 7 topics
- [[training-group-initial-access|Initial Access]] — 9 topics
- [[training-group-execution|Execution]] — 12 topics
- [[training-group-persistence|Persistence]] — 18 topics
- [[training-group-privilege-escalation|Privilege Escalation]] — 11 topics
- [[training-group-defense-evasion|Defense Evasion]] — 34 topics
- [[training-group-credential-access|Credential Access]] — 15 topics
- [[training-group-discovery|Discovery]] — 26 topics
- [[training-group-lateral-movement|Lateral Movement]] — 9 topics
- [[training-group-collection|Collection]] — 12 topics
- [[training-group-command-and-control|Command and Control]] — 15 topics
- [[training-group-exfiltration|Exfiltration]] — 9 topics
- [[training-group-impact|Impact]] — 13 topics

## Source and coverage

https://attack.mitre.org/tactics/enterprise/

Original defensive synthesis aligned to the requested topic list, not vendor-validated exploit procedures. Topic coverage does not imply a live reproduction of every technique.
