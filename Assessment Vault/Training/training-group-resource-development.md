# Resource Development training

Recognize infrastructure and capability preparation while using only organization-owned training resources.

## Resource Development workflow

Defensive analyst training and harmless validation, not an attack execution manual. Use owner-provisioned identities, inert files and approved lab endpoints. Never collect real credentials or private communications. No snapshot/reset dependency. Commands are reference text and are not executed by the app.

Recognize infrastructure and capability preparation while using only organization-owned training resources.

### Verify

1. Create an instructor-owned inventory of approved lab domains, hosts, images, accounts, tools and their owners. No third-party compromise or procurement is part of this exercise.
2. Review registration, certificate, repository and cloud audit evidence already held by the organization. Attribute with corroborating facts, not a shared IP or provider alone.
3. For each resource, document intended use, identity, authorization, provenance, expiry and an abuse-report contact. Do not download or execute suspected malware.

### Fix / prevent

1. Require ownership and provenance review for tools/images and protect cloud/domain accounts with strong authentication and least privilege.
2. Restrict unauthorized hosting and follow provider abuse or incident processes for suspicious external resources; do not take them over.

### Retest

1. Verify approved resources retain named owners and lifecycle dates and unauthorized changes produce audit evidence.
2. Repeat the procurement/provenance review on an inert example and check reporting reaches the responsible team.

### Detection evidence

1. Track unapproved resource creation, suspicious domain/account changes and tool provenance. Preparation on unrelated external systems may not be observable locally.

### Decision branches

- **If Evidence or authority is incomplete:** Mark not tested or a coverage gap; do not invent a result.
- **If Expected deny/control fails:** Record the exact boundary and escalate to its owner; do not expand access.
- **If Expected collection/alert/containment is missing:** Locate the failed milestone using Analyst Training outcome branches and repeat after repair.



## Hands-on labs

- [[training-lab-artifact-integrity|Create inert fixtures and detect a provenance/integrity change]]
- [[training-lab-pipeline-fixtures|Runnable offline telemetry-gap and policy-decision exercise]]

## Topics

- [[training-resource-development-01|Acquire Infrastructure]]
- [[training-resource-development-02|Compromise Accounts]]
- [[training-resource-development-03|Compromise Infrastructure]]
- [[training-resource-development-04|Develop Capabilities]]
- [[training-resource-development-05|Establish Accounts]]
- [[training-resource-development-06|Obtain Capabilities]]
- [[training-resource-development-07|Stage Capabilities]]

[[Analyst Training]]