# Reconnaissance training

Understand information visible before access, and distinguish public exposure from privileged owner inventory.

## Reconnaissance workflow

Defensive analyst training and harmless validation, not an attack execution manual. Use owner-provisioned identities, inert files and approved lab endpoints. Never collect real credentials or private communications. No snapshot/reset dependency. Commands are reference text and are not executed by the app.

Understand information visible before access, and distinguish public exposure from privileged owner inventory.

### DNS and bounded service observation

```powershell
# Replace reserved placeholders with one approved domain/host. No IP-block scan.
Resolve-DnsName -Name 'lab.example' -Type A
Resolve-DnsName -Name 'lab.example' -Type MX
Test-NetConnection -ComputerName 'lab.example' -Port 443 -InformationLevel Detailed
```

DNS records and TCP reachability are leads, not proof of product, ownership, vulnerability or authorization. Run from each documented vantage; failure is inconclusive.

### Verify

1. Get an explicit asset/domain allowlist and distinguish public-source review, target connections and privileged inventory. Do not extend scope to vendors mentioned in records.
2. Record source URL or command, UTC time, resolver/vantage and freshness. Compare observed facts with owner architecture records; label inferred relationships.
3. For exposure findings, show the exact unnecessary public detail or reachable interface, its owner and why it matters. Redact personal information; an email address is not a credential.

### Fix / prevent

1. Remove unnecessary public infrastructure detail and outdated records; restrict management exposure while preserving required DNS and business publishing.
2. Define an information-release policy and a reporting route for suspicious inquiries. Obtain owner approval before changing public records.

### Retest

1. Repeat the same public lookups or approved connection after record propagation; compare from the same vantage.
2. Confirm required service discovery still works and private details no longer appear on the reviewed surfaces.

### Detection evidence

1. Correlate approved connection checks with DNS, edge and application telemetry. Passive public research may leave no logs in your environment; do not promise detection of it.

### Decision branches

- **If Evidence or authority is incomplete:** Mark not tested or a coverage gap; do not invent a result.
- **If Expected deny/control fails:** Record the exact boundary and escalate to its owner; do not expand access.
- **If Expected collection/alert/containment is missing:** Locate the failed milestone using Analyst Training outcome branches and repeat after repair.



## Hands-on labs

- [[training-lab-bounded-discovery|Bounded port discovery and defender correlation]]

## Topics

- [[training-reconnaissance-01|Active Scanning]]
- [[training-reconnaissance-02|Gather Victim Architecture Information]]
- [[training-reconnaissance-03|Gather Victim Identity Information]]
- [[training-reconnaissance-04|Gather Victim Network Information]]
- [[training-reconnaissance-05|Gather Victim Org Information]]
- [[training-reconnaissance-06|Phishing for Information]]
- [[training-reconnaissance-07|Search Open Technical Databases]]
- [[training-reconnaissance-08|Search Open Websites/Domains]]

[[Analyst Training]]