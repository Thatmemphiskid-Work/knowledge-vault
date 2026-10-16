# Credential Access training

Protect authentication material and recognize exposure evidence without collecting, cracking or replaying real secrets.

## Credential Access workflow

Defensive analyst training and harmless validation, not an attack execution manual. Use owner-provisioned identities, inert files and approved lab endpoints. Never collect real credentials or private communications. No snapshot/reset dependency. Commands are reference text and are not executed by the app.

Protect authentication material and recognize exposure evidence without collecting, cracking or replaying real secrets.

### Verify

1. Inventory credential-bearing stores and identity flows from approved architecture and policy exports; record metadata, not secret values.
2. Review access controls, secret lifetime, transport protection, token validation and retained identity events. Discovery of a suspected secret is an incident-handling matter; do not test it by login.
3. Use synthetic identities and instructor-provided redacted fixtures to check expected deny/revoke decisions. No password spraying, keylogging, ticket cracking or memory dumping.

### Fix / prevent

1. Apply phishing-resistant authentication, least privilege, protected secret stores and short-lived tightly scoped tokens where supported.
2. If exposure is established, preserve evidence and revoke/rotate affected secrets through the owner's incident process; patch underlying defects.

### Retest

1. Verify access and revocation policy with a supplied synthetic identity, without copying raw tokens into evidence.
2. Review updated secret-scanning, access and authentication audit evidence and confirm legitimate access remains possible.

### Detection evidence

1. Correlate unusual access to credential stores, factor/grant changes and sign-in anomalies with identity context. Never include passwords, hashes, keys, raw cookies or tokens in training records.

### Decision branches

- **If Evidence or authority is incomplete:** Mark not tested or a coverage gap; do not invent a result.
- **If Expected deny/control fails:** Record the exact boundary and escalate to its owner; do not expand access.
- **If Expected collection/alert/containment is missing:** Locate the failed milestone using Analyst Training outcome branches and repeat after repair.



## Hands-on labs

- [[training-lab-authorization-matrix|Test synthetic-account authorization, logout and containment]]
- [[training-lab-pipeline-fixtures|Runnable offline telemetry-gap and policy-decision exercise]]

## Topics

- [[training-credential-access-01|Adversary-in-the-Middle]]
- [[training-credential-access-02|Brute Force]]
- [[training-credential-access-03|Credentials from Password Stores]]
- [[training-credential-access-04|Exploitation for Credential Access]]
- [[training-credential-access-05|Forge Web Credentials]]
- [[training-credential-access-06|Input Capture]]
- [[training-credential-access-07|Kerberoasting / AS-REP Roasting]]
- [[training-credential-access-08|Network Sniffing]]
- [[training-credential-access-09|OS Credential Dumping]]
- [[training-credential-access-10|Phishing for Credentials]]
- [[training-credential-access-11|Steal Application Access Tokens]]
- [[training-credential-access-12|Steal or Forge Authentication Certificates]]
- [[training-credential-access-13|Steal Web Session Technologies]]
- [[training-credential-access-14|Two-Factor Authentication Evasion]]
- [[training-credential-access-15|Unsecured Credentials]]

[[Analyst Training]]