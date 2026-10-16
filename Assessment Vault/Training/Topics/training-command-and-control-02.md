# Communication Through Removable Media — Command and Control

## Understand the behavior

Media can carry information across an air gap.

## Find / assess evidence

Review media admission, transfer approval and chain-of-custody records.

## Prevent / remediate

Control media use and maintain approved transfer processes.

## Safe exercise

Review a fictional media-transfer manifest; no command exchange.

## Full procedure and result interpretation

## Command and Control workflow

Defensive analyst training and harmless validation, not an attack execution manual. Use owner-provisioned identities, inert files and approved lab endpoints. Never collect real credentials or private communications. No snapshot/reset dependency. Commands are reference text and are not executed by the app.

Evaluate outbound communication policy and telemetry using ordinary requests or synthetic traces, not malware channels, covert signaling or tunneling.

### Observe one ordinary approved HTTPS request

```sh
# Replace with an instructor-owned approved HTTPS endpoint returning static text.
curl --head --connect-timeout 5 --max-time 10 https://lab.example/
```

This validates an ordinary request and related telemetry only. It is not C2, carries no commands or data payload and cannot establish coverage of covert/encrypted variants.

### Verify

1. Document approved destination/service owners, egress policy, proxies, DNS and remote-access software. Do not contact suspicious destinations.
2. Perform one ordinary request to an instructor-owned endpoint or review supplied synthetic flow metadata; capture source, process/identity where available, destination, time and policy outcome.
3. Compare source evidence with network/endpoint collection, intended alert and response. Encrypted application contents may be unavailable; record metadata visibility and privacy constraints.

### Fix / prevent

1. Restrict unnecessary egress and remote-access tools and require destination ownership and reviewed proxy/DNS policy.
2. Collect useful endpoint/network context and repair coverage across fallback routes and regions without weakening TLS validation.

### Retest

1. Repeat the same ordinary request or query fixture and verify policy and telemetry outcomes.
2. Confirm required business traffic still works and distinguish synthetic replay from live communication detection.

### Detection evidence

1. Correlate connection/process identity, DNS, destination ownership and timing. Common protocols, encryption and unusual ports are clues, not automatic proof of malware or guaranteed detection bypass.

### Decision branches

- **If Evidence or authority is incomplete:** Mark not tested or a coverage gap; do not invent a result.
- **If Expected deny/control fails:** Record the exact boundary and escalate to its owner; do not expand access.
- **If Expected collection/alert/containment is missing:** Locate the failed milestone using Analyst Training outcome branches and repeat after repair.



## Runnable labs and limits

- [[training-lab-pipeline-fixtures|Runnable offline telemetry-gap and policy-decision exercise]]

These are control-validation labs, not instructions to execute this harmful technique. Refer to each lab's stated limits.

[[training-group-command-and-control]] · [[Analyst Training]]