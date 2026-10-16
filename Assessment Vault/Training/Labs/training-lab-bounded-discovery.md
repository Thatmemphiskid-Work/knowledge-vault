# Bounded port discovery and defender correlation

## Prerequisites

Nmap already installed, a written target/port allowlist, a non-fragile lab service and agreed source IP. Replace the reserved example. Start with one host; for an explicitly approved small range replace the single address with that exact range, never infer scope from routing. Connection attempts can affect fragile services.

## Ordinary TCP-connect scan of three approved ports

```sh
# Replace 192.0.2.10 with the approved lab address.
nmap -sT -Pn -n -p 22,80,443 --max-rate 5 --max-retries 1 --host-timeout 30s 192.0.2.10
```

-sT uses normal TCP connections; -Pn skips host discovery, not logging; -n avoids DNS lookups. The rate cap bounds load, not stealth. Open means a connection succeeded; closed/filtered/timeout do not prove product absence or a CVE. No exploit scripts are run.

## Operator and defender walkthrough

1. Record UTC start/end, source address, exact approved destinations and command. Stop if the service owner reports degradation.
2. Run once and preserve output. Compare open ports with the owner listener/ingress inventory and intended clients.
3. Defender: query firewall/flow/endpoint logs for the source, destination, ports and window. Check whether successful and denied attempts are recorded; determine whether an alert is actually intended.
4. If an unexpected port is reachable, record excessive exposure and ownership. Establish software identity/version separately through approved inventory; do not label the port scan a vulnerability test.
5. After approved exposure changes, repeat identical ports/vantage and verify required clients still work.

## Expected result

A documented reachable-service list and correlated connection evidence. No alert is not a failure if policy only requires collection. No response is inconclusive.

## What this does not prove

Tests TCP reachability on specified ports, not UDP, application authorization, exploits, stealth or complete host inventory.

[[Analyst Training]]