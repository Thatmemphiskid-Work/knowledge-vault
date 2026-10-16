# Map reachable services without assuming vulnerability

## Map reachable services without assuming vulnerability

Authorized external unauthenticated, internal network, and local administrator views; report each separately. Start with configuration and a small approved port list, not a network-wide scan.

A listening service, a reachable port, and an exploitable service are different facts. A TCP connection establishes reachability from one source at one time. A port label is usually a convention, not proof of the application or its version. Firewalls, NAT, load balancers, IPv6, and split DNS can make external and internal observations differ.

Build a service register containing asset owner, intended clients, listener address, transport, business purpose, expected authentication, and management plane. Compare observed exposure with that register. An unexpected administrator interface is an exposure finding even without a demonstrated exploit. A filtered or silent result is inconclusive about the service behind the boundary.

### One approved TCP port from a recorded vantage

```powershell
# Windows PowerShell; obtain written approval and replace the documentation host.
# One TCP connection attempt, not application identification.
Test-NetConnection -ComputerName service.example.invalid -Port 443 -InformationLevel Detailed
```

Record source address, destination address, port, time, and TcpTestSucceeded. True means a connection worked from this source; false can mean filtering, routing failure, unavailable host, or no listener. Do not extrapolate to UDP or other sources.

### Local listener inventory

```powershell
# Authorized Windows host session; process attribution may need elevated read access.
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess
```

Join process IDs to the approved process/service inventory. Wildcard bindings include multiple interfaces; loopback bindings are normally local-only. Local listeners do not prove remote reachability, and process IDs can change.

### Verify

1. Agree asset addresses, source networks, approved ports, rate, window, owner contact, and stop conditions. Fragile appliances require owner review before even basic connections. Stop if error rates or service latency rise.
2. Export current firewall, listener, ingress, DNS, and load-balancer configuration. Record IPv4 and IPv6 destinations and whether a proxy answers instead of the origin.
3. Attempt only the approved connection checks from each approved vantage; record exact outcomes. For application identity use owner configuration and deployed inventory, not the port number alone.
4. For every unexpected reachable endpoint, document intended versus actual clients and whether authentication is required. Gather configuration evidence of sensitive functions without invoking them.

### Fix / prevent

1. Remove unused listeners and ingress rules through change control.
2. Restrict management planes to approved administration networks and identities. Bind local-only services to loopback; review IPv6 separately.
3. Assign each remaining service an owner, support lifecycle, authentication policy, and exposure baseline.

### Retest

1. Repeat the same port checks from the same source networks and address families; retain before/after records.
2. Confirm expected clients still connect and unintended clients cannot. Reconcile host listeners with edge rules; closure of one route does not establish closure of all routes.

### Detection evidence

1. Alert on new listeners or ingress rules outside the baseline and retain actor/change-ticket context.
2. Correlate rejected connections and unexpected management access with destination ownership. An absence of firewall logs is not proof that no traffic arrived.

### Decision branches

- **If Reachable from an unauthorized network:** Confirm the destination and route with the owner; report excessive exposure, not a CVE.
- **If Internal connection succeeds but external check fails:** Record an internal attack surface and a boundary observation; do not describe the service as absent.
- **If No response or incomplete asset inventory:** Mark coverage incomplete and reconcile routing and owner evidence before closing.

## Optional source provenance

The procedure is self-contained; these sources are audit context, not required reading.

- [[book-09]] (PDF page 76): Separates internal hosts from systems visible to outsiders and calls for documenting accessible hosts.
- [[book-05]] (PDF page 239): Explains packet/response scanning and that OS identification is a guess.
- [[book-09]] (PDF page 145): Warns that scanning can produce false positives and denial of service; motivates bounded owner-approved checks.