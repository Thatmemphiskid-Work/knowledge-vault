# System Information Discovery — Discovery

## Understand the behavior

OS/build/architecture facts anchor applicability decisions.

## Find / assess evidence

Record local OS build and vendor servicing evidence.

## Prevent / remediate

Patch supported systems and protect unnecessary public disclosure.

## Safe exercise

Collect the approved host's OS metadata and record limitations.

## Full procedure and result interpretation

## Discovery workflow

Defensive analyst training and harmless validation, not an attack execution manual. Use owner-provisioned identities, inert files and approved lab endpoints. Never collect real credentials or private communications. No snapshot/reset dependency. Commands are reference text and are not executed by the app.

Use bounded authorized read-only inventory to understand assets and permissions while protecting personal data and secrets.

### Windows identity, OS and network inventory

```powershell
# Run only in the approved host session; protect exported identifiers.
whoami
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber
Get-NetIPConfiguration
Get-NetTCPConnection | Select-Object State,LocalAddress,LocalPort,RemoteAddress,RemotePort
Get-Date -Format o
```

A point-in-time view is not exhaustive inventory, remote reachability or proof of compromise. Access failures mean incomplete visibility.

### Linux host and interface inventory

```sh
# Approved host session; no network sweep or file-content search.
id
cat /etc/os-release
uname -r
ip address show
ip route show
ss -lnt
date -u
```

Tools may be absent or restricted. These commands reveal local identity/configuration only; they do not establish that adjacent assets are reachable.

### Verify

1. Obtain owner-approved host/resource scope and read privileges. Decide which metadata is needed; avoid browser history, private file contents and secrets.
2. Record command/API, identity, time, platform and access errors. Reconcile point-in-time output with owner inventory and retained change records.
3. Classify differences as unexpected, legitimate, stale or unknown. An administrator's view must not be presented as an unauthenticated capability.

### Fix / prevent

1. Restrict unnecessary enumeration permissions and exposed management interfaces without breaking necessary administration.
2. Maintain inventories with owners and monitor unexpected read activity using identity and resource context.

### Retest

1. Repeat the same approved metadata query and verify expected allowed/denied roles.
2. Confirm inventory reconciliation and telemetry collection; retain unresolved assets instead of reporting absence.

### Detection evidence

1. Discovery commands overlap with legitimate administration. Use principal, host, volume, target scope and change context rather than alerting on a command name alone.

### Decision branches

- **If Evidence or authority is incomplete:** Mark not tested or a coverage gap; do not invent a result.
- **If Expected deny/control fails:** Record the exact boundary and escalate to its owner; do not expand access.
- **If Expected collection/alert/containment is missing:** Locate the failed milestone using Analyst Training outcome branches and repeat after repair.



## Runnable labs and limits

- [[training-lab-bounded-discovery|Bounded port discovery and defender correlation]]
- [[training-lab-benign-execution|Benign interpreter execution and endpoint visibility]]
- [[training-lab-cloud-container-read|Read-only cloud and container control-plane checks]]

These are control-validation labs, not instructions to execute this harmful technique. Refer to each lab's stated limits.

[[training-group-discovery]] · [[Analyst Training]]