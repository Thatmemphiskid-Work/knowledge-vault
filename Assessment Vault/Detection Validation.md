# Detection Validation

## Goal: low-signal coverage, not assumed invisibility
Test whether your IDS/IPS, endpoint controls, identity logs and response automation can detect and contain defined unauthorized actions, including activity that resembles ordinary traffic. This is a detection-engineering plan, not a guide to hiding activity or defeating monitoring.

An IDS does not inherently know who is authorized. Establish the expected identity, device and resource-access policy, and correlate network observations with authentication/endpoint evidence. Encrypted traffic can obscure content; a network-only sensor cannot guarantee detection of every unauthorized actor.

## Test campaign record
- Campaign ID, test owner, bench asset and starting vantage point.
- IDS/IPS rule-set version, sensor placement, endpoint/identity integrations and policy version.
- Ground-truth start/end timestamps (UTC), source identity/device, destination and scenario.
- Expected telemetry sources, alert/rule and allowed detection latency **before** the test.
- Actual raw event, alert ID and timestamp, analyst decision and response action.
- Containment evidence: new attempts denied, existing sessions handled, expected authorized access still works.
- Final classification: detected + contained / detected only / telemetry only / missed / invalid test / correct benign result.

## Scenario matrix
| Scenario | Test action within the bench | Expected evidence | Common interpretation error |
| --- | --- | --- | --- |
| Authorized baseline | Normal use by an approved user/device | Access recorded; no unjustified intrusion alert | Every alert is treated as a success even when legitimate work is blocked |
| Unknown device | A designated unapproved bench device attempts one ordinary connection to a restricted service | Device/access-policy event correlated with connection outcome | A network connection alone is assumed to identify authorization |
| Restricted resource | A test identity without the necessary role requests a protected lab resource | Denial and identity/application logs; policy alert if specified | A login success is mistaken for permission to every resource |
| Low-volume activity | Predeclare a small set of ordinary lab requests spread over the campaign observation period | Per-event visibility and any policy-defined cross-event correlation | No burst alert is incorrectly interpreted as no telemetry |
| Encrypted application traffic | Normal HTTPS connection to a controlled lab service | Network flow plus relevant application/endpoint evidence | Encrypted content is assumed visible to a passive sensor |
| Segment boundary | Ordinary connection attempt between two lab segments where access is prohibited | Firewall/segmentation denial and central visibility | An unreachable service is credited to IDS detection without evidence |
| CVE-specific bench test | A documented reproduction already selected for a catalog CVE | Relevant sensor/endpoint/app event plus the vulnerability outcome | Reproduced vulnerability is assumed automatically detected |
| Containment exercise | Invoke your approved response workflow for a designated test identity/device | Audited action and proof that new access and relevant existing sessions are stopped | An isolation-command success response is mistaken for actual containment |

No packet manipulation, log tampering, monitoring disablement, covert channels, credential theft or stealth payloads are needed for these checks. Keep the behavioral tests distinct from a signature's synthetic self-test.

## Simple telemetry probe (not an attack or a stealth test)
From a bench machine, replace the domain with your controlled lab web service. This one ordinary request helps correlate the client timestamp with network and server logs; it does not prove unauthorized access detection.

```sh
date -u
curl --head --connect-timeout 5 --max-time 10 https://lab-service.example
```

PowerShell equivalent:

```powershell
(Get-Date).ToUniversalTime().ToString('o')
curl.exe --head --connect-timeout 5 --max-time 10 https://lab-service.example
```

The `.example` domain is a placeholder. Your scanner and bench scripts are not run by this app.

## Branching diagnosis
1. **Did the action actually occur and reach the intended point?** No → invalid/not exercised, not a missed detection.
2. **Did the sensor see it?** No → inspect placement, routing, collection and encryption visibility.
3. **Was raw telemetry retained?** No → collection/retention gap.
4. **Did the expected rule alert within the predeclared window?** No → rule/correlation gap or explicitly correct benign result.
5. **Was the alert correctly triaged?** No → routing/context/analyst gap.
6. **Did the approved response contain the test identity/device?** No → response gap.
7. **Did authorized control activity still work?** No → false-positive or containment blast-radius issue.

## Score the system honestly
- Detection coverage: detected expected-positive scenarios / valid expected-positive scenarios.
- Containment coverage: contained expected-positive scenarios / valid expected-positive scenarios.
- Detection latency: first relevant alert timestamp minus ground-truth action timestamp; synchronize clocks and track negative/missing timestamps as invalid measurements.
- Containment latency: verified effective containment timestamp minus action timestamp.
- False positives: benign scenarios producing unjustified intrusion alerts / valid benign scenarios.
- Do not count invalid tests as successes or silently remove misses from the denominator.

Compare the same matrix before/after your IDS improvements and preserve evidence. “All tested cases passed” is a defensible claim; “we detect anyone unauthorized” is not established by a finite campaign.

[[Evidence Template]] · [[Lab Test Procedure]] · [[Assessment Decision Tree]] · [[Incident Response]]
