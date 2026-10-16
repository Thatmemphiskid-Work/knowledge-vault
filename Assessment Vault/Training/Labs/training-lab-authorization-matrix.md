# Test synthetic-account authorization, logout and containment

## Prerequisites

Owner-provided lab application with synthetic users A/B, two synthetic objects and an explicitly approved role/action/object matrix. Obtain exact fixture URLs from the owner; do not guess object IDs or enumerate real users. A test administrator must perform any account suspension/revocation through the existing approved process.

## Operator and defender walkthrough

1. Open separate ordinary browser profiles for A, B and anonymous access. Sign in with supplied test credentials without saving them into training evidence.
2. Through the documented read-only UI or developer tools replay of the approved GET, check A reading A's fixture, B reading B's fixture, anonymous access and A reading the explicitly supplied B fixture. Keep normal method/body; do not probe unrelated routes.
3. For each cell record expected allow/deny, HTTP status, redacted result, request ID and server authorization event. A redirect or error status is not a deny if the body still contains protected fixture data.
4. Log A out normally, then use the owner's approved application test harness to repeat the protected GET with the original synthetic session retained only in test memory. A browser replay using an updated or empty cookie jar checks anonymous access, not old-session revocation. If you cannot preserve that test context, mark revocation untested. Record timing and documented revocation/expiry semantics; do not copy tokens or cookies into notes.
5. To validate containment, have the designated lab administrator revoke/suspend only the synthetic test identity through the approved workflow, then verify access actually stops using the same retained synthetic session context. An alert/ticket without denied access is not confirmed containment.
6. If a deny cell permits protected data, stop expansion, record the exact boundary failure, fix server authorization/session policy and repeat every allow and deny cell.

## Expected result

Authorized fixture reads work; documented unauthorized and revoked-session reads deny without protected data. Record any policy-defined propagation delay separately.

## What this does not prove

No credential theft, brute force, forged tokens, pass-the-hash, session hijacking or real data access. App-specific paths and provider semantics must come from the owner.

[[Analyst Training]]