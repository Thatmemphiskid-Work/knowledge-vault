# Verify identity, sessions, and object-level authorization

## Verify identity, sessions, and object-level authorization

Owner-provisioned synthetic users with documented roles and test objects. No guessing credentials, enumeration of real users, lockout testing, or credential attacks.

Authentication identifies a principal; authorization decides whether that principal may perform an action on a particular object. A successful login does not justify access to another tenant's records or administrator functions. Hidden UI controls are not server-side authorization.

Session validity must follow the application's policy for expiry, logout, privilege changes, and revocation. Test transport, identity provider, application, and background access separately where applicable. Database grants and application roles are separate layers; an overprivileged database identity can expand the impact of an application defect.

### Verify

1. Obtain an anonymous context and synthetic accounts for two ordinary users, a separate tenant if applicable, and an administrator. Create a role/action/object matrix with expected allow and deny decisions; the owner must approve this matrix.
2. Use normal login with supplied credentials and inspect session cookie attributes and documented expiry/revocation configuration. Keep tokens and passwords out of evidence.
3. For read-only approved endpoints compare own-object access, the explicitly provided other test object's identifier, and administrator-only access. Record status, redacted body, role, request ID, and server decision. Do not discover identifiers or access real user data.
4. Distinguish an actual denial from a login redirect or an error page returning sensitive data. For actions that change state, use code/policy review or separately approved synthetic functional tests rather than issuing speculative requests.
5. Perform one normal logout with a test session and verify the protected read is denied afterward under the documented revocation policy. Review password/MFA/reset configuration without probing guesses or recovery tokens.

### Fix / prevent

1. Enforce deny-by-default authorization on every server action using authenticated principal, object ownership/tenant, and permitted operation.
2. Centralize session lifecycle and revocation policy, secure cookies and transport, and protect high-risk actions with appropriate reauthentication/MFA.
3. Minimize application database grants and review recovery and service-account policies independently of UI roles.

### Retest

1. Repeat every allow and deny cell using fresh synthetic sessions and the same test objects, including anonymous access.
2. Confirm authorized users still work and logout/role-change decisions follow policy. Check logs without exposing tokens.

### Detection evidence

1. Log authorization decisions with principal identifier, object category, action, and request ID, avoiding sensitive record contents.
2. Investigate repeated denied cross-tenant actions and privilege changes; validate alerts with a single approved synthetic deny event, not credential attacks.

### Decision branches

- **If A test user receives another test principal's protected data or privileged function:** Report the exact role/object boundary failure and redact data; stop before expanding access.
- **If UI blocks access but server decisions are not checked:** Authorization remains unverified.
- **If A logged-out session remains valid contrary to policy:** Document a session revocation defect, including timing and expected policy; do not infer credential compromise.

## Optional source provenance

The procedure is self-contained; these sources are audit context, not required reading.

- [[book-10]] (PDF page 29): Separates authentication, authorization, confidentiality, integrity, and availability in protocol security.
- [[book-05]] (PDF page 945): Shows how to inspect assigned database privileges rather than assume role names imply restrictions.
- [[book-05]] (PDF page 949): Explains that connection privileges and powerful file privileges have distinct consequences.