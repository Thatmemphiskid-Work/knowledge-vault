# Lab Test Procedure

Environment lifecycle is handled by your existing bench scripts, not by this vault/app. No snapshot or reset step is required by this procedure.

## Procedure record
1. **Identity:** CVE, product, deployed version/build, exact configuration and vendor advisory.
2. **Attacker position:** reachable interface, network segment, protocol, authentication/privileges and user interaction required.
3. **Applicability:** affected range and prerequisites; account for distribution backports and superseded updates.
4. **Test source:** documented diagnostic or lab procedure, tool name/version, scanner/plugin ID, exact invocation and inputs used. Preserve the procedure reference; do not substitute a generic port scan.
5. **Expected result:** specify the vulnerability-specific observable outcome before executing. Describe normal/unaffected behavior too.
6. **Observed result:** logs, response/error, return code, timestamps, service state and any functional impact. Distinguish a verified weakness from a generic crash or failure.
7. **Control:** repeat the same test with the vendor fix/configuration change applied, keeping the vantage point and other conditions comparable. If possible, use an unaffected control to rule out unrelated behavior.
8. **Defense:** vendor fix, compensating controls, remaining exposure and final retest result.

## Branches
- Product match only → candidate.
- Vendor prerequisites confirmed, test unavailable → applicable, verification pending.
- Expected specific result reproduced with evidence → verified in lab.
- Test unsuccessful/ambiguous → inconclusive, not automatically safe.
- Fix applied but not retested → retest pending.
- Same vulnerability-specific outcome no longer reproduced and normal service works → remediated in the tested configuration.

Disruptive lab tests can be documented here, but no bulk exploit implementations are supplied. A complete CVE-specific test collection needs advisory research and validation against the matching vulnerable and fixed builds. See [[Evidence Template]] and [[Assessment Decision Tree]].
