# Assessment Decision Tree

```text
Known asset + attacker vantage point
  |
  +-- Cannot establish product presence? -> Needs inventory evidence
  |
  +-- Product absent, with evidence? -> Not applicable to this asset
  |
  +-- Product present -> collect exact deployed version and configuration
        |
        +-- Advisory applicability unresolved? -> Candidate / needs evidence
        |
        +-- Vendor confirms unaffected or fixed/backported? -> Not affected
        |
        +-- Affected version + required configuration present
              |
              +-- No reproducible documented test? -> Applicable; test pending
              |
              +-- Test fails or signal ambiguous? -> Inconclusive; investigate
              |
              +-- Expected vulnerability-specific result reproduced
                    -> Verified in lab; retain raw evidence
                    -> Apply vendor fix / mitigate / retire unsupported product
                          |
                          +-- No retest? -> Fix applied; retest pending
                          +-- Test still succeeds? -> Fix ineffective; investigate
                          +-- Test no longer succeeds + normal service works
                                -> Remediated; retain before/after evidence
```

The app implements these branches using analyst-entered answers. It does not independently verify answers or run tests. Product inventory correlation reports candidates only. A failed test can reflect missing privileges, unreachable paths, blocked traffic, incorrect payload assumptions or wrong configuration—not absence of the vulnerability.

If you only have an unauthenticated view, do not treat unknown version/configuration as unaffected. State precisely what the attacker can observe versus what an authenticated assessor can establish.

See [[Attacker Vantage and Discovery]], [[Lab Test Procedure]], [[Evidence Template]], [[Incident Response]].
