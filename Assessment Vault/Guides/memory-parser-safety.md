# Assess parser limits and memory-safety evidence

## Assess parser limits and memory-safety evidence

Developer-assisted code/build review and resource-bounded offline tests on an approved test instance. Production fuzzing and crash triggering are outside this guide.

A parser must check declared lengths, available bytes, nesting, counts, and arithmetic before allocation or copying. A multiplication or conversion that wraps can allocate less storage than subsequent operations assume. Memory-safe languages reduce some corruption risks but do not automatically prevent resource exhaustion or unsafe native-extension defects.

A crash is evidence of a failure, not proof of remote code execution or a named CVE. To diagnose it preserve the input, build identity, exception/stack, test conditions, and reproducibility. Mutation testing changes existing samples; grammar-based testing follows a format model. Both need bounded budgets and coverage analysis; neither a quiet run nor enabled mitigations proves absence of defects.

### Verify

1. List parser entry points, reachable roles, supported formats, maximum document sizes, native libraries, and build identifiers. Prioritize externally supplied content but preserve local-only and authenticated boundaries.
2. Review count-times-element-size calculations, signed/unsigned conversions, bounds checks, format-string APIs, recursion, decompression limits, and failure cleanup. Check declared lengths against both available bytes and application policy.
3. Have developers run existing format conformance and boundary tests offline with current compiler/runtime diagnostics appropriate to the stack. Agree CPU, memory, input-count, and time limits; do not adapt a book's live network random-data command.
4. If a bounded test fails, stop that case and preserve a hash of the synthetic input, stack/diagnostic, exact build, resource usage, and relevant code path. Group repeated failures by root cause; keep dumps private because they may contain secrets.
5. Assess supported compiler hardening and platform mitigations from build/runtime evidence. Mark uninstrumented or untested components as coverage gaps.

### Fix / prevent

1. Use checked arithmetic, explicit length validation, bounded allocation, fixed format strings, and safe ownership/lifetime patterns before data access.
2. Prefer maintained memory-safe parsers where feasible and patch native dependencies. Apply current supported hardening rather than historical protection packages from the labs.
3. Enforce document, expansion, recursion, concurrency, and execution-time limits; return controlled errors and add regression cases for diagnosed failures.

### Retest

1. Run the diagnosed cases and valid corpus against the fixed build offline under the same resource budgets and diagnostics.
2. Confirm invalid inputs reject cleanly, valid inputs still parse, and regression tests cover the actual root cause. Record changed coverage and residual untested interfaces.

### Detection evidence

1. Monitor parser exceptions, repeated process restarts, memory growth, and input rejection categories by component/build.
2. Restrict crash artifacts and correlate failures with input origin; avoid retaining customer documents unless incident handling explicitly authorizes it.

### Decision branches

- **If Diagnostic identifies an out-of-bounds operation or arithmetic overflow:** Report the reproducible safety defect and reachable input boundary, not weaponization or assumed exploitability.
- **If Only a timeout or memory spike is observed:** Investigate resource limits and complexity; do not classify it automatically as memory corruption.
- **If No failures but limited corpus or coverage:** Record the tests and limits; absence of observed crashes is not proof of parser safety.

## Optional source provenance

The procedure is self-contained; these sources are audit context, not required reading.

- [[book-02]] (PDF page 249): Explains wrapped allocation arithmetic producing smaller-than-expected buffers.
- [[book-01]] (PDF page 90): Distinguishes mutation and grammar-based testing.
- [[book-01]] (PDF page 102): Lists reproducible samples and crash context and explains clustering duplicate crashes.
- [[book-02]] (PDF page 268): Warns about live critical systems; unsafe random network fuzzing is deliberately not reused.