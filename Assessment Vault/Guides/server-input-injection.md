# Trace web input into database and process boundaries

## Trace web input into database and process boundaries

Authorized source/configuration review and benign functional checks on approved application routes. Distinguish anonymous inputs from authenticated user and administrator inputs.

Injection occurs when data becomes part of an interpreter's instructions. SQL string concatenation and shell command construction are different sinks with the same boundary failure. A logged-in user remains an untrusted input source; authentication before a dangerous operation does not make submitted data safe.

Input validation expresses allowed types, lengths, ranges, and business values. It does not replace parameter binding or safe process APIs. Encoding conversion after validation can change the meaning of a character, so review decoding, normalization, validation, and sink use as a complete sequence. Error-free ordinary requests do not establish injection resistance.

### Verify

1. List entry points including query fields, JSON, headers, imported files, background jobs, and authenticated forms. Record required role and which application component receives each input.
2. Trace representative fields through decoding and validation to database calls, shell/process APIs, templates, and stored procedures. Gather redacted code excerpts with revision and call path; do not collect user secrets.
3. For SQL verify actual parameter binding, including inside stored procedures; dynamic table/column names need explicit allowlisted mappings. For process execution verify a fixed executable and separate argument array with no shell and no attacker-controlled options.
4. On approved non-production routes submit ordinary text, a documented valid boundary value, and a mildly out-of-range plain value within a small agreed size. Confirm documented validation behavior using request IDs and application logs; do not submit interpreter syntax or execution requests.
5. Record whether rejection happens server-side before sink use. A validation error proves only that particular input was rejected; source/trace evidence is needed for the broader conclusion.

### Fix / prevent

1. Use database parameter APIs for values and allowlisted identifiers; eliminate dynamic SQL where possible.
2. Replace shell invocation with library operations or fixed process/argument APIs; validate option values and restrict service account privileges.
3. Define one decoding/normalization policy and validate the final representation server-side. Use bounded error responses without query text, paths, or secrets.

### Retest

1. Review the changed source path to confirm all inputs reach safe sinks; test valid business values and documented invalid boundaries.
2. Check alternate routes, stored procedures, and background consumers. Confirm database/process permissions are limited and legitimate work still succeeds.

### Detection evidence

1. Correlate validation failures, database exceptions, and unexpected child processes with request IDs and roles.
2. Retain error categories rather than raw sensitive input. Establish a normal failure baseline and investigate changes without treating every syntax error as exploitation.

### Decision branches

- **If Untrusted input is concatenated into interpreted SQL or a shell command:** Report the unsafe data-to-code path and its reachable role; do not need or create an exploit payload.
- **If Validation is client-only or precedes meaning-changing conversion:** Treat the server boundary as unverified until validation is enforced on the representation actually used.
- **If Only black-box benign requests are available:** Report observed behavior and coverage limits, not an injection-free assurance.

## Optional source provenance

The procedure is self-contained; these sources are audit context, not required reading.

- [[book-02]] (PDF page 263): Shows that password authentication before shell construction does not protect a controllable command argument.
- [[book-02]] (PDF page 264): Explains SQL query construction from untrusted network strings.
- [[book-02]] (PDF page 265): Describes verification in one encoding followed by security-sensitive use in another.