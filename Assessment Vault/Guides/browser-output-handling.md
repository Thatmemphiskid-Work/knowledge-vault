# Assess browser rendering and DOM trust boundaries

## Assess browser rendering and DOM trust boundaries

Approved web pages, source review, and inert marker checks. Separate immediate reflection, stored rendering, and client-side DOM flows; do not execute injected code.

Browser injection is a rendering-boundary problem: an untrusted value is interpreted as markup or code rather than displayed as data. The relevant context can be HTML text, an attribute, a URL, script, or a DOM API. One escaping function is not correct for all contexts.

Reflected data returns in the current response; stored data is rendered later, possibly to a privileged viewer; DOM data can come from URL state or client storage without appearing in the server response. Finding a plain marker establishes data flow, not script execution. Browser filtering and security headers are supplementary controls, not substitutes for correcting an unsafe sink.

### Verify

1. Map user-controllable fields and later viewers, including administration screens and reports. Use synthetic records only and get approval before any persistent test data.
2. Submit a unique inert alphanumeric marker such as ASSESSMENTMARKER2026 through normal allowed UI behavior. Record route, role, request ID, response content type, and all places the marker appears.
3. Inspect response source and the final DOM with browser developer tools. Identify whether the marker becomes a text node, attribute, URL, or markup, and distinguish server output from client-side transformations.
4. Review source-to-sink paths for unsafe HTML insertion, script construction, and URL scheme handling. Confirm framework autoescaping remains enabled and that trusted-HTML exceptions cannot receive ordinary user input.
5. Review cookie protections and content security policy as defense in depth. A marker displayed correctly or a strict policy does not prove that every rendering path is safe.

### Fix / prevent

1. Prefer text-node APIs and framework escaping. Use context-appropriate encoding at output; avoid constructing script from data.
2. For intentional rich text use a maintained allowlist sanitizer and constrain URL schemes; document trusted-HTML boundaries.
3. Apply a supported restrictive content security policy and secure session cookies without treating them as the primary fix.

### Retest

1. Repeat inert marker flows in immediate, stored, and administrative views; inspect DOM and source after the change.
2. Review every changed sink and test permitted rich text and URLs for correct business behavior. Remove approved synthetic records via normal application controls.

### Detection evidence

1. Monitor rendering exceptions and policy violation reports with route and release identifiers; strip sensitive content from reports.
2. Correlate unusual saved-content changes with viewer errors and audit events. Policy reports alone do not establish a successful attack.

### Decision branches

- **If User data reaches an HTML/code sink without context-appropriate handling:** Document the code path and affected viewers as an unsafe rendering finding; do not run a script demonstration.
- **If Marker is plain text but source coverage is incomplete:** Record the tested path as behaving correctly; retain uncertainty for other contexts and roles.
- **If Client code alone handles rendering:** Assess DOM sinks independently of server-response escaping.

## Optional source provenance

The procedure is self-contained; these sources are audit context, not required reading.

- [[book-01]] (PDF page 445): Defines XSS as changed browser behavior and explains impact beyond a demonstration dialog.
- [[book-01]] (PDF page 457): Explicitly says to fix known XSS rather than rely on browser protection, and discusses client-side validation limitations.