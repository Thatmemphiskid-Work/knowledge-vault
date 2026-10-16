# Assess file access, canonicalization, and upload boundaries

## Assess file access, canonicalization, and upload boundaries

Source and permission review plus owner-created benign file fixtures. Distinguish remote application access, authenticated uploads, and local service-account access. No attempts to read operating-system secrets.

A user-visible name is not a safe filesystem authority. Decoding, separator handling, case rules, Unicode conversion, archive extraction, and symbolic links can change the object a path denotes. Validate the representation actually used and enforce containment using filesystem-aware operations, not a simple string-prefix comparison.

File risk also depends on the account performing the operation and where uploaded bytes are stored. A database FILE privilege or a broadly privileged service account can expose host files even when the remote user has no direct filesystem login. An upload should be treated as untrusted data, not executable application content. Path review here is a defensive synthesis of the books' encoding and file-privilege lessons, not a reproduced traversal lab.

### Verify

1. Inventory download, upload, import, export, archive, template, and logging paths. Record who can choose names and how application identifiers map to actual files.
2. Trace decoding and normalization through the final open/create operation. Review containment checks, path-component rules, link handling, race protection, and behavior for existing versus new files. Retain code revision and approved root configuration.
3. Ask the owner to provision harmless files inside the approved root and in a separate test-only root. Verify ordinary allowed access through the application; verify rejection of disallowed locations through reviewed automated tests or policy evidence, without transmitting traversal strings or reading real host files.
4. Review effective service-account permissions and database grants. Establish whether the account can read or write outside its needed roots; permission evidence is sufficient, so do not demonstrate access to sensitive files.
5. For uploads inspect size/count limits, server-selected names, content policy, non-executable storage, authorization for retrieval, and archive extraction containment. Use only small approved text fixtures and normal names.

### Fix / prevent

1. Map opaque application IDs to server-controlled files and restrict operations to explicit roots with component-aware containment and safe link/race handling.
2. Store uploads under generated names in non-executable storage; enforce bounded sizes, approved types, authorization, and safe archive processing.
3. Remove unnecessary host and database file privileges; separate read, write, and processing accounts where practical.

### Retest

1. Repeat approved fixture operations and reviewed negative containment tests; verify allowed files still work and denied locations remain inaccessible.
2. Recheck permissions, upload handlers, and archive/link behavior after deployment. Remove benign fixtures through approved application/owner procedures.

### Detection evidence

1. Log denied file operations using stable object IDs and reason categories rather than sensitive absolute paths or contents.
2. Monitor writes to application executable/configuration directories and changes in file privileges; correlate with application identity and deployment activity.

### Decision branches

- **If User-selected paths can reach an unrestricted filesystem operation:** Document missing containment and service-account impact without accessing outside data.
- **If Checks occur before a meaning-changing conversion or link resolution:** Containment is not established; request filesystem-aware implementation evidence.
- **If Uploads are outside the web root but a processor still executes them:** Assess the downstream processing boundary; storage location alone is not a complete control.

## Optional source provenance

The procedure is self-contained; these sources are audit context, not required reading.

- [[book-02]] (PDF page 265): Explicitly identifies security checks in one encoding followed by resource access using another as a dangerous sequence.
- [[book-05]] (PDF page 949): Explains that database FILE privilege can read files available to the database service user; used for permission-based assessment, not file extraction.