# Review host trust, service identities, and excessive privileges

## Review host trust, service identities, and excessive privileges

Authorized local configuration review. Separate what a standard local user can observe from administrator-only evidence; do not execute privilege escalation techniques.

A privilege problem is often a trust relationship: a powerful process reads a binary, configuration, script, library, or scheduled-task definition that a less privileged principal can modify. Assess both the execution identity and the writers of every trusted artifact and parent directory. Administrator-only read evidence does not demonstrate that an ordinary user can exploit that relationship.

Service accounts need only their documented functions. Broad database grants, filesystem permissions, interactive login, and unrestricted management access can enlarge a defect's impact. Permission names and default configurations vary across platforms and versions; evaluate current effective rights rather than copying historical setup examples.

### Windows service identity and executable inventory

```powershell
# Authorized local Windows session; some fields may require elevated read access.
Get-CimInstance Win32_Service | Select-Object Name,State,StartName,PathName
```

Identify privileged identities and owner-approved executable/configuration locations. Do not execute PathName. Inspect quoted arguments and effective ACLs separately; a privileged identity or unusual path alone does not prove escalation.

### Review an approved artifact ACL

```powershell
# Replace with the exact owner-approved path on this host. Read-only ACL display.
Get-Acl -LiteralPath 'C:\ApprovedAssessment\service-config.example' | Format-List Owner,AccessToString
```

Compare writers with the service's trust boundary, including parent-directory rights and inherited groups. ACL display does not calculate all effective access or establish which process consumes this file.

### Verify

1. Record platform/build, service owners, administrator groups, service identities, scheduled jobs, and remote management listeners using authorized read access.
2. For each privileged service identify its binary, scripts, configuration, load/search directories, and update source. Review effective writers and ownership, including inherited directory permissions and group membership.
3. Review least-privilege requirements, interactive logon rights, credential storage policy, and database grants using redacted configuration. Do not dump credentials or modify service files to demonstrate impact.
4. Validate suspicious permissions with the owner and platform access-evaluation tools. Establish whether a lower-privilege role has actual write authority and whether a privileged process trusts the artifact; record each fact separately.

### Fix / prevent

1. Run services with narrowly scoped identities; remove unneeded interactive/admin/database privileges.
2. Protect executable, configuration, script, and search directories against unauthorized writers; use explicit supported paths and controlled deployment permissions.
3. Restrict management interfaces and manage secrets through supported protected stores. Document exceptions and service dependencies before changing rights.

### Retest

1. Recalculate effective rights for the same lower-privilege roles and verify that protected artifacts cannot be modified.
2. Verify service startup, maintenance, and business operations still function; repeat listener/identity inventory and compare with the approved baseline.

### Detection evidence

1. Monitor administrator/group membership changes, service identity/path changes, and writes to protected service artifacts.
2. Correlate unexpected privileged child processes with service and change records; retain actor and artifact hashes rather than secret contents.

### Decision branches

- **If Lower-privilege writers control an artifact trusted by a privileged service:** Report the trust/permission defect and code/configuration evidence; no elevation attempt is needed.
- **If Service is privileged but artifacts are protected:** Assess whether privilege is necessary; high privilege alone does not establish a writable-path weakness.
- **If Review was administrator-only:** Label configuration evidence as privileged visibility, not unauthenticated or ordinary-user access.

## Optional source provenance

The procedure is self-contained; these sources are audit context, not required reading.

- [[book-05]] (PDF page 945): Demonstrates inspection of assigned grants and powerful grant options.
- [[book-05]] (PDF page 949): States that users should not receive unneeded privileges and illustrates the service user's host-file reach.