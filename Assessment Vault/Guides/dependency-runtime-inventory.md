# Reconcile dependencies with the code actually running

## Reconcile dependencies with the code actually running

Authorized build manifests, deployment artifacts, runtime inventories, and supplier advisories. No dependency installation, package-script execution, or vulnerability payloads.

Applications inherit risk from frameworks, parsers, plugins, runtimes, native libraries, and container base images. A top-level manifest is not the entire dependency graph. Lockfiles describe a resolved build intent; an artifact inventory or SBOM describes shipped components; running-process evidence establishes what is actually loaded. Reconcile all three rather than assuming they agree.

A framework vulnerability is not proven by a recognizable page or a dependency name. Match exact supplier identity, package revision, deployment context, and vendor advisory conditions. Reachability can prioritize work but an unused-looking code path is not a permanent guarantee because configuration and application routes change.

### Inspect an existing Python environment without installing packages

```shell
# Authorized environment; use the owner's exact deployed interpreter.
# Placeholder must be replaced. Does not install or update packages.
<approved-python-interpreter> -m pip list --format=json
```

Capture interpreter identity and environment alongside output. This lists installed distributions, not necessarily imported modules, OS libraries, vendored code, or other environments. Command failure means inventory is incomplete, not dependency absence.

### Verify

1. Collect source revision, manifests/lockfiles, artifact hash or image digest, SBOM if available, interpreter/runtime identifiers, and deployment location. Use existing build outputs without resolving/installing untrusted dependencies.
2. Compare direct and transitive packages with shipped archives, bundled copies, native extensions, plugins, and runtime-loaded components. Include workers and alternate deployments, not only the front-end process.
3. Map unsupported or potentially affected components to current supplier advisories. Record fixed ranges and distribution backports exactly as documented; classify uncertain identity or applicability as unknown.
4. Identify supplier/source controls, version pinning, update ownership, and supported lifecycle. Check whether an old artifact can be redeployed and whether the updated runtime actually replaced the loaded old component.

### Fix / prevent

1. Upgrade or replace unsupported/affected dependencies following supplier guidance; rebuild and redeploy immutable reviewed artifacts.
2. Pin reviewed sources and resolutions, retain artifact identity, and prevent unapproved registry/source overrides.
3. Assign update ownership and remove unnecessary plugins or bundled copies; verify compatibility and restart loaded components as required.

### Retest

1. Compare the new artifact and running inventories against the resolved dependency graph and supplier fixed conditions.
2. Check worker processes and replicas, functional compatibility, and deployment controls that prevent old artifacts returning. Keep unresolved supplier evidence visible.

### Detection evidence

1. Alert on manifest/lockfile changes without reviewed build provenance, unexpected package sources, and runtime/artifact drift.
2. Monitor supplier advisories and lifecycle changes for the recorded inventory; keep notification routing tied to component owners.

### Decision branches

- **If Lockfile and deployed artifact differ:** Use deployed evidence for exposure and investigate build/deployment drift.
- **If A vulnerable framework is installed but feature use is unclear:** Record applicability uncertainty and obtain configuration/call-path evidence; do not probe with an exploit.
- **If No dependency manager inventory is available:** Request supplier artifact/SBOM and runtime evidence; do not report an empty dependency graph.

## Optional source provenance

The procedure is self-contained; these sources are audit context, not required reading.

- [[book-01]] (PDF page 462): Explains framework-provided functionality and high-impact Struts vulnerabilities; the historical exploit environment is not reused.
- [[book-01]] (PDF page 484): Motivates ongoing supplier-specific update handling including urgent releases.