# Linux

## Find: Shell, local read-only inventory
Only use on explicitly approved assets. Read-only commands may still reveal sensitive inventory; protect output.

```sh
cat /etc/os-release
uname -r
command -v dpkg-query >/dev/null && dpkg-query -W
command -v rpm >/dev/null && rpm -qa
ss -lntup
```

## Test and defend
Inventory is not an exploit test. Compare exact deployed versions and configuration with the CVE's vendor advisory; use supported authenticated scanners or vendor diagnostics where available. Linux distribution backports can invalidate upstream version comparisons. A missing Windows hotfix does not prove vulnerability because updates can be superseded. Runtime dependencies can differ from package-manager output.
Record evidence in [[Evidence Template]], follow [[Assessment Decision Tree]], apply the specific vendor fix, and recheck the deployed instance. For managed services and appliances, use their vendor console rather than assuming host shell access.
