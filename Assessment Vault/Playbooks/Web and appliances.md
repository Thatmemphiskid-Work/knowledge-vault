# Web and appliances

## Find: Shell, replace the example URL with one approved asset; this is NOT a CVE test
Only use on explicitly approved assets. Read-only commands may still reveal sensitive inventory; protect output.

```sh
curl --head --connect-timeout 5 --max-time 10 https://asset.example
# Headers can be hidden or misleading. Use the authenticated admin UI
# or vendor-supported inventory command for the exact firmware/build.
# Do not run generic commands on restricted appliance shells.
```

## Test and defend
Inventory is not an exploit test. Compare exact deployed versions and configuration with the CVE's vendor advisory; use supported authenticated scanners or vendor diagnostics where available. Linux distribution backports can invalidate upstream version comparisons. A missing Windows hotfix does not prove vulnerability because updates can be superseded. Runtime dependencies can differ from package-manager output.
Record evidence in [[Evidence Template]], follow [[Assessment Decision Tree]], apply the specific vendor fix, and recheck the deployed instance. For managed services and appliances, use their vendor console rather than assuming host shell access.
