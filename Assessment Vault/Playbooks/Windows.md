# Windows

## Find: PowerShell, local read-only inventory
Only use on explicitly approved assets. Read-only commands may still reveal sensitive inventory; protect output.

```powershell
Get-CimInstance Win32_OperatingSystem | Select Caption,Version,BuildNumber
Get-HotFix | Sort InstalledOn -Descending | Select -First 20
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Select DisplayName,DisplayVersion,Publisher
Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort,OwningProcess
```

## Test and defend
Inventory is not an exploit test. Compare exact deployed versions and configuration with the CVE's vendor advisory; use supported authenticated scanners or vendor diagnostics where available. Linux distribution backports can invalidate upstream version comparisons. A missing Windows hotfix does not prove vulnerability because updates can be superseded. Runtime dependencies can differ from package-manager output.
Record evidence in [[Evidence Template]], follow [[Assessment Decision Tree]], apply the specific vendor fix, and recheck the deployed instance. For managed services and appliances, use their vendor console rather than assuming host shell access.
