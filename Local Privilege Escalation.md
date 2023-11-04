There are various ways of locally escalating privileges on windows box -:
- Missing patches
- Automated deployment and Auto Logon passwords in clear text
- AlwaysInstallElevated (Any user can run MSI as SYSTEM)
- Misconfigured Services
- DLL Hijacking and more
- NTLM Relaying a.k.a won't fix


We can use below tools for complete coverage
- PowerUp - https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- PrivEsc - https://github.com/enjoiz/Privesc
- WinPEAS - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/

Service Issues using `PowerUp`

- Get services with unquoted paths and a space in their name


```powershell
$ Get-ServiceUnqouted -Verbose
```



- Get services where the current user can write to its binary or change arguments to the binary

```powershell
$ Get-ModifiableServiceFile -Verbose
```



- Get the services whose configuration current user can modify

```powershell
$ Get-ModifiableService -Verbose
```



We can also automate this by using the below commands


```powershell
# For Powerup
$ Invoke-AllChecks

# For PrivEsc
$ Invoke-PrivEsc

# For PEASS-ng
$ winPEASx64.exe
```


