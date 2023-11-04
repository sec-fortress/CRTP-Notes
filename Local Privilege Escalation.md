There are various ways of locally escalating privileges on windows box -:
- Missing patches
- Automated deployment and Auto Logon passwords in clear text
- AlwaysInstallElevated (Any user can run MSI as SYSTEM)
- Misconfigured Services
- DLL Hijacking and more
- NTLM Relaying a.k.a won't fix


We can use below tools for complete coverage
- PowerUp - https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- Privesc - https://github.com/enjoiz/Privesc
- WinPEAS - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/

