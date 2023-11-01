# **What is Domain Enumeration?**

- Once we have a foothold on target machine
- We will try to map out various entities, trusts, ACL's, relationships and privileges for the target domain
- The enumeration can be done by using Native executables and **.NET** classes in powershell
- To check DC, Parent, forest etc -:

```powershell
$ $ADClass = [System.DirectoryServices.AtciveDirectory.Domain]
$ $ADClass::GetCurrentomain()
```

To check current user privilege use -:

```powershell
$ whoami /priv
```

- To speed up things we can use Powerview -:

https://github.com/ZeroDayLab/PowerSploit/blob/master/Recon/PowerView.ps1





