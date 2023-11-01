# **What is Domain Enumeration?**

- Once we have a foothold on target machine
- We will try to map out various entities, trusts, ACL's, relationships and privileges for the target domain
- The enumeration can be done by using Native executables and **.NET** classes in powershell

# **Enumerating Domain**

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


- The active directory powershell module comes in handy as it offers less detection by AV

https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/

- To use ActiveDirectory module without installing RSAT, we can use `Import-Module` for the valid ActiveDirectory module DLL -:

https://github.com/samratashok/ADModule


