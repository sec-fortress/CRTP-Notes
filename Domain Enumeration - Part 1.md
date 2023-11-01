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



- To use ActiveDirectory module without installing **Remote Server Administration Tools** (RSAT), we can use `Import-Module` for the valid ActiveDirectory module DLL -:


https://github.com/samratashok/ADModule



## **Importing Modules to powershell**


### **Powerview module**

First of all download the powerview `.ps1` file from the link above

- change directory to where the module is located and run the powerview module

```powershell
$ cd C:\AD\Tools
$ ..\Powerview.ps1
```


**_Example :_**

![](https://i.imgur.com/64RjZRZ.png)


### **Active Directory Powershell module**


Download both files (`.dll` and `.psd1`) from senpai **samratashok** github handle from the link above

- Import `Microsoft.ActiveDirectory.Management.dll`

```powershell
$ cd C:\AD\Tools\ADmodule-master
$ Import-Module .\Microsoft.ActiveDirectory.Management.dll
```

- Import `ActiveDirectory.psd1`

```powershell
$ Import-Module .\ActiveDirectory\ActiveDirectory.psd1
```


**_Example :_**

![](https://i.imgur.com/ugWzM3j.png)


> Sometimes we might need to bypass Antimalware Scan Interface (AMSI) before we can upload this modules, we look on how to do that later




## **Enumerating Domain with Powerview and Active Directory Module**

**_Note :_** If one doesn't work then the other will, you know the difference between both as stated earlier 

- Get Current Domain

```powershell
$ Get-NetDomain # Powerview
$ Get-ADDomain # ActiveDirectory Module
```

- Get object of another domain

```Powershell
$ Get-NetDomain -Domain moneycorp.local # Powerview
$ Get-ADDomain -Identity moneycorp.local # AD Module
```


- Get domain SID for the current domain

```powershell
$ Get-DomainSID # powerview
$ (Get-ADDomain).DomainSID # AD module
```

- Get domain policy for the current domain

```powershell
$ Get-DomainPolicy # Powerview
$ (Get-DomainPolicy)."system access" # Powerview
```


**_Example :_**


![](https://i.imgur.com/IXElkMe.png)


- Get domain policy for another domain

```powershell
$ (Get-DomainPolicy -domain moneycorp.local)."system access" # powerview
```


- Get kerberos policy

```powershell
$ (Get-DomainPolicy)."Kerberos Policy" # powerview
```


> This is useful if we want to carry out an attack like **Golden tickets** as it makes sense to enumerate the **kerberos** policy first


- Get domain controllers for the current domain

```powershell
$ Get-NetDomain
```