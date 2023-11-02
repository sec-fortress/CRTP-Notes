# **Domain Enumeration Cont'd - GPO**

## **What is Group Policy ?**

- Group Policy Provides the ability to manage configuration and changes easily and centrally in AD.
- Allows configuration of -:
	- Security settings
	- Registry-based policy settings
	- GPO preferences like startup/shutdown/log-on/logoff scripts settings
	- Software installation
- GPO can be abused for various attacks like privilege escalation, backdoors, persistence etc.

**Using `powerview` we can actually get some Interesting information from the GPO**

- Get list of GPO in current domain

```powershell
$ Get-NetGPO # get list of all group policy object
$ Get-NetGPO -ComputerName dcorp-student1.dollarcorp.moneycorp.local
```

We can also filter with -:

```powershell
$ Get-NetGPO | select displayname
```

> **Note :** The **Default Domain Policy** and **Default Domain Controllers Policy** are default GPO, so we should really focus on the ones that comes next.


- Get GPO(s) which use restricted Groups of `groups.xml` for interesting users

```powershell
$ Get-NetGPOGroup
```

- Get users which are in a local group of a machine using GPO

```powershell
$ Find-GPOComputerAdmin -Computername dcorp-student1.dollarcorp.moneycorp.local
```

- Get machines where the given user is member of a specific group

```powershell
$ Find-GPOLocation -UserName student1 -Verbose
```

- Get OUs in a domain

```powershell
$ Get-NetOU -FullData
```

- Get GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU

First of all run 

```powershell
$ Get-NetOU -FullData
```

Now copy the GPO of the OU you want t 