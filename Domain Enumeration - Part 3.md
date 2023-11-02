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
$ Get-NetGPO
$ Get-NetGPO -ComputerName dcorp-student1.dollarcorp.moneycorp.local
```

