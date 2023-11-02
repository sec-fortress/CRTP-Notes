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

Now copy the GPO of the OU you want to extract machines from

![](https://i.imgur.com/DGySe2D.png)

Then run

```powershell
$ Get-NetGPO -GPOname '{AB306569-220D-43FF-BO3B-83E8F4EF8081}'
```


# **Learning Objective 2**

- [ ] Enumerate following for the dollarcorp domain
	- List all the OUs
	- List all the computers in the StudentMachines OU.
	- List all the GPOs
	- Enumerate GPO applied on the StudentMachines OU


## **Solution**


**_Coming Soon_**




# **Domain Enumeration Cont'd - ACL**


##  **What is an Access Control Model (ACL) ?**


- [ ] Enables control on the ability of a process to access objects and other resources in active directory based on :
	- Access Tokens (security context of a process - identity and privileges of user)
	- Security Descriptors (SID of the owner, Discretionary ACL (DACL) and System ACL (SACL))


## **Enumerating ACL**

- Get the ACLs associated with the specified object 

```powershell
# powerview
$ Get-ObjectAcl -SamAccountName student1 -ResolveGUIDs
```


**_Example :_**


![](https://i.imgur.com/sNgi5yP.png)

> Note that there are 3 major properties we should look out for. The `ObjectDN` which signifies name of target machine, in this case `CN=student1`. Then the `IdentityReference` that states which users have permissions followed by the `ActiveDirectoryRights` that states the permissions that **IdentityReference** users have.


- Get the ACLs associated with the specified prefix to be used for search

```powershell
# powerview
$ Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose
```

- We can also enumerate ACLs using ActiveDirectory module but without resolving GUIDs

```powershell
# AD Module
$ (Get-Acl "AD:\CN=Administrator, CN=Users, DC=dollarcorp, DC=moneycorp,DC=local").Access
```

- Get the ACLs associated with the specified LDAP path to be used for search

```powershell
# powerview
$ Get-ObjectAcl -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose
```

- Search for interesting ACEs

```powershell
Invoke-ACLScanner -ResolveGUIDs
```

- Get the ACLs associated with the specified path

```powershell
Get-PathAcl -Path "\\dc.mydomain.local\sysvol" 
```