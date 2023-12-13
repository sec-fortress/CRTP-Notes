
# **Domain Enumeration Cont'd - GPO # Powerview**

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
$ Get-DomainGPO # get list of all group policy object
$ Get-DomainGPO -ComputerIdentity dcorp-student1.dollarcorp.moneycorp.local
```

We can also filter with -:

```powershell
$ Get-DomainGPO | select displayname
```

> **Note :** The **Default Domain Policy** and **Default Domain Controllers Policy** are default GPO, so we should really focus on the ones that comes next.


- Get GPO(s) which use restricted Groups of `groups.xml` for interesting users

```powershell
$ Get-DomainGPOLocalGroup
```

- Get users which are in a local group of a machine using GPO

```powershell
$ Find-DomainGPOComputerLocalGroupMapping -ComputerIdentity dcorp-student505.dollarcorp.moneycorp.local
```

- Get machines where the given user is member of a specific group

```powershell
$ Find-DomainGPOUserLocalGroupMapping -Identity student1 -Verbose
```


# **Domain Enumeration - Organizational Units (OU)**




- Get OUs in a domain

```powershell
$ Get-DomainOU 
```

- Get GPO applied on an OU. Read GPOname from gplink attribute from Get-NetOU

First of all run 

```powershell
$ Get-DomainOU 
```

Now copy the GPO of the OU you want to extract machines from

![](https://i.imgur.com/DGySe2D.png)

Then run

```powershell
$ Get-DomainGPO -Identity "{AB306569-220D-43FF-BO3B-83E8F4EF8081}"
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
$ Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs
```


**_Example :_**


![](https://i.imgur.com/sNgi5yP.png)

> Note that there are 3 major properties we should look out for. The `ObjectDN` which signifies name of target machine, in this case `CN=student1`. Then the `IdentityReference` that states which users have permissions followed by the `ActiveDirectoryRights` that states the permissions that **IdentityReference** users have.


- Get the ACLs associated with the specified prefix to be used for search

```powershell
# powerview
$ Get-DomainObjectAcl -SearchBase "LDAP://CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose
```

- We can also enumerate ACLs using **ActiveDirectory** module but without resolving GUIDs

```powershell
# AD Module
$ (Get-Acl "AD:\CN=Administrator, CN=Users, DC=dollarcorp, DC=moneycorp,DC=local").Access
```

- Get the ACLs associated with the specified LDAP path to be used for search

```powershell
# powerview
$ Get-DomainObjectAcl -ADSpath "LDAP://CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose
```

- Search for interesting ACEs

```powershell
# powerview
$ Find-InterestingDomainAcl -ResolveGUIDs
```

- Get the ACLs associated with the specified path

```powershell
# powerview
$ Get-PathAcl -Path "\\dc.mydomain.local\sysvol" 
```

# **Learning Objective 3**

- [ ] Enumerate following for the dollarcorp domain:
	- ACL for the Users group
	- ACL for the Domain Admins group
	- All modify rights/permissions for the student


## **Solution**


**_Coming Soon_**


