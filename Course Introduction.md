# **What we will cover**

- [ ] **Introduction to Active Directory and Kerberos**
- [ ] **Introduction to Powershell**
- [ ] **Domain Enumeration (Attacks and Defense)**
- [ ] **Trust and Privileges Mapping**
- [ ] **Local Privilege Escalation**
- [ ] **Credential Replay Attacks (Over-PassTheHash, Token Replay etc.)**
- [ ] **Domain Privilege Escalation (Attacks and Defense)**
- [ ] **Dumping System and Domain Secrets**
- [ ] **Kerberos Attacks and Defense (Golden, silver tickets and more)**
- [ ] **Abusing Cross Forest Trusts (Attacks and Defense)**
- [ ] **Delegation Issues**
- [ ] **Persistence Techniques**
- [ ] **Abusing SQL Server Trusts in an AD Environment**
- [ ] **Bypassing Defenses**

# **Our End Goal**

- [ ] **Basic Prior Knowledge of Active Directory is needed**
- [ ] **Demonstrate how an attack can be executed and then have learning objective to practice what we have learnt**
- [ ] **The lab focuses on real world red team operations using built-in tools and focusing on functionality abuse**
- [ ] **No exploits and exploitation framework is needed**
- [ ] **We start from a foothold box as a normal domain user to domain admins**


# **Philosophy of This Course**

- [ ] **We will emulate an adversary  who has  a foothold machine on the target domain**
- [ ] **We will not use any exploit**
- [ ] **We will try to abuse functionality and features which are rarely patched**
- [ ] **We try to use built-in tools and avoid touching disk on any target and will not use exploit framework throughout the lessons**

# **What is Active Directory**

- [ ] A directory Service used to manage windows Network
- [ ] Stores information about objects on the network and makes it easily accessible by available users and admins
- [ ] Enables Centralized, secure management of an entire network across a building, a city or multiple locations throughout the world

# **Active Directory Components**

- [ ] Schema - Defines objects and their attributes
- [ ] Query and index mechanism - Provides searching and publication of objects and their properties
- [ ] Global catalog - Contains information about every object in the directory
- [ ] Replication service - Distribute information across domain controllers



![](https://i.imgur.com/gurz65j.png)


# **Active Directory Structure**

- [ ] Forests, domains and Organization units are the basic building blocks of active directory structure

![](https://servergeeks.files.wordpress.com/2012/10/ad-1.jpg)


# **What is Powershell?**


- [ ] Provides access to almost everything in a windows platform and Active Directory environment
- [ ] More useful for an attacker
- [ ] Provides the capability of running powerful scripts completely from memory making it ideal for foothold shells/boxes
- [ ] Easy to learn and really powerful
- [ ] Based on **.NET** framework and is tightly integrated with windows


# **Powershell Help System**


- Show help message and exit

```powershell
$ Get-Help
$ Help
$ -?
```

- supports wildcard.
- Comes with various options and filters.
- Get help for conceptual topics -:

```powershell
$ Get-Help About_<topic>
```


- List everything about the help topics 

```powershell
$ Get-Help *
```

- List everything that contains the word, **process**

```powershell
$ Get-Help process
```

![](https://i.imgur.com/Xbqgted.png)


- Update help system -:

```powershell
$ Update-Help
```

- List full help about a topic (Get-Item cmdlet in this case)

```powershell
$ Get-Help Get-Item -Full
```

- List examples of how to run a cmdlet (Get-Item cmdlet in this case)

```powershell
$ Get-Help Get-Item -Examples
```


# **What are Powershell Cmdlets**


- they are used to perform an action and a **.NET** object is returned as the output.
- They accept parameters for different operations
- They have aliases
- They are NOT executables and can be written with few lines of scripts

- To list all cmdlets do -:

```powershell
$ Get-Command -CommandType cmdlet
```


- There are many cmdlets from an attacker's perspective. for example `Get-process` lists processes running on a system.


![](https://i.imgur.com/r08A5q7.png)

**Reference -:** [https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-7.3](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-7.3)


# **Powershell Scripts**


- Uses cmdlets, native commands, functions, .NET, DLLs, Windows API and much more in a single **program**
- Powershell scripts are really powerful and could do much stuff in less lines
- Easy syntax

## **ISE**

- It is a GUI editor/scripting environment
- Tab completion, context-sensitive help, syntax highlighting, selective execution, in-line help are some useful features
- Comes with a handy console pane to run commands from the ISE

## **Execution Policy**

By default running powershell scripts on a box after foothold might be disabled on a machine due to **Execution Policy**

- It is not a security measure, it is present to prevent user from accidentally executing scripts.
- Several ways to bypass

```powershell
$ powershell -Executionpolicy bypass
$ powershell -c <cmd>
$ Powershell -encodedcommand
$ $env:PSExecutionPolicyPreference="bypass"
```


**Reference -:** [https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/)


# **Powershell Modules**

- **Powershell** also support modules
- A module can me imported with -:


```powershell
$ Import-Module <modulepath>
```

- All the commands in a module can be listed with -:

```powershell
$ Get-Command -Module <modulename>
```


# **Powershell Script Execution**


![](https://i.imgur.com/mnJMOA1.png)

# **Powershell and AD**

Powershell and Active Directory Integration

- [ADSI]
- .NET Classes
  `System.DirectoryServices.ActiveDirectory`
- Native Executable
- Powershell (.NET Classes and WMI)


# **Methodology - Assume Breach**

- Insider attack simulation is an important part of the assume breach execution cycle.
- The assume breach methodology will will be used on an AD environment and use internal access available with an adversary to perform further attacks


![](https://i.imgur.com/YBUBDUg.png)



# **Insider Attack Simulation**

- Recon - Gather IP address, hostname etc
- Domain Enumeration - Enumerate domains for shares, usernames etc
- Local Privilege Escalation - Moving from a lower level user to a higher level user
- Admin Reconnaissance - Once we have enough rights and knowledge we start to dig deep
- Lateral Movement - We start to check if we have access to any other machines with trusted privileges
- Domain Admin privileges
- Cross Trust Attacks - 

![](https://i.imgur.com/lu6j7Eh.png)

# **The lab Environment**


![](https://i.imgur.com/WTDzOE2.png)


