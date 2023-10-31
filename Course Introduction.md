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

![Uploading file...3qztt]()



- Update help system -:

```powershell
$ Update-Help
```








 


