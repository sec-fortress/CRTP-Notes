# **Domain Enumeration Cont'd - Trusts**

## **What is Trusts**

- Trust is a relationship between two domains or forests which allows users of one domain or forest to access resources in the other domain or forest.
- Trust can be automatic (parent-child, same forest etc.) or established (forest, external).
- Trusted Domain Objects (TDOs) represent the trust relationships in a domain

## **Trust Direction**

**_One-Way Trust -:_**

![](https://i.imgur.com/rty5NIl.png)

**_Two-Way Trust -:_**

![](https://i.imgur.com/XJ1nq9T.png)


**For More Information On Trusts, View Learning Material**

- Get a list of all domain trusts for the current domain

```powershell
# Powerview
$ Get-NetDomainTrust
$ Get-NetDomainTrust -Domain <TargetName>

# AD Module
$ Get-ADTrust
$ Get-ADTrust -Identity <TargetName>
```


- Get details about the current forest

```powershell
# powerview
$ Get-NetForest
$ Get-NetForest -Forest eurocorp.local

# AD Module
$ Get-ADForest
$ Get-ADForest -Identity eurocorp.local
```


- Get all domains in the current forest

```powershell
# powerview
$ Get-NetForestDomain
$ Get-NetForestDomain -Forest eurocorp.local

# AD Module
$ (Get-ADForest).Domains
```

- Get all global catalogs for the current forest

```powershell
# powerview
$ Get-NetForestCatalog
$ Get-NetForestCatalog -Forest eurocorp.local
```

- Map trusts of a forest

```powershell
# powerview
$ Get-NetForestTrust
$ Get-NetForestTrust -Forest eurocorp.local
```


# **Learning Objective 4**

- Enumerate all domains in the moneycorp.local forest.
- Map the trusts of the dollarcorp.moneycorp.local domain.
- Map external trust in the moneycorp.local forest.
- Identify external trusts of dollarcorp domain. Can you enumerate trusts for a trusting forest ?


## **Solutions**

**_Coming Soon_**

> **Note :** In this section, before now, we have only be querying the domain controller for information, No other machine was been communicated to.




# **Domain Enumeration Cont'd - User Hunting**

Note that this enumeration is much more more noisy than any we've been doing before now 


- Find all machines on the current domain where the current user has local admin access

```powershell
# powerview
$ Find-LocalAdminAccess -Verbose
```

> **Note :** This function queries the DC of the current or provided domain for a list of computers `(Get-NetComputer)` and then use multi-threaded `Invoke-CheckLocalAdminAccess` on each machine


