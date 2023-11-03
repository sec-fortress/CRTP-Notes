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
$ ()
```