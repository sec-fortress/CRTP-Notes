**Let think of scenario's where there where no service or paths, how can we escalate privileges in an active directory environment, what are other opportunities/ways we can go about it ??**

# **Kerberoast**

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


