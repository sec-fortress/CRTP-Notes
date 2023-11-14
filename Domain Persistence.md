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





