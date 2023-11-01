# **Domain Enumeration Cont'd**

**Make sure to import/download both powerview and AD Module first from the links shown in Domain Enumeration - Part 1**



- Get a list of Computers in the Current domain

```powershell
# Powerview
$ Get-NetComputer
$ Get-NetComputer -OperatingSystem "*Server 2016*"
$ Get-NetComputer -Ping
$ Get-NetComputer -FullData 

# AD Module
$ Get-ADComputer -Filter * | select Name
$ Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' -Properties OperatingSystem | select Name,OperatingSystem
$ Get-ADComputer -Filter * -Properties DNSHostName | %(Test-Connection -Count 1 -ComputerName $_.DNSHostName)
$ Get-ADComputer -Filter * -Properties *
```

**_Example_ :**

![](https://i.imgur.com/vmBif3X.png)

- Get all the groups in the current domain

```powershell
# powerview
$ Get-NetGroup # provides list of all domain groups
$ Get-NetGroup -Domain <targetdomain>
$ Get-NetGroup -FullData # list all group properties in a domain

# AD Module
$ Get-ADGroup -Filter * | select Name
$ Get-ADGroup -Filter * -Properties *
```


- Get all groups containing the word "admin" in group name

```powershell
# powerview
$ Get-NetGroup *admin*
$ Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
```

- Get all the members of the Domain Admins and Enterprise Admins group

```powershell
# powerview
$ Get-NetGroupMember -GroupName "Domain Admins" -Recurse # Domain admins
$ Get-NetGroupMember -GroupName "Enterprise Admins" -Recurse # Enterprise admins

#test the below command also
#Get-NetGroupMember -GroupName "Domain Admins" -Properties * | select DistinguishedName,GroupCategory,GroupScope,Name,Members

# AD modules 
$ Get-ADGroupMember -Identity "Domain Admins" -Recursive # Domain admins
$ Get-ADGroupMember -Identity "Enterprise Admins" -Recursive # Enterprise admins
```

**_Example :_**


![](https://i.imgur.com/nYGNRo8.png)


> **Note :** The `IsGroup` property tells us that this two domain admins do not belong to any group, they stand alone as a normal user, Also if does not matter what the `MemberName` property is, if the `MemberSID` **RID** is available (ask google for more info!!), the **RID** is an identifier telling us who this person is, It might be an Administrator account having a different/changed member-name but if you check the **RID** and it is "500" then it is an Administrator account


- Get the group membership for a user :

Run whoami first to check for the current username

```powershell
$ whoami
marvel\fcastle
```

Now get the group membership with the username

```powershell
# powerview
$ Get-NetGroup -UserName "fcastle"

# AD Module
$ Get-ADPrincipalGroupMembership -Identity fcastle
```


> **Note :** If you see an **RID** then it is a builtin group, if no **RID** then it isn't a built in group


![](https://i.imgur.com/5k973U5.png)



- List all the local groups on a machine (needs administrator privs on non-dc machines)

```powershell
# powerview
$ Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -ListGroups
```


- Get members of all the local groups on a machine (needs administrator privs on non-dc machines)

```powershell
# powerview
$ Get-NetLocalGroup -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Recurse
```


- Get actively logged users on a computer (needs local admin rights on the target)

```powershell
# powerview
$ Get-NetLoggedon -ComputerName <servername>
```


- Get locally logged users on a computer (needs remote registry on the target - started be default on server OS)

```powershell
# powerview
$ Get-LoggedonLocal -ComputerName dcorp-dc.dollarcorp.moneycorp.local 
```


- Get the last logged user on a computer (needs administrative rights and remote registry on the target)

```powershell
# powerview
$ Get-LastLoggedon -ComputerName <servername>
```

- Find shares on hosts in current domain

```powershell
# powerview
$ Invoke-ShareFinder -Verbose # print all shares
$ Invoke-ShareFinder -Verbose -ExcludeStandard -ExcludePrint -ExcludeIPC # remove default shares from output

# there are high chances we can access any of the shares given as output
```


- Find sensitive files on computers in the domain

```powershell
# powerview
$ Invoke-FileFinder -Verbose 
```


- Get all fileservers of the domain

```powershell
# powerview
$ Get-NetFileServer -Verbose # looks for high valued target
```



3


