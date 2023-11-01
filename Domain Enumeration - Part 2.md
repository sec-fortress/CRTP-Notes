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

- Get all the members of the Domain Admins group

```powershell
# powerview
$ Get-NetGroupMember -GroupName "Domain Admins" -Recurse

# AD modules 
$ Get-ADGroupMember -Identity "Domain Admins" -Recursive
```

**_Example :_**


![](https://i.imgur.com/nYGNRo8.png)


> **Note :** The `IsGroup` property tells us that this two domain admins do not belong to any group, they stand alone as a normal user, Also if does not matter what the `MemberName` property is, if the `MemberSID` **RID** is available (google!!), the **RID** is an identifier telling us who this person is, also it is a very significant number and can only be seen with one user


