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


![](data:image/png;base64,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)



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


