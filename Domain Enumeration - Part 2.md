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



