# **What is Domain Enumeration?**

- Once we have a foothold on target machine
- We will try to map out various entities, trusts, ACL's, relationships and privileges for the target domain
- The enumeration can be done by using Native executables and **.NET** classes in powershell

# **Enumerating Domain**

- To check DC, Parent, forest etc -:

```powershell
$ $ADClass = [System.DirectoryServices.AtciveDirectory.Domain]
$ $ADClass::GetCurrentomain()
```

To check current user privilege use -:

```powershell
$ whoami /priv
```

- To speed up things we can use Powerview -:

https://github.com/ZeroDayLab/PowerSploit/blob/master/Recon/PowerView.ps1


- The active directory powershell module comes in handy as it offers less detection by AV



https://4sysops.com/wiki/how-to-install-the-powershell-active-directory-module/



- To use ActiveDirectory module without installing **Remote Server Administration Tools** (RSAT), we can use `Import-Module` for the valid ActiveDirectory module DLL -:


https://github.com/samratashok/ADModule



## **Importing Modules to powershell**


### **Powerview module**

First of all download the powerview `.ps1` file from the link above

- change directory to where the module is located and run the powerview module

```powershell
$ cd C:\AD\Tools
$ ..\Powerview.ps1
```


**_Example :_**

![](https://i.imgur.com/64RjZRZ.png)


### **Active Directory Powershell module**


Download both files (`.dll` and `.psd1`) from senpai **samratashok** github handle from the link above

- Import `Microsoft.ActiveDirectory.Management.dll`

```powershell
$ cd C:\AD\Tools\ADmodule-master
$ Import-Module .\Microsoft.ActiveDirectory.Management.dll
```

- Import `ActiveDirectory.psd1`

```powershell
$ Import-Module .\ActiveDirectory\ActiveDirectory.psd1
```


**_Example :_**

![](https://i.imgur.com/ugWzM3j.png)


 **Sometimes we might need to bypass Antimalware Scan Interface (AMSI) before we can upload this modules, we look on how to do that (**On**) -:**


# **Bypassing PowerShell Security**


• We will use Invisi-Shell (https://github.com/OmerYa/Invisi-Shell) for
bypassing the security controls in PowerShell.

• The tool hooks the .NET assemblies
(System.Management.Automation.dll and System.Core.dll) to bypass
logging

• It uses a CLR Profiler API to perform the hook.

• "A common language runtime (CLR) profiler is a dynamic link library
(DLL) that consists of functions that receive messages from, and send
messages to, the CLR by using the profiling API. The profiler DLL is
loaded by the CLR at run time."


## **How to use**


Using Invisi-Shell


• With admin privileges run:

```powershell
$ RunWithPathAsAdmin.bat
```



• With non-admin privileges:


```powershell
$ RunWithRegistryNonAdmin.bat 

# Always use this one cos' it a bit silent
# Regardless of admin or non-admin privileges
```


• Type exit from the new `PowerShell` session to complete the clean-up.



# **Bypassing AV Signatures for PowerShell**


- We can always load scripts in memory and avoid detection using AMSI bypass
- How do we bypass signature based detection of on-disk PowerShell scripts by Windows Defender?
- We can use the AMSITrigger (https://github.com/RythmStick/AMSITrigger) tool to identify the exact part of a script that is detected.
- We can use DefenderCheck (https://github.com/t3hbb/DefenderCheck) to identify code and strings from a binary / file that Windows Defender may flag.
- Simply provide path to the script file to scan it:

```powershell
$ AmsiTrigger_x64.exe -i C:\AD\Tools\Invoke-PowerShellTcp_Detected.ps1
$ DefenderCheck.exe PowerUp.ps1
``` 

- For full obfuscation of PowerShell scripts, see Invoke-Obfuscation (https://github.com/danielbohannon/Invoke-Obfuscation). That is used for obfuscating the AMSI bypass in the course!

## **Steps to avoid signature based detection are pretty simple:**

1. Scan using AMSITrigger
2. Modify the detected code snippet
3. Rescan using AMSITrigger
4. Repeat the steps 2 & 3 till we get a result as **“AMSI_RESULT_NOT_DETECTED”** or
**“Blank”**.


**_Example -:_**


• Scan using `AMSITrigger`


![](https://i.imgur.com/h5qjJAE.png)


• Reverse the **"System.AppDomain"** string on line number 59


```powershell
$String = 'niamoDppA.metsyS’
$classrev = ([regex]::Matches($String,'.','RightToLeft') | ForEach
{$_.value}) -join ‘’
$AppDomain =
[Reflection.Assembly].Assembly.GetType("$classrev").GetProperty('Cur
rentDomain').GetValue($null, @())
```


• Check again with `AMSITrigger`


![](https://i.imgur.com/sC7X1g7.png)



> Make sure to check PDF for more examples



## **Enumerating Domain with Powerview and Active Directory Module**

**_Note :_** If one doesn't work then the other will, you know the difference between both as stated earlier 

- Get Current Domain

```powershell
$ Get-Domain # Powerview
$ Get-ADDomain # ActiveDirectory Module
```

- Get object of another domain

```Powershell
$ Get-Domain -Domain moneycorp.local # Powerview
$ Get-ADDomain -Identity moneycorp.local # AD Module
```


- Get domain SID for the current domain

```powershell
$ Get-DomainSID # powerview
$ (Get-ADDomain).DomainSID # AD module
```

- Get domain policy for the current domain

```powershell
$ Get-DomainPolicyData # Powerview
$ (Get-DomainPolicyData).systemaccess # Powerview
```


**_Example :_**


![](https://i.imgur.com/IXElkMe.png)


- Get domain policy for another domain

```powershell
$ (Get-DomainPolicy -domain moneycorp.local).systemaccess # powerview
```


- Get kerberos policy

```powershell
$ (Get-DomainPolicy)."Kerberos Policy" # powerview
```


> This is useful if we want to carry out an attack like **Golden tickets** as it makes sense to enumerate the **kerberos** policy first


- Get domain controllers for the current domain

```powershell
$ Get-DomainController # Powerview
$ Get-ADDomainController # AD module
```

- Get domain controllers for another domain

```powershell
$ Get-DomainController -Domain moneycorp.local # powerview
$ Get-ADDomainController -DomainName moneycorp.local -Discover # AD module 
```

> Once we have interesting information/details about the domain controller, we can start going after the users


- Get a list of users in the current domain

```powershell
# Powerview
$ Get-DomainUser
$ Get-DomainUser -Identity student1

# Active Directory Module
$ Get-ADUser -Filter * -Properties *
$ Get-ADUser -Identity student1 -Properties *
```

We can also sort out properties by Piping (|) what we want to the `select` command e.g -:


```powershell
# Powerview
# output only the "cn" property of each user data
$ Get-DomainUser | select cn

# AD modules
# output only the "Name" property from each user data
Get-ADUser -Filter * -Properties * | select Name
```


This are what we call properties -:



![](https://i.imgur.com/ycv4kYe.png)


- Get list of all properties for users in the current domain

```powershell
# Powerview
$ Get-DomainUser -Identity student1 -Properties *
$ Get-DomainUser -Properties samaccountname,logonCount

# AD Modules
$ Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name

$ Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```


Enumerating **properties** is a very important phase when performing Active Directory attacks, here are few properties  you should consider using in `powerview` -:

```powershell
# powerview
$ Get-DomainUser -Properties pwdlastset
$ Get-DomainUser -Properties badpwdcount
$ Get-DomainUser -Properties logoncount
```

**pwdlastset** -: The `pwdlastset` property stores the value of the date and time when the user's password was last changed. The older the time of change, The higher chance the account is a decoy, Take Note! 


![](https://i.imgur.com/apx9rn0.png)



**badpwdcount** -: The badPwdCount property specifies the number of times the user tried to log on to the account using an incorrect password. Any user with 0 count or low is definitely a decoy because they don't have incorrect logon attempts.


![](https://i.imgur.com/0qyltCP.png)

**logoncount** -: This attribute specifies the number of times that the account has successfully logged on. A value of 0 indicates that the value is unknown

![](https://i.imgur.com/Txuo0A4.png)


- Search for a particular string in a user's attributes :

```powershell
# Powerview
$ Get-DomainUser -LDAPFilter "Description=*built*" | Select name,Description

# AD Module
$ Get-ADUser -Filter 'Description -like "*built*"' -Properties Description | select name,Description
```

> **Note -:** We can not only use the keyword **"built"** when using the option `-SearchTerm`, we can search for keywords like **"Password"**, **"Username"** , **"Secrets"** etc.

