---
date: 2025-01-13T21:00:11-06:00
# description: ""
image: "/images/THM-SilverPlatter/SilverPlatter.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Silver Platter"
type: "post"
---

* Platform: TryHackMe
* Link: [Silver Platter](https://tryhackme.com/r/room/silverplatter)
* Level: Easy
* OS: Linux
---

Silver Platter is a straightforward machine that begins with `http` services running on two different ports, one of which reveals a potential username. Through enumeration, we discover a Silverpeas login page and use a custom password list to identify valid credentials, granting access to the dashboard. Further research helps us find `CVE-2023-47323`, which we use to obtain another set of credentials and an initial foothold. The user, being part of the `adm` group, has access to system logs where another password is found. This allows us to pivot to a different user. With unrestricted `sudo` privileges on the new account, obtaining root access is effortless.

## Scanning

```
nmap -sC -sV -oA nmap/SilverPlatter [IP_ADDRESS]
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-13 23:13 CST
Nmap scan report for 10.10.49.248
Host is up (0.26s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 1b:1c:87:8a:fe:34:16:c9:f7:82:37:2b:10:8f:8b:f1 (ECDSA)
|_  256 26:6d:17:ed:83:9e:4f:2d:f6:cd:53:17:c8:80:3d:09 (ED25519)

80/tcp   open  http       nginx 1.18.0 (Ubuntu)
|_http-title: Hack Smarter Security
|_http-server-header: nginx/1.18.0 (Ubuntu)

8080/tcp open  http-proxy
|_http-title: Error
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Tue, 14 Jan 2025 05:14:16 GMT
|     <html><head><title>Error</title></head><body>404 - Not Found</body></html>
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SMBProgNeg, SSLSessionReq, Socks5, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|     Connection: close
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Tue, 14 Jan 2025 05:14:14 GMT
|_    <html><head><title>Error</title></head><body>404 - Not Found</body></html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=1/13%Time=6785F2A7%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20clos
SF:e\r\nContent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Tu
SF:e,\x2014\x20Jan\x202025\x2005:14:14\x20GMT\r\n\r\n<html><head><title>Er
SF:ror</title></head><body>404\x20-\x20Not\x20Found</body></html>")%r(HTTP
SF:Options,C9,"HTTP/1\.1\x20404\x20Not\x20Found\r\nConnection:\x20close\r\
SF:nContent-Length:\x2074\r\nContent-Type:\x20text/html\r\nDate:\x20Tue,\x
SF:2014\x20Jan\x202025\x2005:14:14\x20GMT\r\n\r\n<html><head><title>Error<
SF:/title></head><body>404\x20-\x20Not\x20Found</body></html>")%r(RTSPRequ
SF:est,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nC
SF:onnection:\x20close\r\n\r\n")%r(FourOhFourRequest,C9,"HTTP/1\.1\x20404\
SF:x20Not\x20Found\r\nConnection:\x20close\r\nContent-Length:\x2074\r\nCon
SF:tent-Type:\x20text/html\r\nDate:\x20Tue,\x2014\x20Jan\x202025\x2005:14:
SF:16\x20GMT\r\n\r\n<html><head><title>Error</title></head><body>404\x20-\
SF:x20Not\x20Found</body></html>")%r(Socks5,42,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Ge
SF:nericLines,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x2
SF:00\r\nConnection:\x20close\r\n\r\n")%r(Help,42,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r
SF:(SSLSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length
SF::\x200\r\nConnection:\x20close\r\n\r\n")%r(TerminalServerCookie,42,"HTT
SF:P/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\
SF:x20close\r\n\r\n")%r(TLSSessionReq,42,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(Kerberos
SF:,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r\nConn
SF:ection:\x20close\r\n\r\n")%r(SMBProgNeg,42,"HTTP/1\.1\x20400\x20Bad\x20
SF:Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(LPD
SF:String,42,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x200\r
SF:\nConnection:\x20close\r\n\r\n")%r(LDAPSearchReq,42,"HTTP/1\.1\x20400\x
SF:20Bad\x20Request\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\
SF:n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 138.59 seconds
```

We have three open ports:
* 22 running SSH
* 80 running HTTP
* 8080 also running HTTP

## Enumeration

At `http://silverplatter.thm/` we find a cybersecurity website.

![Silver Platter website](/images/THM-SilverPlatter/silverplatter_website.png)

The contact page at `http://silverplatter.thm/#contact` gives us a possible username `scr1ptkiddy`. We also learn that [Silverpeas](https://www.silverpeas.org/) is running.

![Contact page](/images/THM-SilverPlatter/contact_page.png)

The directory brute forcing and subdomain enumeration are both unfruitful on port 80.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://silverplatter.thm/
```

![Gobuster on port 80](/images/THM-SilverPlatter/gobuster_80.png)

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://axlle.htb -H "Host: FUZZ.silverplatter.thm" -ic
```

![Ffuf on port 80](/images/THM-SilverPlatter/ffuf_80.png)

`http://silverplatter.thm:8080/` leads to a `404` error page.

![404 error page](/images/THM-SilverPlatter/404_error.png)

The enumeration for port 8080 shows `http://silverplatter.thm:8080/website/` but we cannot access it.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://silverplatter.thm:8080/
```

![gobuster on port 8080](/images/THM-SilverPlatter/gobuster_8080.png)

![forbidden page](/images/THM-SilverPlatter/forbidden.png)

Similarly `http://silverplatter.thm:8080/console` is also inaccessible.

![console page](/images/THM-SilverPlatter/8080_console.png)

Silverpeas usually runs on port 8080.

![silverpeas port](/images/THM-SilverPlatter/silverpeas_port.png)

We are able to access it at `http://silverplatter.thm:8080/silverpeas` where we find a login page.

![silverpeas login page](/images/THM-SilverPlatter/silverpeas_login.png)

## Initial Foothold

We cannot use the `rockyou.txt` list since the room description tells us that these passwords are excluded. So we will attempt to make a password list with `cewl`.

```
cewl http://silverplatter.thm > passwords.txt
```

![password list](/images/THM-SilverPlatter/pwds_list.png)

We can use hydra for the brute force attack using a login request to get the post-form name.

![login request](/images/THM-SilverPlatter/login_request.png)

```
hydra -l scr1ptkiddy -P pwds.txt silverplatter.thm -s 8080 http-post-form "/silverpeas/AuthenticationServlet:Login=^USER^&Password=^PASS^&DomainId=0:F=Login or password incorrect"
```

![brute force attack with Hydra](/images/THM-SilverPlatter/hydra_creds.png)

Using these credentials we are able to login.

![silverpeas dashboard](/images/THM-SilverPlatter/silverpeas_dashboard.png)

Click on `1 unread notification` to read the message. 

![inbox message](/images/THM-SilverPlatter/message_url.png)

[This article](https://rhinosecuritylabs.com/research/silverpeas-file-read-cves/) from Rhino Security Labs details vulnerabilities about Silverpeas. 

Ater reading through the CVEs carefully we see that [CVE-2023-47323](https://github.com/RhinoSecurityLabs/CVEs/tree/master/CVE-2023-47323) can be exploited to read all messages by just changing the `ID` value.

![Read messages vulnerability](/images/THM-SilverPlatter/read_message_cve.png)

Changing the value to `6`, we recover the credentials for the user `tim`.

![tim credentials](/images/THM-SilverPlatter/tim_creds.png)

```
Username: tim

Password: cm0nt!md0ntf0rg3tth!spa$$w0rdagainlol
```

We login via SSH and recover the user flag.

![user flag](/images/THM-SilverPlatter/user_flag.png)

### Shell as Tyler

Checking `/etc/passwd` we notice another user `tyler`.

![user list](/images/THM-SilverPlatter/user_list.png)

With linpeas we learn that the current user is part of the `adm` group. The members of this group are able to read logs on a system.

![adm group](/images/THM-SilverPlatter/adm_group.png)

Let's look for passwords in the log files.

```
grep -Ri "password" 2>/dev/null
```

![find password in logs](/images/THM-SilverPlatter/pwd_find.png)

Near the end of the output we find a database password: `_Zd_zx7N823/`.

![database password](/images/THM-SilverPlatter/db_pwd.png)

Using it we are able to switch to `tyler`.

![tyler account](/images/THM-SilverPlatter/switch_to_tyler.png)

## Privilege Escalation

With `sudo -l` we discover that `tyler` has unrestricted `sudo` access on the system. 

![sudo privileges command](/images/THM-SilverPlatter/sudo-l_cmd.png)

With a simple `sudo su` command we become root and read the root flag.

