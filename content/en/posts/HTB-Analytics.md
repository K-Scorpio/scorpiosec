---
date: 2024-03-23T01:25:21-05:00
# description: ""
image: "/images/HTB-Analytics/Analytics.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Analytics"
type: "post"
---

* Platform: Hack The Box
* Link: [Analytics](https://app.hackthebox.com/machines/Analytics)
* Level: Easy
* OS: Linux
---

Analytics features a Metabase instance, which is an open-source business intelligence software. The target is vulnerable to `CVE-2023-38646` allowing command execution while unauthenticated. After enumerating the environment varialbles, SSH credentials are discovered and the root shell is gained via a kernel exploit.

Target IP Address - `10.10.11.233`

## Scanning 

```
nmap -sC -sV -oA nmap/Analytics 10.10.11.233
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-15 13:11 CDT
Nmap scan report for 10.10.11.233
Host is up (0.047s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.31 seconds
```

We are being redirected to `analytical.htb` which is added to the `/etc/hosts` file.

```
sudo echo "10.10.11.233 analytical.htb" | sudo tee -a /etc/hosts
```

## Enumeration

The website does not have anything interesting besides a login page that redirects me to `http://data.analytical.htb/`, I add the subdomain to my `/etc/hosts` file.

```
sudo echo "10.10.11.233 data.analytical.htb" | sudo tee -a /etc/hosts
```

Visiting the newly found subdomain leads to a login page for [Metabase](https://www.metabase.com/) which is an open-source business intelligence software.

![Metabase login page](/images/HTB-Analytics/signin-Metabase.png)

None of the default credentials worked.

![Metabase default credentials](/images/HTB-Analytics/Metabase-default-users.png)

Looking for Metabase vulnerabilities we find [CVE-2023-38646](https://www.cvedetails.com/vulnerability-list/vendor_id-19475/product_id-51231/Metabase-Metabase.html) allowing attackers to execute commands even while unauthenticated.

![CVE-2023-38646](/images/HTB-Analytics/cve-2023-38646.png)

A PoC for the exploit is found [here](https://github.com/m3m0o/metabase-pre-auth-rce-poc/tree/main). 

## Initial Foothold

The `setup-token` is retrieved by going to `http://data.analytical.htb/api/session/properties`.

![setup-token](/images/HTB-Analytics/Metabase-setup-token.png)

Craft a reverse shell with [Reverse Shell Generator](https://www.revshells.com/).

To run the exploit use 
 
```
python3 main.py -u http://[targeturl] -t [setup-token] -c "[command]"
```

Setup your listener, run the command

![Metabase exploit running](/images/HTB-Analytics/Metabase-xploit.png)

And catch a shell!

![Initial foothold](/images/HTB-Analytics/foothold.png)

After accessing the system no flag is found in this user home directory and trying to upgrade the shell fails. We seem to be in a constrained environment with a limited amount of services/utilities, probably a container. `0::/` is discovered in both `/proc/1/cgroup` and `/proc/self/cgroup` which is a strong indication that we are operating within a container. This typically signifies that the process with `PID 1` (usually the init process) is running within a `cgroup`, which is a common characteristic of containerized environments.

After finding and examining the content of the script `/app/run_metabase.sh`, it appears that the environment variables are manipulated via the functions `file_env` and `docker_setup_env`.

Running `env` leaks some credentials.

> The `env` command prints out the current environment variables set in the shell. Environment variables are key-value pairs that hold information about the environment in which a process is running.

![Leaked user credentials](/images/HTB-Analytics/user-credentials.png)

```
META_USER=metalytics
META_PASS=An4lytics_ds20223#
```
We log in SSH with them.

```
ssh metalytics@analytical.htb
```

And the user flag is found at `/home/metalytics/user.txt`.

![User flag](/images/HTB-Analytics/user-flag.png)

## Privilege Escalation

Searching for privilege escalation paths with `sudo -l` and enumerating the system manually give no leads at this point. Turning my attention to system kernel, I check its features with `uname -a && cat /proc/version`.

![System kernel version](/images/HTB-Analytics/system-features.png)

The system is running Ubuntu 22.04 and kernel version 6.2.0-25-generic. After searching for exploits I find [GameOver(lay)](https://www.crowdstrike.com/blog/crowdstrike-discovers-new-container-exploit/) featuring `CVE-2023-2640` and `CVE-2023-32629`. A PoC is available at this [Github account](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629/blob/main/exploit.sh).

After running the exploit, a root shell is obtained and the root flag is accessible at `/root/root.txt`.

![Root flag](/images/HTB-Analytics/root-flag.png)

Thanks for taking the time to check out my blog, this machine was fairly straightforward. Keep learning and practicing!
