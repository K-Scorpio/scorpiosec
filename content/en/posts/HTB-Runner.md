---
date: 2024-08-22T19:24:15-05:00
# description: ""
image: "/images/HTB-Runner/Runner.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Runner"
type: "post"
---

* Platform: Hack The Box
* Link: [Runner](https://app.hackthebox.com/machines/Runner)
* Level: Medium
* OS: Linux
---

Runner starts with a basic website offering CI/CD solutions. Through subdomain enumeration, we uncover a vulnerable TeamCity instance (CVE-2023-42793), granting us access. A backup archive downloaded from this instance reveals a private SSH key and password hashes. Using the SSH key, we gain an initial foothold and retrieve the user flag. Further exploration uncovers another subdomain hosting a Portainer.io instance, which we access using the previously recovered credentials. Privilege escalation is achieved by exploiting a bind mount, allowing access to the root directory of the target machine via the container.

Target IP address - `10.10.11.13`

## Scanning 

> I am using a script for the scanning phase, you can find it [here](https://github.com/K-Scorpio/scripts-collection/blob/main/nmap_scan.sh). I found myself always running the same commands, so it makes things easier for me.

```
./nmap_scan.sh 10.10.11.13 Runner
```

**Results**

```shell
Running detailed scan on open ports: 22,80,8000
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-22 19:23 CDT
Nmap scan report for 10.10.11.13
Host is up (0.054s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http        nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://runner.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8000/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.64 seconds
```

The scan discovers three open ports 22 (SSH), 80 (HTTP with Nginx), and 8000 (nagios-nsca).
There is also a redirection to `runner.htb`.

Let's update our hosts file.

```
sudo echo "10.10.11.13 runner.htb" | sudo tee -a /etc/hosts
```

## Enumeration

We find a company website offering CI/CD solutions at `http://runner.htb`. This website does not present any features that we can exploit and directory enumeration does not return anything useful for `http://runner.htb`.

![Runner website](/images/HTB-Runner/runner-website.png)

Moving on to subdomain enumeration, we find `teamcity` which we add to our `/etc/hosts` file.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 100 -u http://runner.htb -H "Host: FUZZ.runner.htb" -ic -fs 154
```

![subdomain enumeration](/images/HTB-Runner/ffuf-subdomain.png)

## Initial Foothold

`http://teamcity.runner.htb` leads to a login form for TeamCity with version `2023.05.3`. Researching for specific vulnerabilities we discover [CVE-2023-42793](https://www.exploit-db.com/exploits/51884), allowing us to create a new user with administrative privileges.

![teamcity subdomain](/images/HTB-Runner/teamcity-runner.png)

Using this [PoC](https://github.com/H454NSec/CVE-2023-42793) we exploit the vulnerability and create a new admin user with the credentials `H454NSec5438:@H454NSec`.

```
python3 CVE-2023-42793.py -u http://teamcity.runner.htb
```
![Poc in use](/images/HTB-Runner/Poc_use.png)

We now login into the TeamCity instance.

![teamcity subdomain login](/images/HTB-Runner/teamcity-admin-login.png)

In the `Administration` section, under `Server Administration` we find a `Backup` option and we use the `Start Backup` button to begin the process.

![teamcity backup](/images/HTB-Runner/backup.png)

![teamcity backup start](/images/HTB-Runner/backup-start.png)

After it's done we can download the archive by clicking on the link.

![teamcity backup archive](/images/HTB-Runner/backup-file.png)

> After unzipping the archive I couldn't access the files because they didn't have any permissions set, so I changed them recursively on all files.

```
unzip TeamCity_Backup_20240421_214500.zip && chmod -R 744 *
```

We end up with several files and folders.

![teamcity backup files](/images/HTB-Runner/backup-files.png)

We find a private SSH key at `config/projects/AllProjects/pluginData/ssh_keys/id_rsa` but as of now we don't know which user it belongs to.

We also find a list of users and their password hashes at `database_dump/users`.

> `admin` and `matthew` are the interesting users here, the other users were created by our exploit.

![user hashes](/images/HTB-Runner/db-users-hashes.png)

The hash for `admin` (john) couldn't be cracked but we successfully recovered the password for `matthew` which is `piper123`.

```
hashcat -a 0 -m 3200 matthew-hash.txt /usr/share/wordlists/rockyou.txt
```

![user matthew hash cracked](/images/HTB-Runner/matthew-pwd.png)

Using the previously found SSH key, we are able to login as `john` via SSH.

![SSH admin login](/images/HTB-Runner/ssh-login-admin.png)

```
ssh -i id_rsa john@runner.htb
```

![john user](/images/HTB-Runner/john-user.png)

The user flag is at `/home/john/user.txt`.

## Privilege Escaltion

Using `linpeas` for the system enumeration we find another subdomain that we were unable to discover previously, `portainer-administration.runner.htb`.

![subdomain internal](/images/HTB-Runner/subdomain-intern.png)

At `http://portainer-administration.runner.htb/` we are presented with another login form for `portainer.io`. The credentials `matthew:piper123` work here!

![portainer login](/images/HTB-Runner/portainer-login.png)

We are unable to modify the current container but we can create new volumes.

1. Select the container `primary` and you will get a drop down menu in the left pane

![container primary](/images/HTB-Runner/container-primary.png)

2. Click on `Volumes` then `Add volume` in the right corner

![add volume for conmtainer](/images/HTB-Runner/add-volume.png) 

3. When creating the volume use the `+ add driver option` and add the three options below in order to create a root volume.

![add driver option button](/images/HTB-Runner/add_driver_options.png) 

![volume options](/images/HTB-Runner/volume-options.png) 

* The **device** option specifies the source path on the host system that will be mounted into the container. In this case, it's set to `/`, which is the root directory of the host machine.
* The **o** option stands for "options," and in this context, `bind` refers to a "bind mount."
* The **type** option defines the type of mount being used. When set to `none`, it indicates that no specific file system type is being used for this mount.

4. In `Containers` we create a new container with `ubuntu` as the image name, make sure to check `Interactive & TTY (-i -t)` for `Console` under `Advanced container settings`. 

![portainer console](/images/HTB-Runner/console-interactive.png) 

Under `Volumes` click on `+map additional volume`, for `container` enter `/mnt/root` and select the volume you just created, finally deploy the container.

![Advanced container settings, volume section](/images/HTB-Runner/advanced_container_settings_volume.png) 

5. You should now have a new running container 

![created container](/images/HTB-Runner/myContainer.png) 

Select it and click on `Console` and then `Connect`.

![container status](/images/HTB-Runner/console-container.png) 

6. You will login as root and the root flag is at `/mnt/root/root/root.txt`.

![Root flag](/images/HTB-Runner/root-flag.png) 

### Why does this work?

This privilege escalation technique takes advantage of the volume binding feature in Docker, specifically using Portainer.io as a management tool.

The volume in question is mounted to the container with the root file system (`/`) as its device and `bind` as the type. This means that the root file system of the host is being mounted to the container.

When we create a new container and mount this volume at `/mnt/root`, it essentially gives the container access to the root directory of the host machine.

Since the volume is bound to the host's root directory, and we've logged into the container with an interactive console, we have direct access to the host’s file system from within the container.

By default, containers typically run as root inside their own environment, and because of the bind mount, this root user inside the container effectively has access to the root directory of the host. This allows us to manipulate or execute files on the host system as if we were the root user of the host, leading to full control over the host machine.

## Closing Words

I am not proficient with container hacking but this box prompted me to learn more about it. Below you will find a non-exhaustive list of the resources I used.

First we need to know what is Docker and what it is used for - [Docker Crash Course](https://www.youtube.com/watch?v=pg19Z8LL06w&ab_channel=TechWorldwithNana).

Then we can learn about Docker exploitation:

* [Lesson 4: Hacking Containers Like A Boss](https://www.practical-devsecops.com/lesson-4-hacking-containers-like-a-boss/)
* [Hacking into your containers, and how to stop it!](https://www.youtube.com/watch?v=IuiJdQsty5k&ab_channel=Docker)
* [Pentesting Docker on HackTricks](https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker#privilege-escalation)

I hope you enjoyed this write up, thanks for taking the time to read it!
