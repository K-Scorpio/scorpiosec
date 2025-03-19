---
date: 2024-03-23T01:25:21-05:00
# description: ""
image: "/images/HTB-Analytics/Analytics.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Analytics"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Analytics](https://app.hackthebox.com/machines/Analytics)
* Niveau: Facile
* OS: Linux
---

Analytics comporte une instance Metabase, qui est un logiciel open-source de "business intelligence". La cible est vulnérable au CVE-2023-38646 qui permet l'exécution de commandes en l'absence d'authentification. Après avoir énuméré les variables de l'environnement, des identifiants SSH sont découverts et le shell root est obtenu via un "kernel exploit".

L'adresse IP cible - `10.10.11.233`

## Scanning 

```
nmap -sC -sV -oA nmap/Analytics 10.10.11.233
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-15 13:11 CDT
Nmap scan report for 10.10.11.233
Host is up (0.047s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.31 seconds
```

Nous sommes redirigés vers `analytical.htb` qui est ajouté au fichier `/etc/hosts`.

```
sudo echo "10.10.11.233 analytical.htb" | sudo tee -a /etc/hosts
```

## Enumération

Le site ne présente rien d'intéressant à part une page de login qui me redirige vers `http://data.analytical.htb/`, j'ajoute le sous-domaine à mon fichier `/etc/hosts`.

```
sudo echo "10.10.11.233 data.analytical.htb" | sudo tee -a /etc/hosts
```

La visite du sous-domaine récemment identifié conduit à une page de connexion pour [Metabase](https://www.metabase.com/).

![Metabase login page](/images/HTB-Analytics/signin-Metabase.png)

Aucune des informations d'identification par défaut ne fonctionne.

![Metabase default credentials](/images/HTB-Analytics/Metabase-default-users.png)

En recherchant les vulnérabilités de Metabase, nous trouvons [CVE-2023-38646](https://www.cvedetails.com/vulnerability-list/vendor_id-19475/product_id-51231/Metabase-Metabase.html) permettant aux attaquants d'exécuter des commandes même lorsqu'ils ne sont pas authentifiés.

![CVE-2023-38646](/images/HTB-Analytics/cve-2023-38646.png)

Un PoC pour l'exploit se trouve [ici](https://github.com/m3m0o/metabase-pre-auth-rce-poc/tree/main). 

## Accès initial

Le `setup-token` est récupéré en allant sur `http://data.analytical.htb/api/session/properties`.

![setup-token](/images/HTB-Analytics/Metabase-setup-token.png)

Un shell inversé est créé à l'aide de [Reverse shell generator](https://www.revshells.com/).

Pour exécuter l'exploit, utilisez
 
```
python3 main.py -u http://[targeturl] -t [setup-token] -c "[command]"
```

Configurez votre listener et exécutez la commande.

![Metabase exploit running](/images/HTB-Analytics/Metabase-xploit.png)

Nous accédons au système par l'intermédiaire de l'utilisateur `Metabase`.

![Initial foothold](/images/HTB-Analytics/foothold.png)

Le fichier `user.txt` ne se trouve pas dans le répertoire personnel de cet utilisateur et la tentative de "upgrade" l'interpréteur de commandes échoue. Nous semblons être dans un environnement contraint avec un nombre limité de services, probablement un conteneur. `0::/` est découvert à la fois dans `/proc/1/cgroup` et `/proc/self/cgroup` ce qui est une forte indication que nous opérons dans un conteneur. Cela signifie typiquement que le processus avec le `PID 1` (habituellement le processus init) s'exécute dans un `cgroup`, ce qui est une caractéristique commune des environnements conteneurisés.

Après avoir trouvé et examiné le contenu du script `/app/run_metabase.sh`, il est évident que les variables d'environnement sont manipulées via les fonctions `file_env` et `docker_setup_env`.

L'exécution de `env` dévoile quelques informations d'identification.

> La commande `env` affiche les variables d'environnement actuelles définies dans l'interpréteur de commandes. Les variables d'environnement sont des paires clé-valeur qui contiennent des informations sur l'environnement dans lequel un processus s'exécute.

![Leaked user credentials](/images/HTB-Analytics/user-credentials.png)

```
META_USER=metalytics
META_PASS=An4lytics_ds20223#
```
Nous utilisons ces identifiants pour nous connecter avec SSH.

```
ssh metalytics@analytical.htb
```

Et le fichier `user.txt` se trouve dans `/home/metalytics/user.txt`.

![User flag](/images/HTB-Analytics/user-flag.png)

## Escalade des privilèges

La recherche de pistes d'escalade de privilèges avec `sudo -l` et l'énumération manuelle du système ne mènent à rien pour l'instant. Portant mon attention sur le noyau du système, je vérifie ses caractéristiques avec `uname -a && cat /proc/version`.

![System kernel version](/images/HTB-Analytics/system-features.png)

Le système fonctionne sous Ubuntu 22.04 et la version du noyau 6.2.0-25-generic. Après avoir cherché des attaques, je découvre [GameOver(lay)](https://www.crowdstrike.com/blog/crowdstrike-discovers-new-container-exploit/) avec les `CVE-2023-2640` et `CVE-2023-32629`. Un PoC est disponible sur ce [compte Github](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629/blob/main/exploit.sh).

Après l'exécution de l'exploit, un shell root est obtenu et le fichier `root.txt` est accessible dans `/root/root.txt`.

![Root flag](/images/HTB-Analytics/root-flag.png)

Merci d'avoir visité mon blog!
