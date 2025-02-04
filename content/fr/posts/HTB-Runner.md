---
date: 2024-08-22T19:24:15-05:00
# description: ""
image: "/images/HTB-Runner/Runner.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Runner"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Runner](https://app.hackthebox.com/machines/Runner)
* Niveau: Moyen
* OS: Linux
---

Runner débute avec un site web présentant des solutions CI/CD. Grâce à l'énumération des sous-domaines, nous découvrons une instance TeamCity vulnérable (CVE-2023-42793), ce qui nous permet d'y accéder. Une archive de sauvegarde téléchargée depuis cette instance révèle une clé SSH privée et des hachages de mots de passe. En utilisant la clé SSH, nous obtenons un accès initial et récupérons le fichier `user.txt`. Après l'énumération du system cible nous trouvons un autre sous-domaine hébergeant une instance de Portainer.io, à laquelle nous accédons en utilisant les informations d'identification récupérées précédemment. L'escalade des privilèges est réalisée en exploitant un montage bind, permettant l'accès au répertoire racine de la machine cible via le conteneur.

Addresse IP cible - `10.10.11.13`

## Balayage 

> J'utilise un script pour la phase de balayage, vous pouvez le trouver [ici](https://github.com/K-Scorpio/scripts-collection/blob/main/nmap_scan.sh) . Les commandes que j'utilise sont souvent les mêmes, ce qui me facilite la tâche.

```
./nmap_scan.sh 10.10.11.13 Runner
```

**Résultats**

```shell
Running detailed scan on open ports: 22,80,8000
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-22 19:23 CDT
Nmap scan report for 10.10.11.13
Host is up (0.054s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http        nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://runner.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8000/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.64 seconds
```

Le scan détecte trois ports ouverts : 22 (SSH), 80 (HTTP avec Nginx), et 8000 (nagios-nsca).
Il y a aussi une redirection vers `runner.htb`.

Mettons à jour notre fichier hosts.

```
sudo echo "10.10.11.13 runner.htb" | sudo tee -a /etc/hosts
```

## Enumération

Nous découvrons le site web d'une entreprise proposant des solutions CI/CD à l'adresse `http://runner.htb`. Ce site ne présente aucune fonctionnalité que nous pourrions exploiter et l'énumération des répertoires ne produit rien d'utile pour `http://runner.htb`.

![Runner website](/images/HTB-Runner/runner-website.png)

Avec l'énumération des sous-domaines, nous trouvons `teamcity` que nous ajoutons à notre fichier `/etc/hosts`.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 100 -u http://runner.htb -H "Host: FUZZ.runner.htb" -ic -fs 154
```

![subdomain enumeration](/images/HTB-Runner/ffuf-subdomain.png)

## Accès Initial

`http://teamcity.runner.htb` mène à un formulaire de connexion pour TeamCity avec la version `2023.05.3`. En recherchant les vulnérabilités, nous découvrons le [CVE-2023-42793](https://www.exploit-db.com/exploits/51884) , qui nous permet de créer un nouvel utilisateur avec des privilèges administratifs.

![teamcity subdomain](/images/HTB-Runner/teamcity-runner.png)

En utilisant ce [PoC](https://github.com/H454NSec/CVE-2023-42793), nous exploitons la vulnérabilité et créons un nouvel utilisateur admin avec les identifiants `H454NSec5438:@H454NSec`.

```
python3 CVE-2023-42793.py -u http://teamcity.runner.htb
```
![Poc in use](/images/HTB-Runner/Poc_use.png)

Nous nous connectons à l'instance TeamCity.

![teamcity subdomain login](/images/HTB-Runner/teamcity-admin-login.png)

Dans la section `Administration`, sous `Server Administration` nous trouvons une option `Backup` et nous utilisons le bouton `Start Backup` pour démarrer le processus.

![teamcity backup](/images/HTB-Runner/backup.png)

![teamcity backup start](/images/HTB-Runner/backup-start.png)

Une fois l'opération terminée, nous pouvons télécharger l'archive en cliquant sur le lien.

![teamcity backup archive](/images/HTB-Runner/backup-file.png)

> Après l'extraction de l'archive, nous modifions les permissions sur tous les fichiers afin d'y accéder.

```
unzip TeamCity_Backup_20240421_214500.zip && chmod -R 744 *
```

![teamcity backup files](/images/HTB-Runner/backup-files.png)

Nous trouvons une clé SSH dans `config/projects/AllProjects/pluginData/ssh_keys/id_rsa` mais pour l'instant nous ne savons pas à quel utilisateur elle appartient.

Nous obtenons aussi une liste d'utilisateurs et leurs hachage de mot de passe dans `database_dump/users`.

> `admin` et `matthew` sont les utilisateurs intéressants ici, les autres ont été créés par le PoC.

![user hashes](/images/HTB-Runner/db-users-hashes.png)

Le hash de `admin` (john) ne peut pas être craqué mais nous récupérons avec succès le mot de passe de `matthew` qui est `piper123`.

```
hashcat -a 0 -m 3200 matthew-hash.txt /usr/share/wordlists/rockyou.txt
```

![user matthew hash cracked](/images/HTB-Runner/matthew-pwd.png)

En utilisant la clé SSH trouvée précédemment, nous nous connectons en tant que `john` via SSH.

![SSH admin login](/images/HTB-Runner/ssh-login-admin.png)

```
ssh -i id_rsa john@runner.htb
```

![john user](/images/HTB-Runner/john-user.png)

Le fichier `user.txt` se trouve dans `/home/john/user.txt`.

## Elévation de Privilèges

En utilisant `linpeas` pour l'énumération du système, nous identifions un autre sous-domaine que nous n'avions pas pu découvrir auparavant, `portainer-administration.runner.htb`.

![subdomain internal](/images/HTB-Runner/subdomain-intern.png)

À l'adresse `http://portainer-administration.runner.htb/` nous sommes face à une autre page de connexion pour `portainer.io`. Les identifiants `matthew:piper123` sont valides ici!

![portainer login](/images/HTB-Runner/portainer-login.png)

Nous ne sommes pas en mesure de modifier le conteneur actuel, mais nous pouvons créer de nouveaux volumes.

1. Sélectionnez le conteneur `primary` et vous obtiendrez un menu déroulant dans le panneau de gauche.

![container primary](/images/HTB-Runner/container-primary.png)

2. Cliquez sur `Volumes` puis sur `Add volume` dans le coin droit.

![add volume for conmtainer](/images/HTB-Runner/add-volume.png) 

3. Lors de la création du volume, utilisez l'option `+ add driver option` et ajoutez les trois options ci-dessous afin de créer un volume racine.

![volume options](/images/HTB-Runner/volume-options.png) 

* L'option **device** spécifie le chemin source sur le système hôte qui sera monté dans le conteneur. Dans ce cas, il est défini sur `/`, qui est le répertoire racine de la machine hôte.
* L'option **o** signifie «options» et, dans ce contexte, `bind` fait référence à un «montage bind».
* L'option **type** définit le type de montage utilisé. Lorsqu'elle est définie par `none`, elle indique qu'aucun type de système de fichiers spécifique n'est utilisé pour ce montage.

4. Dans `Containers` créez un nouveau container avec `ubuntu` comme nom d'image, assurez-vous de cocher `Interactive & TTY (-i -t)` pour `Console` dans `Advanced container settings`.

![portainer console](/images/HTB-Runner/console-interactive.png) 

Sous `Volumes` cliquez sur `+map additional volume`, pour `container` entrez `/mnt/root` et sélectionnez le volume que vous venez de créer, enfin déployez le conteneur.

![Advanced container settings, volume section](/images/HTB-Runner/advanced_container_settings_volume.png) 

5. Vous devriez maintenant avoir un nouveau conteneur en cours d'exécution. 

![created container](/images/HTB-Runner/myContainer.png) 

Sélectionnez-le et cliquez sur `Console` puis sur `Connect`.

![container status](/images/HTB-Runner/console-container.png) 

6. Vous vous connecterez en tant que root et trouverez `root.txt` dans `/mnt/root/root/`.

![Root flag](/images/HTB-Runner/root-flag.png) 

### Explication du processus d'exploitation

Cette technique d'escalade de privilèges exploite la fonctionnalité de liaison de volume de Docker, en particulier en utilisant Portainer.io comme outil de gestion.

Le volume en question est monté sur le conteneur avec le système de fichiers racine (`/`) comme périphérique et `bind` comme type. Ceci signifie que le système de fichiers racine de l'hôte est monté sur le conteneur.

Lorsque nous créons un nouveau conteneur et que nous montons ce volume sur `/mnt/root`, cela donne essentiellement au conteneur l'accès au répertoire racine de la machine hôte.

Puisque le volume est lié au répertoire racine de l'hôte, et que nous nous sommes connectés au conteneur avec une console interactive, nous avons un accès direct au système de fichiers de l'hôte depuis le conteneur.

Par défaut, les conteneurs s'exécutent généralement en tant que root dans leur propre environnement, et grâce au montage avec `bind`, cet utilisateur root à l'intérieur du conteneur a accès au répertoire racine de l'hôte. Ainsi, nous pouvons manipuler ou exécuter des fichiers sur le système hôte comme si nous étions l'utilisateur racine de l'hôte, ce qui nous permet de contrôler totalement la machine hôte.

## Mots de Fin

Je ne suis pas très compétent en matière d'exploitation de conteneurs, mais cette box m'a incité à en apprendre davantage sur le sujet. Vous trouverez ci-dessous une liste non exhaustive des ressources que j'ai utilisées.

Tout d'abord, il faut savoir ce qu'est Docker et à quoi il sert - [Docker Crash Course](https://www.youtube.com/watch?v=pg19Z8LL06w&ab_channel=TechWorldwithNana)

Ensuite, nous pourrons nous familiariser avec les méthodes d'exploitation de Docker:

* [Lesson 4: Hacking Containers Like A Boss](https://www.practical-devsecops.com/lesson-4-hacking-containers-like-a-boss/)
* [Hacking into your containers, and how to stop it!](https://www.youtube.com/watch?v=IuiJdQsty5k&ab_channel=Docker)
* [Pentesting Docker on HackTricks](https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker#privilege-escalation)

Merci d'avoir pris le temps de lire mon article, j'espère qu'il vous a été utile !
