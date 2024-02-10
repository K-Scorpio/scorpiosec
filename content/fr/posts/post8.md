+++
title = "Comment restaurer une clé USB bootable pour une utilisation normale sur Linux et Windows"
date = 2024-02-09T14:55:37-06:00
draft = false
toc = true
tags = ['Troubleshooting']
categories = ['Personal']
+++

## Introduction 

Après avoir transformé une clé USB en clé USB amorçable, elle devient inutilisable et ne peut plus transferrer de données. J'ai d'abord cru qu'il suffisait de supprimer tous les fichiers de la clé USB pour qu'elle retrouve son fonctionnement normal. Après avoir cherché en ligne un guide pour réinitialiser la clé USB, je n'ai pas trouvé de solution satisfaisante. J'ai donc décidé de créer un guide complet. Dans cet article, je vous expliquerai comment restaurer votre clé USB, que vous utilisiez Linux ou Windows.

## Sur Linux

Pour utiliser à nouveau la clé USB comme un périphérique de stockage normal, vous devez la formater, ce qui effacera toutes les données existantes. Sous Linux, on peut utiliser GParted pour le formatage.

**1. Commencez par lancer gparted (s'il n'est pas installé, vous pouvez l'installer avec `sudo apt install gparted`):**

```
sudo gparted
```

Vous pouvez utiliser le menu déroulant dans le coin supérieur droit pour passer d'un disque à l'autre. Le périphérique USB est souvent nommé `/dev/sdb`. Vous pouvez également identifier votre périphérique de stockage par l'espace en GiB.

![GParted Interface](/images/gparted1.png)

**2. Supprimez les partitions existantes répertoriées sur la clé USB**

Cliquez avec le bouton droit de la souris sur chaque partition existante sur la clé USB et sélectionnez "Delete". Je n'ai qu'une seule partition répertoriée sous le nom de `/dev/sdb1`. Si l'option "Supprimer" est grisée, cela signifie que vous devez d'abord démonter le périphérique ce qui peut se faire avec un clic droit sur le périphérique et en sélectionnant "Unmount" dans l'explorateur de fichiers.

**3. Créer une nouvelle table de partitions**

Après avoir supprimé toutes les partitions, cliquez sur le menu "Device" et sélectionnez "Create Partition Table".
Choisissez ensuite le type de table de partitions que vous souhaitez créer (généralement "msdos" pour MBR ou "gpt" pour GPT). Cliquez sur "Appliquer". (msdos fera l'affaire)

![GParted Create New Partition Table](/images/gparted2.png)

**4. Créer une nouvelle partition**

Créez maintenant une nouvelle partition dans l'espace non alloué. Cliquez avec le bouton droit de la souris sur l'espace non alloué, choisissez "New" (Nouveau), définissez le système de fichiers souhaité et cliquez sur "Add" (Ajouter). Cliquez sur le bouton vert pour "Apply All Operations" (Appliquer toutes les opérations). Vous devez utiliser le bouton vert de vérification chaque fois que vous voyez "1 operation pending" (1 opération en attente) en bas de l'écran.

![GParted Create a New Partition](/images/gparted3.png)

**5. Formatage réussi**

Vous devriez voir apparaître un écran indiquant que toutes les opérations ont été effectuées avec succès. Vous pouvez toutefois aller plus loin.

![GParted Operation Successful](/images/gparted4.png)

**6. Configuration du système de fichiers**

Dans mon cas, j'ai deux ordinateurs portables (Windows et Linux) et pour que les périphériques de stockage fonctionnent sur les deux systèmes, vous devez utiliser un type de système de fichiers compatible. Je recommande de formater votre périphérique en `exFAT` si vous voulez l'utiliser sur Windows et Linux. Si vous prévoyez de l'utiliser exclusivement sur un système Linux, choisissez `ext4` et pour les systèmes Windows `NTFS`.

Faites un clic droit sur la partition et survolez `Format to`, vous obtiendrez une liste de systèmes de fichiers, sélectionnez `exfat` et appuyez sur le bouton vert pour continuer. Fermez toutes les fenêtres une fois les opérations terminées et vous remarquerez dans la section `File System` que le périphérique utilise maintenant `exfat`.

![GParted Operation Successful](/images/gparted5.png)


![GParted Operation Successful](/images/gparted6.png)

Votre périphérique USB est maintenant prêt à être utilisé.

**7. Le périphérique ne s'affiche pas dans l'explorateur de fichiers sur les systèmes Windows**

Il peut arriver que, bien que la clé USB soit reconnue sur un système Windows, elle n'apparaisse pas dans l'explorateur de fichiers avec d'autres lecteurs tels que (C:) et (D:). Cela est dû au fait qu'aucune lettre de lecteur n'a été attribuée au périphérique. Vous pouvez y remédier en utilisant l'application Disk Management (Gestion des disques) de Windows.
	
* Cliquez avec le bouton droit de la souris sur le menu Démarrer et sélectionnez "Disk Management" dans le menu contextuel.

![GParted Operation Successful](/images/Disk-Management-1.png)

* Dans la fenêtre Gestion des disques, vous devriez voir une liste de lecteurs. Recherchez votre clé USB, qui peut être identifiée comme "Removable" (amovible) ou "Unknown" (inconnu).

* Cliquez avec le bouton droit de la souris sur le lecteur USB et sélectionnez "Change Drive Letter and Paths" (Modifier la lettre du lecteur et les chemins d'accès), puis cliquez sur "Add" (Ajouter). (Il est préférable de laisser quelques lettres libres pour les lecteurs de l'ordinateur, donc choisissez F: ou une lettre plus éloignée).

![GParted Operation Successful](/images/Disk-Management-2.png)

* Choisissez une lettre de lecteur dans la liste et cliquez sur "OK".

Après avoir attribué une lettre de lecteur, votre clé USB devrait maintenant apparaître dans l'Explorateur de fichiers de votre ordinateur Windows.

![GParted Operation Successful](/images/File-Explorer.png)

## Sur Windows

1. Branchez la clé USB amorçable sur un port USB de votre ordinateur Windows.

2. Appuyez sur Win + E pour ouvrir l'Explorateur de fichiers.

3. Cliquez avec le bouton droit de la souris sur la clé USB et sélectionnez "Formater..." dans le menu contextuel.

4. Dans la boîte de dialogue Format, vous pouvez choisir le système de fichiers souhaité. Pour assurer la compatibilité entre Windows et d'autres systèmes d'exploitation comme Linux, vous pouvez choisir exFAT. Si vous prévoyez d'utiliser la clé USB uniquement avec Windows, vous pouvez choisir NTFS. Vous pouvez également définir une étiquette de volume (volume label) si vous le souhaitez.

![GParted Operation Successful](/images/Windows-formatting.png)

5. Cliquez sur le bouton "Démarrer" (Start) pour lancer le processus de formatage.

6. Si vous êtes invité à confirmer, cliquez sur "OK" pour continuer. Notez que le formatage effacera toutes les données de la clé USB. Veillez donc à sauvegarder tous les fichiers importants avant de poursuivre.

7. Attendez que Windows termine le processus de formatage. Cela peut prendre quelques instants, en fonction de la taille de la clé USB.

![GParted Operation Successful](/images/Windows-formatting-2.png)

8. Une fois le processus de formatage terminé, éjectez la clé USB de votre ordinateur de manière sécurisée afin de vous assurer que toutes les modifications ont été finalisées et que la clé peut être retirée sans risque.

Une fois ces étapes terminées, votre clé USB amorçable devrait redevenir une clé USB normale et vous pourrez l'utiliser à des fins de stockage.
