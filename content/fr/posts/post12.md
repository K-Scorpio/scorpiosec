+++
title = "HTB: Manager"
date = 2024-03-15T22:14:37-05:00
draft = false
toc = true
images = ['/images/HTB-Manager/Manager.png']
tags = ['Hack The Box']
categories = ['Writeups']
+++

* Platforme: Hack The Box
* Lien: [Manager](https://app.hackthebox.com/machines/Manager)
* Niveau: Moyen
* OS: Windows
---

Manager présente un serveur Windows 2019 utilisant Active Directory et une base de données MSSQL en plus de quelques services tels que MSRPC et HTTP. La cible est vulnérable au brute forcing RID et à l'ESC7 ( Vulnerable Certificate Authority Access Control).

L'adresse IP cible est `10.10.11.236`

## Balayage (Scanning)


