---
date: 2024-02-13T14:31:59-06:00
# description: ""
image: "/images/THM-OhSINT/OhSINT.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: OhSINT"
type: "post"
---

* Platform: TryHackMe
* Link: [OhSINT](https://tryhackme.com/room/ohsint)
* Level: Easy
* Type: OSINT
---

This is an OSINT challenge, OSINT stands for Open-Source Intelligence. It's essentially the collection and analysis of publicly available information to gain valuable insights. Think of it like putting together a puzzle using pieces you find scattered around the internet, libraries, or anywhere information is freely accessible.

After downloading the Task Files, with the `Download Task Files` button you get a single image named `WindowsXP.jpg`. As you can see, you cannot get anything from this picture at first glance. 

![WindowsXP backgroung image](/images/THM-OhSINT/WindowsXP.jpg)

## 1. What is this user's avatar of?

>Imagine you have a collection of photos from your recent vacation. The photos themselves capture the memories, but there's more you might want to know about them: when were they taken, where, by whom? This "extra" information that describes the photos themselves is called metadata. In short metadata is data that provides information about other data.

On Linux, we can use the `exiftool` to read the image metadata. Run the command `exiftool WindowsXP.jpg` and you will get some output.

![Output of exiftool command](/images/THM-OhSINT/exiftool-cmd-result.png)

We get some useful information and a nickname for the Copyright, `OWoodflint`. This room being a OSINT case we look for publicly available information.

Googling `OWoodflint` get us multiple links, let's look at the X (formerly Twitter) account first.

![Search results of googling OWoodflint](/images/THM-OhSINT/OWoodflint-search-results.png)

We see a cat as the profile picture, we try `cat` as the answer of the first question and it is the correct answer.

## 2. What city is this person in?

The hint tells us to use the BSSID found on X on a site called `Wigle.net`. 

![BSSID found on X account](/images/THM-OhSINT/OWoodflint-BSSID.png)

In his second post the user gave us a BSSID of `B4:5D:50:AA:86:41`. Now we go on [wigle.net](https://www.wigle.net/) and use that BSSID.

> A BSSID (**Basic Service Set Identifier**) is a unique identifier assigned to each wireless access point (AP) or router in a Wi-Fi network. It distinguishes one wireless network from another within a given coverage area. Essentially, the BSSID serves as the MAC (Media Access Control) address of the wireless device.

Enter the BSSID and click on the `Filter` button below.

![BSSID search on wigle.net](/images/THM-OhSINT/Wigle-BSSID-search.png)

You will have to zoom out and look for a purple circle on the map. The match shows `London`. This turns out to be the correct answer for the second question.

![BSSID search result](/images/THM-OhSINT/BSSID-location-match.png)

## 3. What is the SSID of the WAP he connected to?

>An SSID, which stands for **Service Set Identifier**, is essentially the name of a Wi-Fi network. It's the public identifier that a wireless router broadcasts to announce its presence and allow nearby devices to connect.

Keep zooming in on the location marked on the map and you will see the word `UnileverWiFi` above the BSSID you entered earlier, which is the correct answer for this question.

![WAP SSID](/images/THM-OhSINT/OhSINT-WAP-SSID.png)

## 4. What is his personal email address?

The second search result is a Github account, let's look there. We find an email address `OWoodflint@gmail.com`.

![Email address found on Github](/images/THM-OhSINT/OhSINT-email.png)

## 5. What site did you find his email address on?

We found the email address on `Github`.

## 6. Where has he gone on holiday?

We see a WordPress website on the Github repository.

![WordPress site url](/images/THM-OhSINT/OhSINT-WordPress-site.png)

On the WordPress site the user revealed his location, saying that he is in `New York`, which is the correct answer.

![Target holiday location](/images/THM-OhSINT/OhSINT-holiday-location-1.png)

## 7. What is the person's password?

I recently learned about sensitive data exposure and how sometimes you will find sensitive data in the source code of web pages. Looking at the source code, we find a string written in white (`#ffffff` is the Hex color code for the white color). The author of this web page attempted to hide this string by writing it in white on a white background, essentially making it invisible. We try `pennYDr0pper.!` as the password and gets it right.

![user password in source code](/images/THM-OhSINT/OhSINT-password.png)

> I think when it comes to OSINT challenges one should be very attentive and nothing should be overlooked. The password was just in front of me but I didn't pick up on it at first. I accidentally pressed `Ctrl+a` and the string `pennYDr0pper.!` became visible but I failed to notice that it was not visible before. 

![Target holiday location](/images/THM-OhSINT/WP-password-trick.png)

That's it for my first writeup! I will try to tackle different types of hacking challenges to keep them interesting. Until next time.
