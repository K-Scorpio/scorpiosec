---
date: 2024-11-04T12:11:25-06:00
# description: ""
image: "/images/THM-SeeTwo/SeeTwo.png"
showTableOfContents: true
tags: ["TryHackMe"]
categories: ["Writeups"]
title: "THM: SeeTwo"
type: "post"
---

* Platform: TryHackMe
* Link: [SeeTwo](https://tryhackme.com/r/room/seetworoom)
* Level: Medium
---

In this room we have to investigate a pcap file. At first we find what looks like some benign traffic, however after digging deeper we find an ELF binary containing some `.pyc` files. Decompiling one the file allows us to understand the tactics used by the attacker, and with a python script we find all the information we need.

## Investigation

Right after loading the pcap file, we get an overview of the traffic. Let's use the `Conversations` feature in Wireshark (Statistics --> Conversations).

Under `IPv4` we find two communications:
- `10.0.2.64` sent 2152 packets to `10.0.2.71`. We also notice that 16 MB of data were transfer, that's definitely worth investigating.
- `10.0.2.71` sent 2 packets to `10.0.2.3`.

![SeeTwo - Wireshark IPv4 conversations](/images/THM-SeeTwo/IPv4_conv.png)

Under the `TCP` section, we find more information, we see that there is traffic on ports: `22` likely SSH, `1337` and `80` probably HTTP. The 16 MB of data was sent transferred via port 80.

![SeeTwo - Wireshark TCP conversations](/images/THM-SeeTwo/TCP_conv.png)

As we were thinking the traffic over port 22 is indeed SSH, we can skip it since we do not have a key for decryption at this moment.

![Wireshark SSH traffic](/images/THM-SeeTwo/SSH_traffic.png)

We cannot say for sure which protocol is running on port `1337`, so let's check that traffic. We'll begin by examining the conversation containing `60kB` of data.

After the TCP handshake we find some data being transferred on frame `1810`.

![Wireshark 1337 traffic](/images/THM-SeeTwo/frame_1810.png)

We copy the data and head to [CyberChef](https://gchq.github.io/CyberChef/), it turns out to be a picture.

![Pokeball image](/images/THM-SeeTwo/pokeball_pic.png)

After decoding some other data from that same conversation, we get another image.

![Milk image](/images/THM-SeeTwo/frame_1856.png)

The traffic on port `1337` seems to be a dead end, so far we only get images. We turn our attention to the HTTP conversation, but first let's see if we can export files related to the protocol (File --> Export Objects --> HTTP).

We get a file called `base64_client`.

![base64_client file](/images/THM-SeeTwo/base64_client.png)

![base64_client file type](/images/THM-SeeTwo/base64_client_filetype.png)

After decoding the data we end up with a Linux binary.

![Linux ELF](/images/THM-SeeTwo/Linux_ELF.png)

Running `strings` on the file we can read `pydata` at the end. 

```
strings decoded_base64 | tail
```

![pydata](/images/THM-SeeTwo/pydata.png)

Assuming that it is related to Python, we can try to find all the `python` mentions from the output.

```
strings decoded_base64 | grep "python"
```

![grep on python](/images/THM-SeeTwo/strings_python.png)

There are a lot of mentions about `CPython` and python `version 3.8`. We can use a tool such as [PyInstaller Extractor](https://github.com/extremecoders-re/pyinstxtractor) to extract the content of the ELF binary.

```
git clone https://github.com/extremecoders-re/pyinstxtractor
cd pyinstxtractor
python pyinstxtractor.py ELF_binary_location
```

![pyinstextractor command](/images/THM-SeeTwo/pyinstxtractor.png)

We get some `.pyc` files which are compiled python files. We need to use a decompiler for Python version `3.8`. 

![pyc files](/images/THM-SeeTwo/pyc_files.png)

We can use [decompyle3](https://github.com/rocky/python-decompile3) to decompile our files. After installing it we run the command below.

```
decompyle3 client.pyc_location > client.py
```

![decompyle3 command](/images/THM-SeeTwo/decompyle3_clientpyc.png)

We then read the content of `client.py`.

![client.py code](/images/THM-SeeTwo/client_py.png)

Now we have a better picture of what is happening, this code is a command-and-control communication (C2) with the IP address `10.0.2.64` and it is using port `1337`. It also leverages some `XOR encryption`, we have the key so we can do some decrytion.

The command sent by the attacker and the response he/she gets are always split into two parts `encoded_image` and `encoded_command`. These two parts are separated by `AAAAAAAAAA`.

Going back to Wireshark, we use the filter `tcp.port == 1337` and follow the TCP stream.

![separator in Wireshark](/images/THM-SeeTwo/separator.png)

> The request data is in blue and the response is in red.

When we decrypt the entire data of a request or a response we get an image and we are tricked to believe that this is a harmless communication. The command is actually whatever comes after the separator. 

Let's use `JB0=` which is the first encoded command sent by the attacker. We use the key below for the XOR decryption. 

```
MySup3rXoRKeYForCommandandControl
```

![decoded command in CyberChef](/images/THM-SeeTwo/cmd_decoded.png)

![decoded response in CyberChef](/images/THM-SeeTwo/C2_response_decoded.png)

The command is `id` and the response was `uid=1000(bella) gid=1000(bella) groups=1000(bella),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)`.

If we keep doing this we will discover everything that was done by the attacker on the server, but this manual process is slow, so we will use a script.

```python
from scapy.all import rdpcap, TCP
import base64

PCAP_FILE = "capture.pcap"
TARGET_PORT = 1337
SEPARATOR = "AAAAAAAAAA"
XOR_KEY = "MySup3rXoRKeYForCommandandControl".encode("utf-8")

def xor_crypt(data, key):
    key_length = len(key)
    return bytes([byte ^ key[i % key_length] for i, byte in enumerate(data)])

def decode_and_decrypt(payload):
    try:
        parts = payload.split(SEPARATOR)
        if len(parts) < 2:
            return None  

        encoded_part = parts[1]
        decoded_part = base64.b64decode(encoded_part.encode("utf-8"))

        decrypted_data = xor_crypt(decoded_part, XOR_KEY)

        return decrypted_data.decode("utf-8")
    except Exception as e:
        print(f"Error decoding payload: {e}")
        return None

packets = rdpcap(PCAP_FILE)
for packet in packets:
    if packet.haslayer(TCP):
        if packet[TCP].sport == TARGET_PORT:
            payload = bytes(packet[TCP].payload).decode("utf-8", errors="ignore")
            decoded_command = decode_and_decrypt(payload)
            if decoded_command:
                print("Decoded C2 Command:", decoded_command)
        elif packet[TCP].dport == TARGET_PORT:
        
            payload = bytes(packet[TCP].payload).decode("utf-8", errors="ignore")
            decoded_response = decode_and_decrypt(payload)
            if decoded_response:
                print("Decoded C2 Response:", decoded_response)
```

The output of the script provides all the answers.

### What is the first file that is read? Enter the full path of the file.

Run the script and find the `cat` command.

### What is the output of the file from question 1?

The answer is the output of the `cat` command.

### What is the user that the attacker created as a backdoor? Enter the entire line that indicates the user.

The first `echo` command gives you the annswer.

### What is the name of the backdoor executable?

Find the command adding the `SUID bit` to the binary.

### What is the md5 hash value of the executable from question 4?

The attacker computed the md5 hash with the `md5sum` command, find it and read its output.

### What was the first cronjob that was placed by the attacker?

Find the second `echo` command and you will get the answer.

### What is the flag?

With the third `echo` command, the attacker encoded a string, decode it and you will get the flag.
