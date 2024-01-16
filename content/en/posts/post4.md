+++
title = "Demystifying the Linux File System Hierarchy"
date = 2024-01-14T20:05:43-06:00
draft = false
toc = true
categories = ['Operating Systems']
tags = ['Linux', 'Filesystem']
+++

## Linux File Hierarchy Structure

Proficiency in Linux is indispensable for cybersecurity professionals, you may have noticed that Linux is different from Windows in the way files are organized. The Filesystem Hierarchy Standard (FHS) maintained by the Linux Foundation provides a model for the directories structure. While there may be some variations across Linux distributions, they typically adhere to this standard. To enhance your Linux skills, a fundamental understanding of the file system is essential. In this blog post we will explore the Linux file system.

> This is not an exhaustive list but we will look at the most common directories.

![Linux Filesystem Overview](/images/Linux-File-Hierarchy-Structure.png)
*Linux Filesystem Overview*

## / (Root)

At the core of the Linux Filesystem Hierarchy you have the root directory represented by the symbol "/". This directory is the starting point for the entire file system. 
* Every single file and directory start from the root directory
* Only the root user has write permissions under this directory
* The home directory of the root user is /root
* Executing `ls -l /` will display the contents of the root directory

## /bin & /sbin

These directories contain essential binaries and system commands. While both directories house binary files, there is a fundamental distinction in the types of binaries they contain.

The /bin directory, derived from 'binary,' is reserved for storing vital executable binaries crucial to the core functionality of the operating system. These binaries are necessary for user interactions and are often used in single-user mode. Common commands such as ls (list files), cp (copy), and mv (move) find their home in the /bin directory.

Conversely, the /sbin directory, representing 'system binary,' contains binaries designed exclusively for system administration and maintenance tasks. Unlike the binaries in /bin, those in /sbin are typically intended for use by the system administrator rather than regular users. System binaries essential for tasks like system recovery, repair, and diagnostics are housed here.

| **/bin** | **/sbin** |
| -------- | --------- |
| Contains common linux commands used in single-user modes such as ps, ls, ping, grep, cp, etc. | Contains commands typically used by system administrators such as iptables, reboot, fdisk, ifconfig, swapon, etc. |

## /boot

The /boot directory houses critical files that are essential for the booting process of the operating system. The boot loader files and the Linux kernel are stored in this directory. The bootloader is responsible for initiating the operating system during the boot process. As the initial phase of a Linux system's startup sequence, the contents of /boot are integral to initiating the kernel and facilitating a smooth boot experience. Corrupting or deleting certain files in this directory can hinder the correct booting of your system.

## /dev

The /dev directory serves as a gateway to the device files that represent hardware devices connected to the system. Unlike regular files, these device files act as interfaces, enabling communication between the operating system and hardware components.

The name "/dev" is short for "device," and this directory acts as a virtual filesystem containing entries for each device or pseudo-device connected to the system. These entries are represented as special files, allowing processes to interact with hardware through standardized input and output operations.

Inside the /dev directory, you will find various devices files. Here are a few of them:
* */dev/fd* - Floppy disk devices
* */dev/tty* - Terminal devices representing console and serial ports  
* */dev/sda* (1,2,3, etc.) - disk devices representing hard drives
* */dev/usb* (1,2,3, etc.) - USB device entries

## /etc

The /etc directory serves as a central hub for configuration files that dictate the behavior of the operating system, system services, and installed applications. These configuration files are often plain text files and serve as a means to customize and fine-tune the settings of different components.

Linux adheres to the principle of separating configuration data from executables by centralizing configuration files in /etc. This separation allows for easier system administration, as modifications and updates to settings can be made without altering the core functionality of the associated programs. In this directory you can find:
* */etc/passwd* - Contains user account information, including usernames, user IDs, and home directories (believe it or not, your actual passwords aren't here)
* */etc/hosts* - Mapping of IP addresses to hostnames, facilitating local hostname resolution
* */etc/shadow* - Stores user passwords in an encrypted hashed format
* */etc/network/* - Configuration files for network settings, including interfaces and routing

## /home

The /home directory functions as a private space for each user, encompassing individual user home directories like Documents, Downloads, Desktop, Pictures, etc. Its primary purpose is to provide a dedicated space for storing the personal files, documents, and settings of individual users. When a new user account is created, a corresponding directory is established within /home, encapsulating their unique environment.

## /lib 

The /lib directory contains shared libraries and kernel modules. Short for "library", this directory ensures the availability of essential resources that support the functioning of various programs and applications on a Linux system such as the binaries in /bin and /sbin.

Shared libraries, also known as dynamic-link libraries, are compiled code modules that multiple programs can use simultaneously. Placing these shared libraries in /lib ensures that they are readily accessible to the applications that depend on them, promoting efficiency and resource optimization.

Kernel modules, which extend the functionality of the Linux kernel, are also stored in /lib. These modules can be dynamically loaded or unloaded as needed, enhancing the adaptability and versatility of the operating system.

## /media

The /media directory is a mount point for removable media devices such as USB drives, external hard disks, and optical discs. Acting as a temporary staging area for these devices, /media allows users to access and interact with their contents seamlessly.

It plays a crucial role in providing a standardized location for mounting external and removable storage devices. When a user connects a USB drive or inserts an optical disc, the operating system mounts the device to a subdirectory within /media, creating a point of access for users to read, write, and manage the contents.

## /mnt 

The /mnt directory act as a generic mount point for temporary filesystems and remote file systems. Unlike the /media directory, which is specifically designed for removable media, /mnt is a flexible and manually managed location that allows users and administrators to mount various filesystems as needed.

The /mnt directory acts as a staging area for temporarily mounting additional filesystems, whether they are local or remote. This flexibility makes /mnt a versatile location for accessing data from different sources, such as network shares, external drives, or filesystems intended for temporary use.

While /media is dedicated to automatically mounting removable media devices, /mnt provides a more manual and customizable approach, allowing users to mount and access various filesystems based on their specific requirements.

## /opt

The /opt directory is designated for the installation of optional or add-on software packages. Abbreviated from "optional," /opt provides a standardized location for third-party applications that are not part of the core system but are added to enhance the functionality of the operating system.

The /opt directory is a dedicated space for software vendors and developers to install their applications without interfering with the standard system files and directories. This separation ensures that optional software packages do not disrupt the core system components and adhere to a consistent installation structure.

Applications installed in /opt typically have their own subdirectories, containing the necessary binaries, libraries, documentation, and other resources. This organization simplifies the management and removal of optional software, promoting a clean and modular approach to extending the capabilities of the Linux system.

## /tmp

The /tmp directory is a temporary storage location for files that are required during the course of system operations. Abbreviated from "temporary", /tmp is intended for the storage of transient data that may be needed by applications, processes, or users and is automatically cleared upon system reboot.

This is designed to be a shared space for storing temporary files, facilitating communication between different processes and allowing applications to create and manipulate temporary data as needed. The key characteristics of /tmp include its ephemeral nature and the absence of persistent storage, making it an ideal location for short-term storage requirements.

## /usr

The /usr directory is a fundamental component of the Linux filesystem, housing user-related resources, secondary user programs, and data. Abbreviated from "Unix System Resources", /usr encompasses a wide range of directories, each contributing to the overall functionality and organization of the Linux operating system.

The /usr directory is designed to contain user-related resources and secondary user programs that are not essential for system booting and repair. It plays a crucial role in separating the core system binaries in /bin and /sbin from additional programs and resources that enhance the user experience.

## Conclusion 

This overview is just the tip of the iceberg. You can dive deeper into each directory to further your understanding of the Linux Filesystem Hierarchy. If you are looking for books, I suggest [How Linux Works, What Every Superuser Should Know, 3rd Edition](https://www.amazon.com/How-Linux-Works-Brian-Ward/dp/1718500408) and [The Linux Command Line, 2nd Edition: A Complete Introduction](https://linuxcommand.org/tlcl.php) (the second book is free).

I hope this blog post was helpful to you. Keep learning!
