+++
title = "From Bootable to Usable: A Guide to Restoring Your USB Drive for Everyday Use"
date = 2024-02-09T14:55:37-06:00
draft = false
toc = true
tags = []
+++

## Introduction 

After you turn a USB stick into a bootable USB drive you may have noticed that it becomes unusable for normal purposes (you cannot use it anymore to move data around). Ignorant me thought that I only needed to delete all the files on the USB stick to revert it to its "normal mode". I then search online for a guide to get it back but I could not find anything good (maybe my research skills just suck) so I decided to write my own guide. In this blog post I will show you how to "revive" your USB stick whether you are on Linux or Windows.

## Linux Method

To use the USB stick as a normal storage device again, you'll need to format it, which will erase all existing data. On Linux we can use GParted for for the formatting.

1. Start by launching gparted (if if not installed, you can install it with `sudo apt install gparted`):

```
sudo gparted
```

This will bring GParted interface, you can use the dropdown menu in the top-right corner to switch between your different drives. The USB drive will often be named `/dev/sdb`, or a similar identifier. You can also identify your storage device by the space in GiB.

![GParted Interface](/images/gparted1.png)

2. Delete the existing partitions listed on the USB drive 

Right-click on each existing partition listed on the USB drive and select "Delete." Confirm any prompts. I only have one partition listed for me as `/dev/sdb1`. If the "Delete" option is greyed out it means that you have to unmount the device first.

3. Create a New Partition Table

After deleting all partitions, click on the "Device" menu and select "Create Partition Table."
Then choose the type of partition table you want to create (usually "msdos" for MBR or "gpt" for GPT). Click "Apply." (msdos will work just fine)

![GParted Create New Partition Table](/images/gparted2.png)

4. Create a New Partition

Now, create a new partition on the unallocated space. Right-click on the unallocated space, choose "New," set the desired file system, and click "Add." Click on the green check button to "Apply All Operations". You have to do the same everytime you see "1 operation pending" at the bottom of the screen.

![GParted Create a New Partition](/images/gparted3.png)

5. Formatting successful

You should see a screen saying that All Operations were successful. But there is more that you can do.

![GParted Operation Successful](/images/gparted4.png)

6. File system configuration

In my case I have two laptops (Windows and Linux) and in order for storage devices to work on both systems you have to use a compatible file system type. I recommend to format your device to `exFAT` if you want to use on Windows and Linux. If you plan on using it just on Linux system choose `ext4` and for Windows systems `NTFS`.

Righ-click on the partition and hover over `Format to`, you will get a list of file ssytems select `exfat` and press the green check button to continue. Close all the window after the operations are done and you should see that under the `File System` section the device now uses `exfat`.

![GParted Operation Successful](/images/gparted5.png)


![GParted Operation Successful](/images/gparted6.png)

Your USB device is now ready to be used for use.

7. Device not showing in file explorer on Windows systems

It may happen that despite the USB stick being recognized on a Windows system, it does not appear in the file explorer with other drives such as (C:) and (D:). This happens because the device does not have a drive letter assigned. You can fix it by using the Disk Management application on Windows.
	
* Right-click on the Start menu and select "Disk Management" from the context menu.

![GParted Operation Successful](/images/Disk-Management-1.png)

* In the Disk Management window, you should see a list of drives. Look for your USB drive, which may be labeled as "Removable" or "Unknown."

* Right-click on the USB drive and select "Change Drive Letter and Paths." and Click "Add." (It is better to leave some free letters for the computer drives, so choose F: or something further than that).

![GParted Operation Successful](/images/Disk-Management-2.png)

* Choose a drive letter from the list and click "OK.

After assigning a drive letter, your USB drive should now appear in File Explorer on your Windows laptop.

![GParted Operation Successful](/images/File-Explorer.png)

## Windows Method

1. Plug the bootable USB drive into a USB port on your Windows computer.

2. Press Win + E to open File Explorer.

3. Right-click on the USB drive and select "Format..." from the context menu.

4. In the Format dialog box, you can choose the desired file system. For compatibility between Windows and other operating systems like Linux, you can choose FAT32 or exFAT. If you only plan to use the USB drive with Windows, you can choose NTFS. You can also set a volume label if desired.

![GParted Operation Successful](/images/Windows-formatting.png)

5. Click on the "Start" button to begin the formatting process.

6. If prompted to confirm, click "OK" to proceed. Note that formatting will erase all data on the USB drive, so make sure to back up any important files before proceeding.

7. Wait for Windows to complete the formatting process. This may take a few moments, depending on the size of the USB drive.

![GParted Operation Successful](/images/Windows-formatting-2.png)

8. Once the formatting process is complete, safely eject the USB drive from your computer to ensure that all changes are finalized and the drive is safe to remove.

After completing these steps, your bootable USB drive should be reverted back to a normal USB stick, and you can use it for regular storage purposes.
