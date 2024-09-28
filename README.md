# BIG-IP-Next-Proxmox-Scripts

# Prerequisit
You must have a link to the BIG-IP Next CM qcow image handy.  You can get this through an account on myF5 and the downloads section.
Once you have selected a version there's an option to copy the URL.  That's what you will need.
If you already have the image local on storage you can select local for the image and provide the full path to the image to the script.



The defaults for this script are taken from Eric Chen's great youtube video:
https://www.youtube.com/watch?v=l9Diyr1uA6I


To use this script, go to the Proxmox Web console and not SSH.
Open the console and paste this:

```
bash -c "$(wget -qLO - https://github.com/russgmoore/BIG-IP-Next-Proxmox-Scripts/raw/main/install-bigip-next-cm.sh)"
```