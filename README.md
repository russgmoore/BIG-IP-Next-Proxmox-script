# F5 Proxmox Scripts to speed installation of products

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
bash -c "$(wget -qLO - https://github.com/russgmoore/F5-Proxmox-Scripts/raw/main/install-bigip-next-cm.sh)"
```

# Distributed Cloud SMSv2 CE Script

# Prerequisit
You must have created an SMSv2 site with type "KVM", created a token on that site, and you will need the download image location if you don't have the image stored
locally on the proxmox host this script will run on.

To use this script, go to the Proxmox Web console and not SSH.
Open the console and paste this:

```
bash -c "$(wget -qLO - https://github.com/russgmoore/F5-Proxmox-Scripts/raw/main/install-xc-smsv2.sh)"
```
