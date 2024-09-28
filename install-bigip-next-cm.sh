#!/usr/bin/env bash

# substantial parts of this script were taken from:
# Copyright (c) 2021-2024 tteck
# Author: tteck (tteckster)
# License: MIT
# https://github.com/tteck/Proxmox/raw/main/LICENSE
# all other content Copyright (c) 2024
# Author: Russell Moore
# LicenseL MIT

# a nice header to show during build
function header_info {
  clear
  cat <<"EOF"
______ _____  ______ _____ _____     ___________   _   _           _     _____ ___  ___
|  ___|  ___| | ___ \_   _|  __ \   |_   _| ___ \ | \ | |         | |   /  __ \|  \/  |
| |_  |___ \  | |_/ / | | | |  \/_____| | | |_/ / |  \| | _____  _| |_  | /  \/| .  . |
|  _|     \ \ | ___ \ | | | | _|______| | |  __/  | . ` |/ _ \ \/ / __| | |    | |\/| |
| |   /\__/ / | |_/ /_| |_| |_\ \    _| |_| |     | |\  |  __/>  <| |_  | \__/\| |  | |
\_|   \____/  \____/ \___/ \____/    \___/\_|     \_| \_/\___/_/\_\\__|  \____/\_|  |_/
EOF
}
header_info
echo -e "\n Loading..."

#generate some mac addresses
GEN_MAC1=02:$(openssl rand -hex 5 | awk '{print toupper($0)}' | sed 's/\(..\)/\1:/g; s/.$//')
GEN_MAC2=02:$(openssl rand -hex 5 | awk '{print toupper($0)}' | sed 's/\(..\)/\1:/g; s/.$//')

#determine the next available ID for a VM
NEXTID=$(pvesh get /cluster/nextid)


#setup some colors for our interface
YW=$(echo "\033[33m")
BL=$(echo "\033[36m")
HA=$(echo "\033[1;34m")
RD=$(echo "\033[01;31m")
BGN=$(echo "\033[4;92m")
GN=$(echo "\033[1;92m")
DGN=$(echo "\033[32m")
CL=$(echo "\033[m")
BFR="\\r\\033[K"
HOLD="-"
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"
THIN="discard=on,ssd=1,"
set -e
trap 'error_handler $LINENO "$BASH_COMMAND"' ERR
trap cleanup EXIT

#our error handler
function error_handler() {
  local exit_code="$?"
  local line_number="$1"
  local command="$2"
  local error_message="${RD}[ERROR]${CL} in line ${RD}$line_number${CL}: exit code ${RD}$exit_code${CL}: while executing command ${YW}$command${CL}"
  echo -e "\n$error_message\n"
  cleanup_vmid
}



# Function to rename file if it ends with ".qcow" to ".qcow2"
rename_qcow_file() {
  local file_path="$1"

  # Check if the file ends with ".qcow"
  if [[ "$file_path" == *.qcow ]]; then
    # Create new file path with ".qcow2" extension
    local new_file_path="${file_path%.qcow}.qcow2"

    # Rename the file
    mv "$file_path" "$new_file_path"

    # Update the original variable contents
    file_path="$new_file_path"
  fi

  echo "$file_path"
}


function cleanup_vmid() {
  if qm status $VMID &>/dev/null; then
    qm stop $VMID &>/dev/null
    qm destroy $VMID &>/dev/null
  fi
}


function cleanup() {
  popd >/dev/null
  rm -rf $TEMP_DIR
}

TEMP_DIR=$(mktemp -d)
pushd $TEMP_DIR >/dev/null
if whiptail --backtitle "F5 Proxmox install script" --title "BIG-IP Next CM" --yesno "This will create a new F5 BIG-IP Next CM VM. Proceed?" 10 58; then
  :
else
  header_info && echo -e "⚠ User exited script \n" && exit
fi


function prompt_for_input() {
  local input_type=""
  local selected_input=""

  while true; do
    choice=$(whiptail --title "File location Selection" --menu "Choose an option" 15 60 4 \
            "1" "Enter Download URL" \
            "2" "Enter local file path" 3>&1 1>&2 2>&3)

    exitstatus=$?
    if [ $exitstatus != 0 ]; then
      echo "User canceled."
      exit 1
    fi

    case $choice in
      1)
        input_type="URL"
        selected_input=$(whiptail --inputbox "Enter the URL:" 8 60 3>&1 1>&2 2>&3)
        if [[ $? != 0 ]]; then
          continue
        fi

        if [[ $selected_input =~ ^https?:// ]]; then
          host=$(echo $selected_input | awk -F[/:] '{print $4}')
          if ping -c 1 "$host" &> /dev/null; then
            break
          else
            whiptail --msgbox "Host is not resolvable. Please try again." 8 60
          fi
        else
          whiptail --msgbox "Invalid URL format. Please try again." 8 60
        fi
        ;;
      2)
        input_type="LOCAL"
        selected_input=$(whiptail --inputbox "Enter the file path:" 8 60 3>&1 1>&2 2>&3)
        if [[ $? != 0 ]]; then
          continue
        fi

        if [[ -f $selected_input && -r $selected_input ]]; then
          break
        else
          whiptail --msgbox "File does not exist or is not readable. Please try again." 8 60
        fi
        ;;
      *)
        whiptail --msgbox "Invalid choice. Please try again." 8 60
        ;;
    esac
  done

  # Export the variables
  export INPUT_TYPE="$input_type"
  export INPUT_VALUE="$selected_input"
}

function parse_url() {
  local url=$1
  local urlhost=""
  local uribase=""

  # Extract the hostname from the URL
  urlhost=$(echo "$url" | awk -F[/:] '{print $4}')

  # Extract the URI without the query string and strip the leading "/"
  uribase=$(echo "$url" | sed 's|.*/\([^/?]*\)?.*|\1|')

  # Export the variables
  export URLHOST="$urlhost"
  export URIFILE="$uribase"
}

if [[ "$INPUT_TYPE" == "URL" ]]; then
  parse_url "$INPUT_VALUE"
fi

function msg_info() {
  local msg="$1"
  echo -ne " ${HOLD} ${YW}${msg}..."
}

function msg_ok() {
  local msg="$1"
  echo -e "${BFR} ${CM} ${GN}${msg}${CL}"
}

function msg_error() {
  local msg="$1"
  echo -e "${BFR} ${CROSS} ${RD}${msg}${CL}"
}

function check_root() {
  if [[ "$(id -u)" -ne 0 || $(ps -o comm= -p $PPID) == "sudo" ]]; then
    clear
    msg_error "Please run this script as root."
    echo -e "\nExiting..."
    sleep 2
    exit
  fi
}

function pve_check() {
  if ! pveversion | grep -Eq "pve-manager/8.[1-3]"; then
    msg_error "This version of Proxmox Virtual Environment is not supported"
    echo -e "Requires Proxmox Virtual Environment Version 8.1 or later."
    echo -e "Exiting..."
    sleep 2
    exit
  fi
}

function arch_check() {
  if [ "$(dpkg --print-architecture)" != "amd64" ]; then
    msg_error "This script will not work with PiMox! \n"
    echo -e "Exiting..."
    sleep 2
    exit
  fi
}

function ssh_check() {
  if command -v pveversion >/dev/null 2>&1; then
    if [ -n "${SSH_CLIENT:+x}" ]; then
      if whiptail --backtitle "Proxmox install Script" --defaultno --title "SSH DETECTED" --yesno "It's suggested to use the Proxmox shell instead of SSH, since SSH can create issues while gathering variables. Would you like to proceed with using SSH?" 10 62; then
        echo "you've been warned"
      else
        clear
        exit
      fi
    fi
  fi
}

function exit-script() {
  clear
  echo -e "⚠  User exited script \n"
  exit
}

function default_settings() {
  VMID="$NEXTID"
  FORMAT=",efitype=4m"
  MACHINE="q35"
  DISK_CACHE=""
  HN="mybigipnextcm"
  CPU_TYPE="x86-64-v2-AES"
  SOCKET=1
  CORE_COUNT="8"
  RAM_SIZE="16384"
  BRG1="vmbr0"
  BRG2="vmbr1"
  MAC1="$GEN_MAC1"
  MAC2="$GEN_MAC2"
  IPADDR1="192.168.1.233
  IPADDR2="10.10.10.10
  GW="192.168.1.2"
  NS="192.168.1.2"
  CIUSER="admin"
  CIPWD="admin"
  CITYPE="nocloud"
  VLAN1=""
  VLAN2=""
}

function advanced_settings() {
  while true; do
    if VMID=$(whiptail --backtitle "Proxmox F5 CM Install Script" --inputbox "Set Virtual Machine ID" 8 58 $NEXTID --title "VIRTUAL MACHINE ID" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
      if [ -z "$VMID" ]; then
        VMID="$NEXTID"
      fi
      if pct status "$VMID" &>/dev/null || qm status "$VMID" &>/dev/null; then
        echo -e "${CROSS}${RD} ID $VMID is already in use${CL}"
        sleep 2
        continue
      fi
      echo -e "${DGN}Virtual Machine ID: ${BGN}$VMID${CL}"
      break
    else
      exit-script
    fi
  done

  while true; do
    if PW1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --passwordbox "\nSet Root Password (needed for root ssh access)" 9 58 --title "PASSWORD (leave blank for automatic login)" 3>&1 1>&2 2>&3); then
      if [[ ! -z "$PW1" ]]; then
        if [[ "$PW1" == *" "* ]]; then
          whiptail --msgbox "Password cannot contain spaces. Please try again." 8 58
        elif [ ${#PW1} -lt 8 ]; then
          whiptail --msgbox "Password must be at least 8 characters long. Please try again." 8 58
        else
          if PW2=$(whiptail --backtitle "Proxmox VE Helper Scripts" --passwordbox "\nVerify Root Password" 9 58 --title "PASSWORD VERIFICATION" 3>&1 1>&2 2>&3); then
            if [[ "$PW1" == "$PW2" ]]; then
              CIPWD="PW1"
              echo -e "${DGN}Using Root Password: ${BGN}********${CL}"
              break
            else
              whiptail --msgbox "Passwords do not match. Please try again." 8 58
            fi
          else
            exit-script
          fi
        fi
      else
        PW1="admin"
        CIPWD="admin"
        echo -e "${DGN}Using Root Password: ${BGN}$PW1${CL}"
        break
      fi
    else
      exit-script
    fi
  done

  while true; do
    NET=$(whiptail --backtitle "Proxmox VE Helper Scripts" --inputbox "Set a Static IPv4 CIDR Address (/24)" 8 58 dhcp --title "IP ADDRESS" 3>&1 1>&2 2>&3)
    exit_status=$?
    if [ $exit_status -eq 0 ]; then
      if [ "$NET" = "dhcp" ]; then
        echo -e "${DGN}Using IP Address: ${BGN}$NET${CL}"
        break
      else
        if [[ "$NET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
          echo -e "${DGN}Using IP Address: ${BGN}$NET${CL}"
          break
        else
          whiptail --backtitle "Proxmox VE Helper Scripts" --msgbox "$NET is an invalid IPv4 CIDR address. Please enter a valid IPv4 CIDR address or 'dhcp'" 8 58
        fi
      fi
    else
      exit-script
    fi
  done

  if [ "$NET" != "dhcp" ]; then
    while true; do
      GATE1=$(whiptail --backtitle "Proxmox VE Helper Scripts" --inputbox "Enter gateway IP address" 8 58 --title "Gateway IP" 3>&1 1>&2 2>&3)
      if [ -z "$GATE1" ]; then
        whiptail --backtitle "Proxmox VE Helper Scripts" --msgbox "Gateway IP address cannot be empty" 8 58
      elif [[ ! "$GATE1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        whiptail --backtitle "Proxmox VE Helper Scripts" --msgbox "Invalid IP address format" 8 58
      else
        GATE=",gw=$GATE1"
        echo -e "${DGN}Using Gateway IP Address: ${BGN}$GATE1${CL}"
        break
      fi
    done
  else
    GATE=""
    echo -e "${DGN}Using Gateway IP Address: ${BGN}Default${CL}"
  fi

  if MACH=$(whiptail --backtitle "Proxmox F5 CM Install Script" --title "MACHINE TYPE" --radiolist --cancel-button Exit-Script "Choose Type" 10 58 2 \
    "i440fx" "Machine i440fx" OFF \
    "q35" "Machine q35" ON \
    3>&1 1>&2 2>&3); then
    if [ $MACH = q35 ]; then
      echo -e "${DGN}Using Machine Type: ${BGN}$MACH${CL}"
      FORMAT=""
      MACHINE=" -machine q35"
    else
      echo -e "${DGN}Using Machine Type: ${BGN}$MACH${CL}"
      FORMAT=",efitype=4m"
      MACHINE=""
    fi
  else
    exit-script
  fi

  if DISK_CACHE=$(whiptail --backtitle "Proxmox F5 CM Install Script" --title "DISK CACHE" --radiolist "Choose" --cancel-button Exit-Script 10 58 2 \
    "0" "None (Default)" ON \
    "1" "Write Through" OFF \
    3>&1 1>&2 2>&3); then
    if [ $DISK_CACHE = "1" ]; then
      echo -e "${DGN}Using Disk Cache: ${BGN}Write Through${CL}"
      DISK_CACHE="cache=writethrough,"
    else
      echo -e "${DGN}Using Disk Cache: ${BGN}None${CL}"
      DISK_CACHE=""
    fi
  else
    exit-script
  fi

  if VM_NAME=$(whiptail --backtitle "Proxmox F5 CM Install Script" --inputbox "Set Hostname" 8 58 mybigipnextcm --title "HOSTNAME" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $VM_NAME ]; then
      HN="mybigipnextcm"
      echo -e "${DGN}Using Hostname: ${BGN}$HN${CL}"
    else
      HN=$(echo ${VM_NAME,,} | tr -d ' ')
      echo -e "${DGN}Using Hostname: ${BGN}$HN${CL}"
    fi
  else
    exit-script
  fi

  if CPU_TYPE=$(whiptail --backtitle "Proxmox F5 CM Install Script" --title "CPU MODEL" --radiolist "Choose" --cancel-button Exit-Script 10 58 2 \
    "0" "x86-64-v2-AES (Default)" ON \
    "1" "Host" OFF \
    3>&1 1>&2 2>&3); then
    if [ $CPU_TYPE = "1" ]; then
      echo -e "${DGN}Using CPU Model: ${BGN}host${CL}"
      CPU_TYPE="host"
    else
      echo -e "${DGN}Using CPU Model: ${BGN}x86-64-v2-AES${CL}"
      CPU_TYPE="x86-64-v2-AES"
    fi
  else
    exit-script
  fi

  if CORE_COUNT=$(whiptail --backtitle "Proxmox F5 CM Install Script" --inputbox "Allocate CPU Cores" 8 58 8 --title "CORE COUNT (minimum 8)" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $CORE_COUNT ]; then
      CORE_COUNT="8"
      echo -e "${DGN}Allocated Cores: ${BGN}$CORE_COUNT${CL}"
    else
      echo -e "${DGN}Allocated Cores: ${BGN}$CORE_COUNT${CL}"
    fi
  else
    exit-script
  fi

  if RAM_SIZE=$(whiptail --backtitle "Proxmox F5 CM Install Script" --inputbox "Allocate RAM in MiB" 8 58 16384 --title "RAM (minimum 16GB)" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $RAM_SIZE ]; then
      RAM_SIZE="16384"
      echo -e "${DGN}Allocated RAM: ${BGN}$RAM_SIZE${CL}"
    else
      echo -e "${DGN}Allocated RAM: ${BGN}$RAM_SIZE${CL}"
    fi
  else
    exit-script
  fi

  if BRG1=$(whiptail --backtitle "Proxmox F5 CM Install Script" --inputbox "Set a Bridge" 8 58 vmbr0 --title "BRIDGE 1" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $BRG1 ]; then
      BRG1="vmbr0"
      echo -e "${DGN}Using Bridge: ${BGN}$BRG1${CL}"
    else
      echo -e "${DGN}Using Bridge: ${BGN}$BRG1${CL}"
    fi
  else
    exit-script
  fi

  if MAC1=$(whiptail --backtitle "Proxmox F5 CM Install Script" --inputbox "Set a Bridge 1 MAC Address" 8 58 $GEN_MAC1 --title "Bridge 1 MAC ADDRESS" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $MAC1 ]; then
      MAC1="$GEN_MAC1"
      echo -e "${DGN}Using MAC Address: ${BGN}$MAC1${CL}"
    else
      MAC1="$MAC1"
      echo -e "${DGN}Using MAC Address: ${BGN}$MAC1${CL}"
    fi
  else
    exit-script
  fi

  if VLAN1=$(whiptail --backtitle "Proxmox F5 CM Install Script" --inputbox "Set a Vlan for bridge 1(leave blank for default)" 8 58 --title "VLAN Bridge 1" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $VLAN1 ]; then
      VLAN1="Default"
      VLAN1=""
      echo -e "${DGN}Using Vlan: ${BGN}$VLAN1${CL}"
    else
      VLAN1=",tag=$VLAN1"
      echo -e "${DGN}Using Vlan: ${BGN}$VLAN1${CL}"
    fi
  else
    exit-script
  fi

  if BRG2=$(whiptail --backtitle "Proxmox F5 CM Install Script" --inputbox "Set a Bridge" 8 58 vmbr0 --title "BRIDGE 2" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $BRG2 ]; then
      BRG2="vmbr1"
      echo -e "${DGN}Using Bridge: ${BGN}$BRG2${CL}"
    else
      echo -e "${DGN}Using Bridge: ${BGN}$BRG2${CL}"
    fi
  else
    exit-script
  fi

  if MAC2=$(whiptail --backtitle "Proxmox F5 CM Install Script" --inputbox "Set a Bridge 2 MAC Address" 8 58 $GEN_MAC2 --title "Bridge 2 MAC ADDRESS" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $MAC2 ]; then
      MAC2="$GEN_MAC2"
      echo -e "${DGN}Using MAC Address: ${BGN}$MAC2${CL}"
    else
      MAC2="$MAC2"
      echo -e "${DGN}Using MAC Address: ${BGN}$MAC2${CL}"
    fi
  else
    exit-script
  fi

  if VLAN2=$(whiptail --backtitle "Proxmox F5 CM Install Script" --inputbox "Set a Vlan for bridge 2(leave blank for default)" 8 58 --title "VLAN Bridge 2" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $VLAN2 ]; then
      VLAN2="Default"
      VLAN2=""
      echo -e "${DGN}Using Vlan: ${BGN}$VLAN2${CL}"
    else
      VLAN2=",tag=$VLAN2"
      echo -e "${DGN}Using Vlan: ${BGN}$VLAN2${CL}"
    fi
  else
    exit-script
  fi

  if (whiptail --backtitle "Proxmox F5 CM Install Script" --title "ADVANCED SETTINGS COMPLETE" --yesno "Ready to create an BIG-IP Next CM  VM?" --no-button Do-Over 10 58); then
    echo -e "${RD}Creating an F5 BIG-IP Next Configuration Manager VM using the above advanced settings${CL}"
  else
    header_info
    echo -e "${RD}Using Advanced Settings${CL}"
    advanced_settings
  fi
  CIUSER="admin"
  SOCKET="1"


}

function start_script() {
  if (whiptail --backtitle "Proxmox F5 CM Install Script" --title "SETTINGS" --yesno "Use Default Settings?" --no-button Advanced 10 58); then
    header_info
    echo -e "${BL}Using Default Settings${CL}"
    default_settings
  else
    header_info
    echo -e "${RD}Using Advanced Settings${CL}"
    advanced_settings
  fi
}

prompt_for_input
check_root
arch_check
pve_check
ssh_check
start_script

echo -e "${DGN}Using Virtual Machine ID: ${BGN}${VMID}${CL}"
echo -e "${DGN}Using Machine Type: ${BGN}${MACHINE}${CL}"
echo -e "${DGN}Using Disk Cache: ${BGN}None${CL}"
echo -e "${DGN}Using Hostname: ${BGN}${HN}${CL}"
echo -e "${DGN}Using CPU Model: ${BGN}${CPU_TYPE}${CL}"
echo -e "${DGN}Allocated Cores: ${BGN}${CORE_COUNT}${CL}"
echo -e "${DGN}Allocated RAM: ${BGN}${RAM_SIZE}${CL}"
echo -e "${DGN}Using Bridge1: ${BGN}${BRG1}${CL}"
echo -e "${DGN}Using Bridge 1 MAC Address: ${BGN}${MAC1}${CL}"
echo -e "${DGN}Using Bridge 1 VLAN1: ${BGN}Default${CL}"
echo -e "${DGN}Using Bridge2: ${BGN}${BRG2}${CL}"
echo -e "${DGN}Using Bridge 2 MAC Address: ${BGN}${MAC2}${CL}"
echo -e "${DGN}Using Bridge 2 VLAN2: ${BGN}Default${CL}"
echo -e "${DGN}Using adminuser: ${BGN}${CIUSER}${CL}"
echo -e "${DGN}Using admin password: ${BGN}${CIPWD}${CL}"
echo -e "${BL}Creating an F5 BIG-IP Next Configuration Manager VM  using the above default settings${CL}"
echo -e "${DGN}File Location: ${BGN}$INPUT_TYPE${CL}"
echo -e "${DGN}File Path: ${BGN}$INPUT_VALUE${CL}"

msg_info "Validating Storage"
while read -r line; do
  TAG=$(echo $line | awk '{print $1}')
  TYPE=$(echo $line | awk '{printf "%-10s", $2}')
  FREE=$(echo $line | numfmt --field 4-6 --from-unit=K --to=iec --format %.2f | awk '{printf( "%9sB", $6)}')
  ITEM="  Type: $TYPE Free: $FREE "
  OFFSET=2
  if [[ $((${#ITEM} + $OFFSET)) -gt ${MSG_MAX_LENGTH:-} ]]; then
    MSG_MAX_LENGTH=$((${#ITEM} + $OFFSET))
  fi
  STORAGE_MENU+=("$TAG" "$ITEM" "OFF")
done < <(pvesm status -content images | awk 'NR>1')
VALID=$(pvesm status -content images | awk 'NR>1')
if [ -z "$VALID" ]; then
  msg_error "Unable to detect a valid storage location."
  exit
elif [ $((${#STORAGE_MENU[@]} / 3)) -eq 1 ]; then
  STORAGE=${STORAGE_MENU[0]}
else
  while [ -z "${STORAGE:+x}" ]; do
    STORAGE=$(whiptail --backtitle "Proxmox VE Helper Scripts" --title "Storage Pools" --radiolist \
      "Which storage pool you would like to use for ${HN}?\nTo make a selection, use the Spacebar.\n" \
      16 $(($MSG_MAX_LENGTH + 23)) 6 \
      "${STORAGE_MENU[@]}" 3>&1 1>&2 2>&3) || exit
  done
fi
msg_ok "Using ${CL}${BL}$STORAGE${CL} ${GN}for Storage Location."
msg_ok "Virtual Machine ID is ${CL}${BL}$VMID${CL}."
msg_info "Retrieving the URL for the BIG-IP Next Configuration Manager Disk Image"
sleep 1
msg_ok "${CL}${BL}${URL}${CL}"

if [[ "$INPUT_TYPE" == "URL" ]]; then
  parse_url "$INPUT_VALUE"
  wget -O "$URIFILE" -q --show-progress "$INPUT_VALUE"
  FILE="$PWD"/"$URIFILE"
else
  FILE="$INPUT_VALUE"
fi

echo -en "\e[1A\e[0K"

msg_ok "Downloaded ${CL}${BL}${FILE}${CL}"

STORAGE_TYPE=$(pvesm status -storage $STORAGE | awk 'NR>1 {print $2}')
case $STORAGE_TYPE in
  nfs | dir)
    DISK_EXT=".qcow2"
    DISK_REF="$VMID/"
    DISK_IMPORT="-format qcow2"
    THIN=""
    ;;
  btrfs)
    DISK_EXT=".raw"
    DISK_REF="$VMID/"
    DISK_IMPORT="-format raw"
    FORMAT=",efitype=4m"
    THIN=""
    ;;
esac
for i in {0,1}; do
  disk="DISK$i"
  eval DISK${i}=vm-${VMID}-disk-${i}${DISK_EXT:-}
  eval DISK${i}_REF=${STORAGE}:${DISK_REF:-}${!disk}
done

msg_info "Creating an F5 BIG-IP Next CM  VM"

#rename the file to end with ".qcom2" or import will fail
FILE=$(rename_qcow_file $FILE)

qm create $VMID --memory $RAM_SIZE --socket $SOCKET --cores $CORE_COUNT --bios seabios --cpu=$CPU_TYPE --name $HN --ostype=l26 \
  -net0 virtio,bridge=$BRG1,macaddr=$MAC1 -net1 virtio,bridge=$BRG2,macaddr=$MAC2 --scsihw virtio-scsi-single \
  --citype nocloud --ciupgrade=0 --ciuser=$CIUSER --cipassword=$CIPWD --ide2=${STORAGE}:cloudinit
qm set $VMID \
  --virtio0 ${STORAGE}:0,import-from="$FILE" \
  -boot order=virtio0

msg_ok "Created a BIG-IP Next Configuration Manager VM ${CL}${BL}(${HN})"
msg_ok "Completed Successfully!\n"
