#!/usr/bin/env bash

# Author: Russell Moore
# Author: tteck (tteckster)
# Copyright (c) 2021-2024 tteck
# all other content Copyright (c) 2024
# LicenseL MIT
# https://github.com/russgmoore/F5-Proxmox-Scripts 
# https://github.com/tteck/Proxmox/raw/main/LICENSE

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

#Define some vars
VMID=""
MACHINE=""
HN=""
CPU_TYPE=""
SOCKET=""
CORE_COUNT=""
RAM_SIZE=""
BRG0=""
BRG1=""
MAC0=""
MAC1=""
IPADDR0=""
IPADDR1=""
GW=""
NS=""
VLAN0=""
VLAN1=""
SSHKEYFILE=""
PRODUCT="F5 BIG-IP NEXT CM"


#our error handler
function error_handler() {
  local exit_code="$?"
  local line_number="$1"
  local command="$2"
  local error_message="${RD}[ERROR]${CL} in line ${RD}$line_number${CL}: exit code ${RD}$exit_code${CL}: while executing command ${YW}$command${CL}"
  echo -e "\n$error_message\n"
  cleanup_vmid
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


# Function to parse the storage.cfg file and present items with "snippets" content
function select_snippets_storage() {
    # Declare an array to hold the storage information
    declare -a storage_items

    # Read the /etc/pve/storage.cfg file
    while IFS= read -r line; do
        # Check if the line starts with non-whitespace (new stanza)
        if [[ ! $line =~ ^\s && $line =~ ^[^:]+:[[:space:]]*([^[:space:]]+) ]]; then
            # Extract the name from the second field
            stanza_name=$(echo "$line" | awk '{print $2}')

            # Look for the path line in the subsequent lines
            while IFS= read -r line; do
                # Check for the path line that starts with whitespace
                if [[ $line =~ ^[[:space:]]+path ]]; then
                    stanza_path=$(echo "$line" | awk '{print $2}')
                # if the stanza has a content type of snippets then store this item in the array
                elif [[ $line =~ ^[[:space:]]+content && $line =~ snippets ]]; then
                    # Store the name and path in the array
                    storage_items+=("$stanza_name:$stanza_path/snippets" "Storage Name: $stanza_name" "OFF")
                    break  # Exit the inner loop after finding the path
                elif [[ ! $line =~ ^\s ]]; then
                    # If a new stanza starts, break out of the inner loop
                    break
                fi
            done
        fi
    done < /etc/pve/storage.cfg

    # Present the array as a radio list selection with whiptail
    if [ ${#storage_items[@]} -eq 0 ]; then
        echo "No storage items found."
        return
    fi

    # Loop until a valid selection is made
    while true; do
        selected_item=$(whiptail --title "Select Storage Item" --radiolist \
           "Choose a place to store our snippets content:" 15 60 4 "${storage_items[@]}" 3>&1 1>&2 2>&3)

        # Check exit status of whiptail
        exit_status=$?
        if [ $exit_status = 0 ]; then
            # Split the selected item into name and path
            selected_name="${selected_item%%:*}"
            selected_path="${selected_item##*:}"
            break  # Exit the loop on valid selection
        else
            echo "Operation canceled."
            break
        fi
    done


    SNIP_STOR="$selected_name"
    SNIP_PATH="$selected_path"
}

# Function to check if a file exists and is readable
function is_valid_file() {
    local file="$1"
    if [[ -f "$file" && -r "$file" ]]; then
        return 0
    else
        return 1
    fi
}


# Function to rename file if it ends with ".qcow" to ".qcow2"
function rename_qcow_file() {
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

function prompt_for_image() {
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
          if host "$host" &> /dev/null; then
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

  INPUT_TYPE="$input_type"
  INPUT_VALUE="$selected_input"
}

function request_token() {
    local token
    while true; do
        token=$(whiptail --title "XC SMSv2 Site Token" --inputbox "Please enter the token for the XC SMSv2 Site:" 10 60 3>&1 1>&2 2>&3)
        if [ $? -eq 0 ]; then
            if [ -n "$token" ]; then
                whiptail --title "Token Provided" --msgbox "Token provided: $token" 10 60
                TOKEN="$token"
                return 0
            else
                whiptail --title "Error" --msgbox "Error: Token is required to continue." 10 60
            fi
        else
            whiptail --title "Cancelled" --msgbox "Operation cancelled." 10 60
            return 1
        fi
    done
}

function parse_url() {
  local url=$1
  local urlhost=""
  local uribase=""

  # Extract the hostname from the URL
  urlhost=$(echo "$url" | awk -F[/:] '{print $4}')

  # Extract the URI without the query string and strip the leading "/"
  uribase=$(echo "$url" | sed 's|.*/||; s|\?.*||')

  URLHOST="$urlhost"
  URIFILE="$uribase"
}


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

function snippets_check() {
  storage_status=$(pvesm status -content snippets | awk 'NR>1')
  if [ -z "$storage_status" ]; then
    msg_error "Unable to detect a valid storage location that accepts SNIPPETS!"
    exit
  else
    msg_ok "Storage found with content type 'snippets'."
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

function is_valid_ipv4() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if ((octet < 0 || octet > 255)); then
                return 1
            fi
        done
        return 0
    else
        return 1
    fi
}

function ssh_check() {
  if command -v pveversion >/dev/null 2>&1; then
    if [ -n "${SSH_CLIENT:+x}" ]; then
      if whiptail --backtitle "F5 Install Script for Proxmox" --defaultno --title "SSH DETECTED" --yesno "It's suggested to use the Proxmox shell instead of SSH, since SSH can create issues while gathering variables. Would you like to proceed with using SSH?" 10 62; then
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
  MACHINE="q35"
  HN="node0"
  CPU_TYPE="host"
  SOCKET=1
  CORE_COUNT="4"
  RAM_SIZE="16384"
  BRG0="vmbr0"
  MAC0="$GEN_MAC0"
  IPADDR0="dhcp"
  msg_ok "${DGN}Using Virtual Machine ID: ${BGN}${VMID}${CL}"
  msg_ok "${DGN}Using Machine Type: ${BGN}${MACHINE}${CL}"
  msg_ok "${DGN}Using Hostname: ${BGN}${HN}${CL}"
  msg_ok "${DGN}Using CPU Model: ${BGN}${CPU_TYPE}${CL}"
  msg_ok "${DGN}Allocated Cores: ${BGN}${CORE_COUNT}${CL}"
  msg_ok "${DGN}Allocated RAM: ${BGN}${RAM_SIZE}${CL}"
  msg_ok "${DGN}Using Bridge: ${BGN}${BRG0}${CL}"
  msg_ok "${DGN}Using Bridge MAC Address: ${BGN}${MAC0}${CL}"
  msg_ok "${DGN}IP: ${BGN}${IPADDR0}${CL}"
  msg_ok "${DGN}File Location: ${BGN}$INPUT_TYPE${CL}"
  msg_ok "${DGN}File Path: ${BGN}$INPUT_VALUE${CL}"
  msg_ok "${BL}Creating an F5 Distributed Cloud Customer Edge VM  using the above default settings${CL}"
}

function advanced_settings() {
  while true; do
    if VMID=$(whiptail --backtitle "F5 Install Script for Proxmox" --inputbox "Set Virtual Machine ID" 8 58 $NEXTID --title "VIRTUAL MACHINE ID" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
      if [ -z "$VMID" ]; then
        VMID="$NEXTID"
      fi
      if pct status "$VMID" &>/dev/null || qm status "$VMID" &>/dev/null; then
        echo -e "${CROSS}${RD} ID $VMID is already in use${CL}"
        sleep 2
        continue
      fi
      msg_ok "${DGN}Virtual Machine ID: ${BGN}$VMID${CL}"
      break
    else
      exit-script
    fi
  done

  if VM_NAME=$(whiptail --backtitle "F5 Install Script for Proxmox" --inputbox "Set Hostname" 8 58 node0 --title "HOSTNAME" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $VM_NAME ]; then
      HN="node0"
      msg_ok "${DGN}Using Hostname: ${BGN}$HN${CL}"
    else
      HN=$(echo ${VM_NAME,,} | tr -d ' ')
      msg_ok "${DGN}Using Hostname: ${BGN}$HN${CL}"
    fi
  else
    exit-script
  fi

  if MACH=$(whiptail --backtitle "F5 Install Script for Proxmox" --title "MACHINE TYPE" --radiolist --cancel-button Exit-Script "Choose Type" 10 58 2 \
    "i440fx" "Machine i440fx" OFF \
    "q35" "Machine q35" ON \
    3>&1 1>&2 2>&3); then
    if [ $MACH = q35 ]; then
      msg_ok "${DGN}Using Machine Type: ${BGN}$MACH${CL}"
      MACHINE="q35"
    else
      msg_ok "${DGN}Using Machine Type: ${BGN}$MACH${CL}"
      MACHINE="i440fx"
    fi
  else
    exit-script
  fi


  if CPU_TYPE=$(whiptail --backtitle "F5 Install Script for Proxmox" --title "CPU MODEL" --radiolist "Choose" --cancel-button Exit-Script 10 58 2 \
    "0" "x86-64-v2-AES (Default)" ON \
    "1" "Host" OFF \
    3>&1 1>&2 2>&3); then
    if [ $CPU_TYPE = "1" ]; then
      msg_ok "${DGN}Using CPU Model: ${BGN}host${CL}"
      CPU_TYPE="host"
    else
      msg_ok "${DGN}Using CPU Model: ${BGN}x86-64-v2-AES${CL}"
      CPU_TYPE="x86-64-v2-AES"
    fi
  else
    exit-script
  fi

  if CORE_COUNT=$(whiptail --backtitle "F5 Install Script for Proxmox" --inputbox "Allocate CPU Cores" 8 58 8 --title "CORE COUNT (minimum 4)" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $CORE_COUNT ]; then
      CORE_COUNT="4"
      msg_ok "${DGN}Allocated Cores: ${BGN}$CORE_COUNT${CL}"
    else
      msg_ok "${DGN}Allocated Cores: ${BGN}$CORE_COUNT${CL}"
    fi
  else
    exit-script
  fi

  if RAM_SIZE=$(whiptail --backtitle "F5 Install Script for Proxmox" --inputbox "Allocate RAM in MiB" 8 58 16384 --title "RAM (minimum 16GB)" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $RAM_SIZE ]; then
      RAM_SIZE="16384"
      msg_ok "${DGN}Allocated RAM: ${BGN}$RAM_SIZE${CL}"
    else
      msg_ok "${DGN}Allocated RAM: ${BGN}$RAM_SIZE${CL}"
    fi
  else
    exit-script
  fi

  if BRG0=$(whiptail --backtitle "F5 Install Script for Proxmox" --inputbox "Set a Bridge" 8 58 vmbr0 --title "BRIDGE 1" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $BRG0 ]; then
      BRG0="vmbr0"
      msg_ok "${DGN}Interface 0 Bridge: ${BGN}$BRG0${CL}"
    else
      msg_ok "${DGN}Interface 0 Bridge: ${BGN}$BRG0${CL}"
    fi
  else
    exit-script
  fi

  if MAC0=$(whiptail --backtitle "F5 Install Script for Proxmox" --inputbox "Set a Bridge 1 MAC Address" 8 58 $GEN_MAC0 --title "Bridge 1 MAC ADDRESS" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $MAC0 ]; then
      MAC0="$GEN_MAC0"
      msg_ok "${DGN}Interface 0 MAC Address: ${BGN}$MAC0${CL}"
    else
      MAC0="$MAC0"
      msg_ok "${DGN}Interface 0 MAC Address: ${BGN}$MAC0${CL}"
    fi
  else
    exit-script
  fi

  if VLAN0=$(whiptail --backtitle "F5 Install Script for Proxmox" --inputbox "Set a Vlan for bridge 1(leave blank for default)" 8 58 --title "VLAN Bridge 1" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
    if [ -z $VLAN0 ]; then
      VLAN0="Default"
      VLAN0=""
      msg_ok "${DGN}Interface 0 Vlan: ${BGN}$VLAN0${CL}"
    else
      VLAN0="$VLAN0"
      msg_ok "${DGN}Interface 0 Vlan: ${BGN}$VLAN0${CL}"
    fi
  else
    exit-script
  fi

  while true; do
    IPADDR0=$(whiptail --backtitle "F5 Install Script for Proxmox" --inputbox "Set a Static IPv4 CIDR Address (/24)" 8 58 dhcp --title "IP ADDRESS" 3>&1 1>&2 2>&3)
    exit_status=$?
    if [ $exit_status -eq 0 ]; then
      if [ "$IPADDR0" = "dhcp" ]; then
        msg_ok "${DGN}IP Address for interface 0: ${BGN}$IPADDR0${CL}"
        break
      else
        if [[ "$IPADDR0" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
          msg_ok "${DGN}IP Address for interface 0: ${BGN}$IPADDR0${CL}"
          break
        else
          whiptail --backtitle "F5 Install Script for Proxmox" --msgbox "$IPADDR0 is an invalid IPv4 CIDR address. Please enter a valid IPv4 CIDR address or 'dhcp'" 8 58
        fi
      fi
    else
      exit-script
    fi
  done

  if [ "$IPADDR0" != "dhcp" ]; then
    while true; do
      GATE1=$(whiptail --backtitle "F5 Install Script for Proxmox" --inputbox "Enter gateway IP address" 8 58 --title "Gateway IP" 3>&1 1>&2 2>&3)
      if [ -z "$GATE1" ]; then
        whiptail --backtitle "F5 Install Script for Proxmox" --msgbox "Gateway IP address cannot be empty" 8 58
      elif [[ ! "$GATE1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        whiptail --backtitle "F5 Install Script for Proxmox" --msgbox "Invalid IP address format" 8 58
      else
        GW="$GATE1"
        msg_ok "${DGN}Using Gateway IP Address: ${BGN}$GW${CL}"
        break
      fi
    done
  else
    GW=""
    msg_ok "${DGN}Using Gateway IP Address: ${BGN}Default${CL}"
  fi

  if [ "$IPADDR0" != "dhcp" ]; then
    while true; do
      NS1=$(whiptail --backtitle "F5 Install Script for Proxmox" --inputbox "Enter Nameserver IP address" 8 58 --title "Nameserver IP" 3>&1 1>&2 2>&3)
      if [ -z "$NS1" ]; then
        whiptail --backtitle "F5 Install Script for Proxmox" --msgbox "Nameserver IP address cannot be empty" 8 58
      elif [[ ! "$NS1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        whiptail --backtitle "F5 Install Script for Proxmox" --msgbox "Invalid IP address format" 8 58
      else
        NS="--nameserver $NS1"
        msg_ok"${DGN}Using Nameserver IP Address: ${BGN}$NS${CL}"
        break
      fi
    done
  else
    NS=""
  fi

  if whiptail --backtitle "F5 Install Script for Proxmox" --defaultno --title "Second interface" --yesno "Would you like to configure a second interface?" 10 60; then

    if BRG1=$(whiptail --backtitle "F5 Install Script for Proxmox" --inputbox "Set a Bridge" 8 58 vmbr1 --title "BRIDGE 2" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
      if [ -z $BRG1 ]; then
        BRG1="vmbr1"
        msg_ok "${DGN}Interface 1 Bridge: ${BGN}$BRG1${CL}"
      else
        msg_ok "${DGN}Interface 1 Bridge: ${BGN}$BRG1${CL}"
      fi
    else
      exit-script
    fi

    if MAC1=$(whiptail --backtitle "F5 Install Script for Proxmox" --inputbox "Set a Bridge 2 MAC Address" 8 58 $GEN_MAC1 --title "Bridge 2 MAC ADDRESS" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
      if [ -z $MAC1 ]; then
        MAC1="$GEN_MAC1"
        msg_ok "${DGN}Interface 1 MAC Address: ${BGN}$MAC1${CL}"
      else
        MAC1="$MAC1"
        msg_ok "${DGN}Interface 1 MAC Address: ${BGN}$MAC1${CL}"
      fi
    else
      exit-script
    fi

    if VLAN1=$(whiptail --backtitle "F5 Install Script for Proxmox" --inputbox "Set a Vlan for bridge 2(leave blank for default)" 8 58 --title "VLAN Bridge 2" --cancel-button Exit-Script 3>&1 1>&2 2>&3); then
      if [ -z $VLAN1 ]; then
        VLAN1="Default"
        VLAN1=""
        msg_ok "${DGN}Interface 1 Vlan: ${BGN}$VLAN1${CL}"
      else
        VLAN1="$VLAN1"
        msg_ok "${DGN}Interface 1 Vlan: ${BGN}$VLAN1${CL}"
      fi
    else
      exit-script
    fi

    while true; do
      IPADDR1=$(whiptail --backtitle "F5 Install Script for Proxmox" --inputbox "Set a Static IPv4 CIDR Address (/24)" 8 58 dhcp --title "IP ADDRESS" 3>&1 1>&2 2>&3)
      exit_status=$?
      if [ $exit_status -eq 0 ]; then
        if [ "$IPADDR0" = "dhcp" ]; then
          msg_ok "${DGN}IP Address for interface 1: ${BGN}$IPADDR0${CL}"
          break
        else
          if [[ "$IPADDR0" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; then
            msg_ok "${DGN}IP Address for interface 1: ${BGN}$IPADDR0${CL}"
            break
          else
            whiptail --backtitle "F5 Install Script for Proxmox" --msgbox "$IPADDR0 is an invalid IPv4 CIDR address. Please enter a valid IPv4 CIDR address or 'dhcp'" 8 58
          fi
        fi
      else
        exit-script
      fi
    done
  else
    BRG1=""
    MAC1=""
    VLAN1=""
    IPADDR1="dhcp"
  fi
 
  if [ -z "${NS}" ]; then
    if whiptail --backtitle "F5 Install Script for Proxmox" --defaultno --title "Define Nameserver" --yesno "Do you want to define a Nameserver?" 10 60; then
        while true; do
            NS1=$(whiptail --inputbox "Enter the Nameserver IP address:" 10 60 3>&1 1>&2 2>&3)
            exitstatus=$?
            if [ $exitstatus = 0 ]; then
                if is_valid_ipv4 "$NS"; then
                    NS="--nameserver $NS1"
                    msg_ok "Nameserver set to: ${DGN}NameServer: ${BGN}$NS1${CL}"
                    break
                else
                    whiptail --msgbox "Invalid IPv4 address. Please enter a valid IP address." 10 60
                fi
            else
                NS=""
                break
            fi
        done
    else
        NS=""
    fi
  fi

  if whiptail --backtitle "F5 Install Script for Proxmox" --defaultno --title "Include SSH Public Keys" --yesno "Do you want to define a file location for SSH public keys to include?" 10 60; then
      while true; do
          SSHKEYFILE1=$(whiptail --inputbox "Enter the full path to the SSH public key file:" 10 60 3>&1 1>&2 2>&3)
          exitstatus=$?
          if [ $exitstatus = 0 ]; then
              if is_valid_file "$SSHKEYFILE1"; then
                  SSHKEYFILE="--sshkeys $SSHKEYFILE1"
                  msg_ok "SSH key file  set to: ${DGN}KeyFile: ${BGN}$SSHKEYFILE1${CL}"
                  break
              else
                  whiptail --msgbox "Invalid file. The file does not exist or is not readable. Please enter a valid file path." 10 60
              fi
          else
              SSHKEYFILE=""
              break
          fi
      done
  else
      SSHKEYFILE=""
  fi


  if (whiptail --backtitle "F5 Install Script for Proxmox" --title "ADVANCED SETTINGS COMPLETE" --yesno "Ready to create a $PROCUCT?" --no-button Do-Over 10 58); then
    msg_info "${RD}Creating an F5 Distributed Cloud Customer Edge VM using the above advanced settings${CL}"
  else
    header_info
    echo -e "${RD}Using Advanced Settings${CL}"
    advanced_settings
  fi

  SOCKET="1"

}

function start_script() {
  if (whiptail --backtitle "F5 Install Script for Proxmox" --title "SETTINGS" --yesno "Use Default Settings?" --no-button Advanced 10 58); then
    header_info
    echo -e "${BL}Using Default Settings${CL}"
    default_settings
  else
    header_info
    echo -e "${RD}Using Advanced Settings${CL}"
    advanced_settings
  fi
}

function get_storage() {
    local content_type="$1"

    # Enumerate Storage for locations to place our Cloud-Init Snippet
                   
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
    done < <(pvesm status -content "$content_type" | awk 'NR>1')
             
    VALID=$(pvesm status -content "$content_type" | awk 'NR>1')
            
    if [ -z "$VALID" ]; then 
      msg_error "Unable to detect a valid storage location for content type: $content_type." 
      exit 1
    elif [ $((${#STORAGE_MENU[@]} / 3)) -eq 1 ]; then
      mySTORAGE=${STORAGE_MENU[0]}
    else 
      while [ -z "${mySTORAGE:+x}" ]; do
        mySTORAGE=$(whiptail --backtitle "F5 Install Script for Proxmox" --title "Storage Pools" --radiolist \
          "Which storage pool you would like to use for ${HN}?\nTo make a selection, use the Spacebar.\n" \
          16 $(($MSG_MAX_LENGTH + 23)) 6 \
          "${STORAGE_MENU[@]}" 3>&1 1>&2 2>&3) || exit 1
      done
    fi 

    echo "$mySTORAGE"
}

function configure_net0() {
    # Ensure BRG0 and MAC0 are defined
    if [ -z "$BRG0" ] || [ -z "$MAC0" ]; then
        echo "Error: BRG0 and MAC0 must be defined."
        return 1
    fi

    # Check if VLAN0 is defined and is an integer between 1 and 4094
    if [[ -n "$VLAN0" && "$VLAN0" =~ ^[0-9]+$ && "$VLAN0" -ge 1 && "$VLAN0" -le 4094 ]]; then
        result="bridge=$BRG0,macaddr=$MAC0,tag=$VLAN0"
    else
        result="bridge=$BRG0,macaddr=$MAC0"
    fi

    echo "$result"
}

function configure_net1() {
    local variable=""

    # Check if $IPADDR1 is defined and is a valid IPv4 address in CIDR format
    if [[ "${IPADDR1}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$ ]]; then
        ip_valid=true
    else
        ip_valid=false
    fi

    # Check if $VLAN1 is set, not empty, and is an integer between 1 and 4094
    if [[ -n "${VLAN1}" && "${VLAN1}" =~ ^[0-9]+$ && "${VLAN1}" -ge 1 && "${VLAN1}" -le 4094 ]]; then
        vlan_valid=true
    else
        vlan_valid=false
    fi

    # Set the variable based on the conditions
    if $ip_valid && $vlan_valid; then
        variable="--net1 virtio,bridge=${BRG1},macaddr=${MAC1},tag=${VLAN1} --ipconfig1 ip=${IPADDR1}"
    elif $ip_valid; then
        variable="--net1 virtio,bridge=${BRG1},macaddr=${MAC1} --ipconfig1 ip=${IPADDR1}"
    elif $vlan_valid; then
        variable="--net1 virtio,bridge=${BRG1},macaddr=${MAC1},tag=${VLAN1} --ipconfig1 ip=dhcp"
    else
        variable="--net1 virtio,bridge=${BRG1},macaddr=${MAC1} --ipconfig1 ip=dhcp"
    fi

    echo "${variable}"
}

function config_ipaddr0() {
    # Check if IPADDR0 is defined
    if [ -z "${IPADDR0+x}" ]; then
        echo "IPADDR0 is not defined globally."
        return 1
    fi

    # Initialize the variable
    ip_variable=""

    # Check if IPADDR0 is "dhcp" or empty
    if [ "$IPADDR0" = "dhcp" ] || [ -z "$IPADDR0" ]; then
        ip_variable="ip=dhcp"
    else
        # Check if IPADDR0 is in CIDR notation
        if [[ "$IPADDR0" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
            ip_variable="ip=$IPADDR0"
            # Check if GW is defined and is a valid IP address
            if [ -n "${GW+x}" ] && [[ "$GW" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                ip_variable+=",gw=$GW"
            fi
        else
            echo "IPADDR0 is defined but not in CIDR notation."
            return 1
        fi
    fi

    # Output the result
    echo "$ip_variable"
    
}

function create_cloud_config() {
    local location="$1"
    local filename="$2"
    local token="$3"

    # Create the full path for the file
    local filepath="$location/$filename"

    # Contents to be written to the file
    local content="#cloud-config
write_files:
- path: /etc/vpm/user_data
  content: |
    token: $token
  owner: root
  permissions: '0644'"

    # Write the content to the file
    echo "$content" > "$filepath"

}

#generate some mac addresses
GEN_MAC0=02:$(openssl rand -hex 5 | awk '{print toupper($0)}' | sed 's/\(..\)/\1:/g; s/.$//')
GEN_MAC1=02:$(openssl rand -hex 5 | awk '{print toupper($0)}' | sed 's/\(..\)/\1:/g; s/.$//')

#determine the next available ID for a VM
NEXTID=$(pvesh get /cluster/nextid)

# Configure a temporary directory to work in
TEMP_DIR=$(mktemp -d)
pushd $TEMP_DIR >/dev/null
if whiptail --backtitle "F5 Install Script for Proxmox" --title "$PRODUCT" --yesno "This will create a new $PRODUCT. Proceed?" 10 58; then
  :
else
  header_info && echo -e "⚠ User exited script \n" && exit
fi

#setup the name for our snippet file 

snippets_check
check_root
arch_check
pve_check
ssh_check
#request_token
prompt_for_image

if [[ "$INPUT_TYPE" == "URL" ]]; then
  parse_url "$INPUT_VALUE"
fi

start_script

#SNIPPET_FILE="$VMID.yaml"

# build configuration for the --ipconfig0 option
IPCONFIG0=$(config_ipaddr0)

#configure our network  options
NET0=$(configure_net0)

# Check if $BRG1 is set as that measn we are defining a second interface
if [ -z "${BRG1}" ]; then
  NET1=""
else
  NET1=$(configure_net1)
fi

msg_info "Validating Storage for content type: images"
STORAGE=$(get_storage images)
#select_snippets_storage

msg_ok "VM Image will be store in: ${CL}${BL}$STORAGE${CL} ${GN}"
#msg_ok "Cloud-Init snippets for the $PRODUCT  will be stored in: ${CL}${BL}$SNIP_STOR${CL} ${GN}"

#create_cloud_config $SNIP_PATH $SNIPPET_FILE $TOKEN

msg_ok "Snippet created in directory ${CL}${BL}$SNIP_PATH${CL} named ${CL}${BL}$SNIPPET_FILE${CL}"
msg_ok "Virtual Machine ID is ${CL}${BL}$VMID${CL}."
msg_info "Retrieving the Disk Image F5 Distributed Cloud Customer Edge"
sleep 1
msg_ok "${CL}${BL}${URL}${CL}"

if [[ "$INPUT_TYPE" == "URL" ]]; then
  parse_url "$INPUT_VALUE"
  wget -O "$URIFILE" -q --show-progress "$INPUT_VALUE"
  FILE="$PWD"/"$URIFILE"
else
  FILE="$INPUT_VALUE"
fi

#rename the file to end with ".qcom2" or import will fail
FILE=$(rename_qcow_file $FILE)

echo -en "\e[1A\e[0K"

msg_ok "Retrieved ${CL}${BL}${FILE}${CL}"

msg_info "Creating your $PRODUCT VM"

qm create $VMID --cores $CORE_COUNT --memory $RAM_SIZE --cpu $CPU_TYPE \
  --machine $MACHINE --name $HN --ostype l26 \
  --net0 virtio,$NET0 --ipconfig0 $IPCONFIG0 $NET1 \
  --scsihw virtio-scsi-single --boot order=scsi0  \
  --ide2 $STORAGE:cloudinit --scsi0 $STORAGE:0,import-from=$FILE \
  --cicustom user=$SNIP_STOR:snippets/$SNIPPET_FILE $NS $SSHKEYFILE

msg_ok "Created a F5 Distributed Cloud Customer Edge VM ${CL}${BL}(${HN})"
msg_ok "Completed Successfully!\n"
