#!/bin/bash

readonly prog_name="ImposTOR"
readonly version="1.1.2"
readonly signature="GNU GPL version 3"

export red="$(tput setaf 1)"
export green="$(tput setaf 2)"
export blue="$(tput setaf 4)"
export white="$(tput setaf 7)"
export b="$(tput bold)"
export reset="$(tput sgr0)"

set -euo pipefail

i="impostor"
installl="/usr/bin"

die() {
    printf "${red}%s${reset}\\n" "[ERROR] $*" >&2
    exit 1
}

info() {
    printf "${b}${blue}%s${reset} ${b}%s${reset}\\n" "::" "${@}"
}


check_root() {
    if [[ "${UID}" -ne 0 ]]; then
        die "R U N   T H I S   S C R I P T   I N   R O O T"
    fi
}

banner() {
    printf "%s\\n\\n" "${red}${b}


    ██▓ ███▄ ▄███▓ ██▓███    ▒█████     ██████  █████████▓ ▒█████   ██▀███  
    ▓██▒ ▓██▒▀█▀ ██ ▒▓██░  ██▒ ▒██▒  ██▒▒ ██    ▒   ▓██▒▓▒ ▒██▒  ██▒ ▓██ ▒ ██▒
    ▒██▒ ▓██    ▓██ ░▓██░ ██▓▒ ▒██░  ██▒░  ▓██▄   ▒ ▓██░▒ ░▒██░  ██▒ ▓██ ░▄█ ▒
    ░██░ ▒██    ▒██  ▒██▄█▓▒ ▒ ▒██   ██░   ▒   ██▒░ ▓██▓░  ▒██   ██░ ▒██▀▀█▄  
    ░██░ ▒██▒   ░██▒ ▒██▒ ░  ░  ░████▓▒░ ▒██████▒▒  ▒██▒░   ░████▓▒░ ░██▓ ▒██▒
    ░▓  ░  ▒░   ░  ░ ▒▓▒░ ░  ░░  ▒░▒░▒░ ▒  ▒▓▒ ▒ ░  ▒ ░░    ░▒░▒░▒░  ░ ▒▓ ░▒▓░
    ▒ ░░  ░      ░░ ▒ ░       ░ ▒ ▒░ ░ ░▒   ░ ░    ░       ░▒ ▒░    ░▒ ░ ▒░
    ▒ ░░      ░   ░ ░       ░ ░ ░ ▒  ░  ░   ░    ░       ░ ░░ ▒     ░░   ░ 
    ░         ░                ░ ░        ░                ░ ░      ░     

    ${reset}"
    printf "%s\\n\\n" "» λ QT CHAATHAN product₍˄·͈༝·͈˄₎◞ ̑̑"
}

install(){
    if [[ ! -f "./$i" ]]; then
        die "Source file ./$i not found."
    fi

    read -rp "Installation? System wide (S) / current user only (u) [S/u]: " choice
    choice="${choice:-S}"   # default S

    if [[ "${choice,,}" == "u" ]]; then
        installl="$HOME/bin"
        mkdir -p "$installl"
    fi

    mv impostor "$installl"
    chmod +x "$installl/$i"
    chown root:root "$installl/$i" 2>/dev/null 
    if [ "${choice,,}" = "s" ]; then
        echo "$USER ALL=(ALL) NOPASSWD: $installl/$i" | sudo tee -a /etc/sudoers.d/"${prog_name:-impostor}" >/dev/null 2>&1 || true
    fi
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Confirm with the user before deletion
    read -p "Are you sure you want to delete the source folder '${script_dir}'? [y/N]: " confirm
    if [[ "${confirm,,}" == "y" ]]; then
        echo "Deleting folder: ${script_dir}"
        rm -rf "${script_dir}"
        echo "Folder deleted."
    else
        echo "Aborted."
    fi

}

clear
banner
check_root
install