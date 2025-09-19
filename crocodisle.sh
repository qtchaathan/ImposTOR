#!/usr/bin/env bash

################################################################################
#                                                                              #
# CrocoD.Isle                                                                  #
#                                                                              #
# version: 1.0.0                                                               #
#                                                                              #
# Cross-Distro Transparent Proxy through Tor                                   #
#                                                                              #
# Copyright (C) 2025 Cruz                                                      #
#                                                                              #
# Inspired by kalitorify and other tools                                       #
#                                                                              #
# GNU GENERAL PUBLIC LICENSE                                                   #
#                                                                              #
# This program is free software: you can redistribute it and/or modify         #
# it under the terms of the GNU General Public License as published by         #
# the Free Software Foundation, either version 3 of the License, or            #
# (at your option) any later version.                                          #
#                                                                              #
# This program is distributed in the hope that it will be useful,              #
# but WITHOUT ANY WARRANTY; without even the implied warranty of               #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                #
# GNU General Public License for more details.                                 #
#                                                                              #
# You should have received a copy of the GNU General Public License            #
# along with this program.  If not, see <http://www.gnu.org/licenses/>.        #
#                                                                              #
################################################################################

## General
#
# program information
readonly prog_name="CrocoD.Isle"
readonly version="1.0.0"
readonly signature="Copyright (C) 2025 Cruz"

# set colors for stdout
export red="$(tput setaf 1)"
export green="$(tput setaf 2)"
export blue="$(tput setaf 4)"
export white="$(tput setaf 7)"
export b="$(tput bold)"
export reset="$(tput sgr0)"

## Directories
readonly backup_dir="/tmp/crocodisle_backups"   # temporary backups

## Network settings
#
# Tor TransPort
readonly trans_port="9040"

# Tor DNSPort
readonly dns_port="5353"

# Tor VirtualAddrNetworkIPv4 and IPv6
readonly virtual_address_ipv4="10.192.0.0/10"
readonly virtual_address_ipv6="fc00::/7"

# LAN destinations that shouldn't be routed through Tor (IPv4 and IPv6)
readonly non_tor_ipv4="127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
readonly non_tor_ipv6="::1/128 fc00::/7 fe80::/10"

# Multicast ranges to drop for safety (mDNS etc.)
readonly multicast_ipv4="224.0.0.0/4"
readonly multicast_ipv6="ff00::/8"

## IP change interval (default 0 = disabled)
ip_change_interval=0  # in minutes

## PID for auto-restart background process
auto_restart_pid=""

## Show program banner
banner() {
printf "${b}${white}
_________                           ________       .___       .__          
\_   ___ \_______  ____   ____  ____\______ \      |   | _____|  |   ____  
/    \  \/\_  __ \/  _ \_/ ___\/  _ \|    |  \     |   |/  ___/  | _/ __ \ 
\     \____|  | \(  <_> )  \__(  <_> )    '   \    |   |\___ \|  |_\  ___/ 
 \______  /|__|   \____/ \___  >____/_______  / /\ |___/____  >____/\___  >
        \/                   \/             \/  \/          \/          \/ 
${reset}\\n\\n"
printf "${b}${white}=[ Transparent proxy through Tor ]${reset}\\n\\n"
}

## Print a message and exit with (1) when an error occurs
die() {
    printf "${red}%s${reset}\\n" "[ERROR] $*" >&2
    exit 1
}

## Print information
info() {
    printf "${b}${blue}%s${reset} ${b}%s${reset}\\n" "::" "${@}"
}

## Print `OK` messages
msg() {
    printf "${b}${green}%s${reset} %s\\n\\n" "[OK]" "${@}"
}

## Check if the program run as a root
check_root() {
    if [[ "${UID}" -ne 0 ]]; then
        die "Please run this program as a root!"
    fi
}

## Detect Tor UID dynamically (works across distros)
get_tor_uid() {
    tor_uid=$(ps -o uid= -C tor 2>/dev/null | head -n1 | tr -d ' ')
    if [[ -z "$tor_uid" ]]; then
        # Fallback for different user names
        tor_uid=$(id -u debian-tor 2>/dev/null || id -u tor 2>/dev/null)
    fi
    if [[ -z "$tor_uid" ]]; then
        die "Unable to detect Tor user UID. Ensure Tor is installed."
    fi
    echo "$tor_uid"
}

## Display program version
print_version() {
    printf "%s\\n" "${prog_name} ${version}"
    printf "%s\\n" "${signature}"
    printf "%s\\n" "License GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>"
    exit 0
}

## Configure general settings
#
# - packages: tor, curl, iptables, ip6tables
# - temporary backups
# - temporary torrc modifications
setup_general() {
    info "Check program settings"

    # packages
    declare -a dependencies=('tor' 'curl' 'iptables' 'ip6tables')
    for package in "${dependencies[@]}"; do
        if ! hash "${package}" 2>/dev/null; then
            die "'${package}' isn't installed, exit"
        fi
    done

    # Create backup dir if not exists
    mkdir -p "${backup_dir}"

    # Backup and modify torrc temporarily
    if [[ ! -f /etc/tor/torrc ]]; then
        die "/etc/tor/torrc file not exist, check Tor configuration"
    fi

    printf "%s\\n" "Temporarily configure /etc/tor/torrc for TransPort and DNSPort"

    if ! cp -f /etc/tor/torrc "${backup_dir}/torrc.backup"; then
        die "can't backup '/etc/tor/torrc'"
    fi

    # Append necessary configs if not present (temporary, will restore on stop)
    {
        echo "TransPort 0.0.0.0:${trans_port} IsolateSOCKSAuth"
        echo "TransPort [::]:${trans_port} IsolateSOCKSAuth"
        echo "DNSPort 0.0.0.0:${dns_port}"
        echo "DNSPort [::]:${dns_port}"
        echo "VirtualAddrNetworkIPv4 ${virtual_address_ipv4}"
        echo "VirtualAddrNetworkIPv6 ${virtual_address_ipv6}"
        echo "AutomapHostsOnResolve 1"
    } >> /etc/tor/torrc

    # DNS settings: /etc/resolv.conf
    printf "%s\\n" "Configure resolv.conf to use Tor DNSPort"

    if ! cp /etc/resolv.conf "${backup_dir}/resolv.conf.backup"; then
        die "can't backup '/etc/resolv.conf'"
    fi

    printf "%s\\n" "nameserver 127.0.0.1" > /etc/resolv.conf
    printf "%s\\n" "nameserver ::1" >> /etc/resolv.conf  # For IPv6

    # Reload systemd if available
    if hash systemctl 2>/dev/null; then
        systemctl --system daemon-reload
    fi
}

## iptables and ip6tables settings
#
# Usage: setup_firewall <arg>
#
# args:
#       set -> set rules for Tor transparent proxy (IPv4/IPv6)
#       restore -> restore default rules
setup_firewall() {
    local tor_uid=$(get_tor_uid)

    case "$1" in
        set)
            printf "%s\\n" "Set firewall rules (iptables and ip6tables)"

            # Flush current rules
            iptables -F
            iptables -X
            iptables -t nat -F
            iptables -t nat -X
            ip6tables -F
            ip6tables -X
            ip6tables -t nat -F
            ip6tables -t nat -X

            # Default policies
            iptables -P INPUT ACCEPT
            iptables -P FORWARD ACCEPT
            iptables -P OUTPUT ACCEPT
            ip6tables -P INPUT ACCEPT
            ip6tables -P FORWARD ACCEPT
            ip6tables -P OUTPUT ACCEPT

            # *nat OUTPUT for IPv4
            # NAT .onion addresses
            iptables -t nat -A OUTPUT -d ${virtual_address_ipv4} -p tcp --syn -j REDIRECT --to-ports ${trans_port}

            # NAT DNS to Tor
            iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports ${dns_port}
            iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports ${dns_port}  # DoT

            # Exclude Tor, loopback, local nets
            iptables -t nat -A OUTPUT -m owner --uid-owner ${tor_uid} -j RETURN
            iptables -t nat -A OUTPUT -o lo -j RETURN
            for lan in ${non_tor_ipv4}; do
                iptables -t nat -A OUTPUT -d ${lan} -j RETURN
            done

            # Redirect TCP to TransPort
            iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports ${trans_port}

            # *filter for IPv4
            iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT
            iptables -A INPUT -i lo -j ACCEPT
            iptables -A INPUT -j DROP

            iptables -A FORWARD -j DROP

            iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
            iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT
            iptables -A OUTPUT -m owner --uid-owner ${tor_uid} -j ACCEPT
            iptables -A OUTPUT -o lo -j ACCEPT
            iptables -A OUTPUT -d 127.0.0.1 -p tcp --dport ${trans_port} -j ACCEPT
            for lan in ${non_tor_ipv4}; do
                iptables -A OUTPUT -d ${lan} -j ACCEPT
            done

            # Drop non-DNS UDP (leaks prevention)
            iptables -A OUTPUT -p udp ! --dport 53 -j DROP

            # Drop multicast (mDNS safety)
            for mcast in ${multicast_ipv4}; do
                iptables -A OUTPUT -d ${mcast} -j DROP
            done

            iptables -A OUTPUT -j DROP

            iptables -P INPUT DROP
            iptables -P FORWARD DROP
            iptables -P OUTPUT DROP

            # IPv6 parallels
            ip6tables -t nat -A OUTPUT -d ${virtual_address_ipv6} -p tcp --syn -j REDIRECT --to-ports ${trans_port}

            ip6tables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports ${dns_port}
            ip6tables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports ${dns_port}

            ip6tables -t nat -A OUTPUT -m owner --uid-owner ${tor_uid} -j RETURN
            ip6tables -t nat -A OUTPUT -o lo -j RETURN
            for lan in ${non_tor_ipv6}; do
                ip6tables -t nat -A OUTPUT -d ${lan} -j RETURN
            done

            ip6tables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports ${trans_port}

            ip6tables -A INPUT -m state --state ESTABLISHED -j ACCEPT
            ip6tables -A INPUT -i lo -j ACCEPT
            ip6tables -A INPUT -j DROP

            ip6tables -A FORWARD -j DROP

            ip6tables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
            ip6tables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT
            ip6tables -A OUTPUT -m owner --uid-owner ${tor_uid} -j ACCEPT
            ip6tables -A OUTPUT -o lo -j ACCEPT
            ip6tables -A OUTPUT -d ::1 -p tcp --dport ${trans_port} -j ACCEPT
            for lan in ${non_tor_ipv6}; do
                ip6tables -A OUTPUT -d ${lan} -j ACCEPT
            done

            # Drop non-DNS UDP IPv6
            ip6tables -A OUTPUT -p udp ! --dport 53 -j DROP

            # Drop multicast IPv6
            for mcast in ${multicast_ipv6}; do
                ip6tables -A OUTPUT -d ${mcast} -j DROP
            done

            ip6tables -A OUTPUT -j DROP

            ip6tables -P INPUT DROP
            ip6tables -P FORWARD DROP
            ip6tables -P OUTPUT DROP
        ;;

        restore)
            printf "%s\\n" "Restore default firewall rules"

            iptables -F
            iptables -X
            iptables -t nat -F
            iptables -t nat -X
            iptables -P INPUT ACCEPT
            iptables -P FORWARD ACCEPT
            iptables -P OUTPUT ACCEPT

            ip6tables -F
            ip6tables -X
            ip6tables -t nat -F
            ip6tables -t nat -X
            ip6tables -P INPUT ACCEPT
            ip6tables -P FORWARD ACCEPT
            ip6tables -P OUTPUT ACCEPT
        ;;
    esac
}

## Check public IP address
check_ip() {
    local url_list=(
        'https://ipinfo.io/'
        'https://api.myip.com/'
        'https://ifconfig.me'
    )

    info "Check public IP address"

    for url in "${url_list[@]}"; do
        local request="$(curl -s "$url")"
        local response="$?"

        if [[ "$response" -ne 0 ]]; then
            continue
        fi

        printf "%s\\n" "${request}"
        break
    done
}

## Check status of program and services
check_status() {
    info "Check current status of Tor service"

    if pgrep -x "tor" > /dev/null; then
        msg "Tor process is running"
    else
        die "Tor is not running! exit"
    fi

    # Check Tor connection
    local hostport="localhost:9050"
    local url="https://check.torproject.org/"

    if curl --socks5 "${hostport}" --socks5-hostname "${hostport}" -s "${url}" | grep -q "Congratulations"; then
        msg "Your system is configured to use Tor"
    else
        printf "${red}%s${reset}\\n\\n" "Your system is not using Tor!"
        printf "%s\\n" "Try restarting Tor with the 'Restart' option"
        return 1
    fi

    check_ip
}

## Start transparent proxy through Tor
start_proxy() {
    check_root

    if pgrep -x "tor" > /dev/null; then
        die "Tor is already running, stop it first"
    fi

    banner
    sleep 1
    setup_general

    printf "\\n"
    info "Starting Transparent Proxy"

    # Start Tor (use systemctl if available, else direct)
    printf "%s\\n" "Start Tor"
    if hash systemctl 2>/dev/null; then>/dev/null 2>&1;
        if ! systemctl start tor.service >/dev/null 2>&1; then
            die "Can't start tor service, exit!"
        fi
    else
        tor &  # Fallback, but may not work well
        sleep 5
    fi

    # Set firewall rules
    setup_firewall set

    # Check status
    printf "\\n"
    if ! check_status; then
        stop_proxy
        die "Failed to verify Tor configuration"
    fi

    printf "\\n${b}${green}%s${reset} %s\\n" \
            "[OK]" "Transparent Proxy activated, your system is under Tor"

    # Start auto-restart if interval set
    if [[ ${ip_change_interval} -gt 0 ]]; then
        auto_restart_tor &
        auto_restart_pid=$!
        msg "Auto IP change enabled every ${ip_change_interval} minutes"
    fi
}

## Stop transparent proxy
stop_proxy() {
    check_root

    if pgrep -x "tor" > /dev/null; then
        info "Stopping Transparent Proxy"

        # Stop auto-restart
        if [[ ! -z "${auto_restart_pid}" ]]; then
            kill ${auto_restart_pid} 2>/dev/null
            auto_restart_pid=""
        fi

        # Restore firewall
        setup_firewall restore

        # Stop Tor
        printf "%s\\n" "Stop Tor"
        if hash systemctl 2>/dev/null; then
            systemctl stop tor.service
        else
            killall tor
        fi

        # Restore resolv.conf
        printf "%s\\n" "Restore default DNS"
        if hash resolvconf 2>/dev/null; then
            resolvconf -u
        else
            cp "${backup_dir}/resolv.conf.backup" /etc/resolv.conf
        fi

        # Restore torrc
        printf "%s\\n" "Restore original /etc/tor/torrc"
        cp "${backup_dir}/torrc.backup" /etc/tor/torrc

        # Clean backups
        rm -rf "${backup_dir}"

        printf "\\n${b}${green}%s${reset} %s\\n" "[-]" "Transparent Proxy stopped"
    else
        die "Tor is not running! exit"
    fi
}

## Restart Tor to change IP
restart_tor() {
    check_root

    if pgrep -x "tor" > /dev/null; then
        info "Restarting Tor to change IP"

        if hash systemctl 2>/dev/null; then
            systemctl restart tor.service
        else
            killall tor
            tor &
        fi
        sleep 2
        check_ip
    else
        die "Tor is not running! exit"
    fi
}

## Background function for auto IP change
auto_restart_tor() {
    while true; do
        sleep $((${ip_change_interval} * 60))
        restart_tor
    done
}

## Set IP change interval
set_ip_interval() {
    read -p "Enter IP change interval in minutes (0 to disable): " new_interval
    if [[ ${new_interval} =~ ^[0-9]+$ ]]; then
        ip_change_interval=${new_interval}
        msg "IP change interval set to ${ip_change_interval} minutes"

        # Restart background if running
        if [[ ! -z "${auto_restart_pid}" ]]; then
            kill ${auto_restart_pid} 2>/dev/null
            auto_restart_pid=""
        fi
        if [[ ${ip_change_interval} -gt 0 && $(pgrep -x "tor") ]]; then
            auto_restart_tor &
            auto_restart_pid=$!
        fi
    else
        die "Invalid input, must be a number"
    fi
}

## Interactive menu
menu() {
    banner
    while true; do
        printf "${b}${blue}Menu:${reset}\\n"
        printf "1. Start Transparent Proxy\\n"
        printf "2. Stop Transparent Proxy\\n"
        printf "3. Restart Tor (Change IP)\\n"
        printf "4. Check Status\\n"
        printf "5. Set IP Change Interval (current: ${ip_change_interval} min)\\n"
        printf "6. Version\\n"
        printf "7. Exit\\n"
        read -p "Choose an option: " choice

        case "${choice}" in
            1) start_proxy ;;
            2) stop_proxy ;;
            3) restart_tor ;;
            4) check_status ;;
            5) set_ip_interval ;;
            6) print_version ;;
            7) exit 0 ;;
            *) printf "${red}Invalid option${reset}\\n" ;;
        esac
        printf "\\n"
    done
}

# Run the menu
menu
