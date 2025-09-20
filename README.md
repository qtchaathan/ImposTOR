<h1 align="center">Impos-TOR</h1>

<p align="center">
Cross-Distro Transparent Proxy through Tor
</p>

<p align="center">
<a href="https://github.com/qtchaathan/impostor/commits/main"><img src="https://img.shields.io/badge/version-1.1.2-blue"></a>
<a href="https://github.com/qtchaathan/ImposTOR/blob/main/LICENSE"><img src="https://img.shields.io/github/license/qtchaathan/impostor.svg"></a>
</p>

## About ImposTOR

**ImposTOR** is a shell script that uses **iptables** and **ip6tables** to create a transparent proxy through the Tor Network. Unlike other tools, it is designed to be cross-distro, working on a wide range of Linux distributions. The program also includes features to check the status of the Tor service and your public IP address.

With ImposTOR, you can redirect all system-wide traffic through the Tor Network.

This program is inspired by tools such as kalitorify and anonsurf.

### What is a Transparent Proxy through Tor?

A transparent proxy is a system that intercepts network traffic without requiring client-side configuration. When configured with Tor, this means all TCP connections are automatically routed through the Tor Network, preventing applications from revealing your real IP address.

For more information, please read the [Tor Project wiki](https://gitlab.torproject.org/legacy/trac/-/wikis/doc/TransparentProxy).

---

## Install

### Download:

```term
git clone https://github.com/qtchaathan/ImposTOR/
```
### Dependencies:

The script requires the following packages:

    tor, curl, iptables, ip6tables

Install them using your distribution's package manager. For example, on a Debian-based system:
```
sudo apt-get update
sudo apt-get install -y tor curl iptables ip6tables
```

## Usage

Run the script with sudo and no arguments to enter the interactive shell.
Code snippet

```
cd ImposTOR
sudo chmod +x ./impostor.sh
./impostor.sh
``` 

You will enter a interactive shell, and you will be prompted to enter commands.

#### Commands list:

    start:       Starts the transparent proxy and configures the firewall rules.

    stop:        Stops the proxy, restores the original firewall rules, and removes temporary configuration files.

    restart:     Restarts the Tor service to change your public IP address.

    status:      Checks the status of the Tor service and your public IP address.

    initip:      Sets the interval for automatic IP address changes.

    v:           Displays the program version and other info.

    help:        Shows the list of commands.

    exit:        Exits the program.

    clear:       Clears the console.

## Security

Read this section carefully before using ImposTOR.

ImposTOR is produced independently from the Tor anonymity software and carries no guarantee from the Tor Project about its quality or suitability.

Transparent Torification protects against accidental connections and DNS leaks but is not a complete solution for anonymity against malware or compromised software.

#### Hostname and MAC Address security risks

Transparent Torification does not hide your hostname, MAC address, or other system-specific details from applications with sufficient privileges. For enhanced security, consider changing your hostname and MAC address before using the script.

## Credits

Inspired by the work on kalitorify and anonsurf.
The Tor Project and Whonix for their invaluable documentation.
