# NetSec Toolkit 🛡️🔍

## 🌟 Overview

A powerful Python-based network security toolkit featuring:
- **ARP Spoofer**: Performs man-in-the-middle attacks by manipulating ARP tables
- **Packet Sniffer**: Captures and analyzes network traffic, extracting URLs and login credentials

Perfect for ethical hacking, network analysis, and security education.

## ✨ Features

### 🔄 ARP Spoofer
- 🎭 Performs bidirectional ARP spoofing (target ↔ router)
- 🔍 Automatic router IP detection
- 📡 MAC address resolution for any IP
- ⏱️ Continuous spoofing with 2-second intervals
- 🔄 Automatic ARP table restoration on exit

### 📡 Packet Sniffer
- 🕵️‍♂️ Captures HTTP traffic in real-time
- 🌐 Extracts visited URLs from network packets
- 🔑 Identifies login credentials (username/password)
- 🖥️ Works on any network interface
- 📊 Clean formatted output of captured data

## 🚀 Prerequisites

- Python 3.x
- Linux (or macOS with adjustments)
- Scapy library (`pip install scapy`)
- Root/sudo privileges
- `optparse`, `re`, `subprocess`, `time` modules

## 🛠️ Usage

### ARP Spoofer
```bash
sudo python ARP_Spoof.py -t <target_ip>
```
Example:
```bash
sudo python ARP_Spoof.py -t 192.168.1.100
```

### Packet Sniffer
```bash
sudo python Packet_Sniffer.py -i <interface>
```
Example:
```bash
sudo python Packet_Sniffer.py -i eth0
```

## 📊 Sample Outputs

### ARP Spoofer
```
Starting ARP Spoofing attack on 192.168.1.100...
+--------------------------------------------------------------------+
| [*] Spoofing:  192.168.1.100       with ->  192.168.1.1            |
| [*] Spoofing:  192.168.1.1         with ->  192.168.1.100          |
| [*] Old MAC:   aa:bb:cc:dd:ee:ff   New MAC:  11:22:33:44:55:66     |
+--------------------------------------------------------------------+
```


### Packet Sniffer
```
[+] HTTP Request >> facebook.com/login
+-------------------------------------------------+
| Website   | facebook.com/login                  |
+-------------------------------------------------+
| Username  | user@example.com                    |
| Password  | s3cr3tp@ss                          |
+-------------------------------------------------+
```


## ⚠️ Legal & Ethical Considerations

- **FOR EDUCATIONAL PURPOSES ONLY**
- Requires explicit permission to use on any network
- May violate laws if used without authorization
- Not responsible for misuse of this software
- Use responsibly and ethically

