# IP Sniffer Tool 🕵️‍♂️💻

A Python script to sniff network packets and detect devices connected to the network. It collects IP, MAC, hostname, and gateway info. You can filter by private or public IPs and save the results with a timestamp. 📊💾

## Features ⚡
- Sniff network packets and detect devices with IP and MAC addresses 🖥️
- Filter by private or public IPs 🌐
- Save scan results to the Downloads folder with a timestamp ⏰
- Select network interface for sniffing 🔌
- Access an interruption menu to:
  - Restart the scan 🔄
  - Save current results 📄
  - Change network interface selection 🔧
  - Change IP filter type 🌎
  - Exit the program ❌

## Requirements 📦
- `pyshark` 🦈
- `colorama` 🎨
- `pyfiglet` ✨
- `psutil` ⚙️
- `ipaddress` 🌍

## Installation 🛠️

To get started, install the required libraries:

```bash
pip install pyshark colorama pyfiglet psutil ipaddress
