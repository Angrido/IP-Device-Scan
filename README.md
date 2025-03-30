**IP Device Scan Tool 🕵️‍♂️💻**

A Python script designed to sniff network packets and identify devices connected to the network. It captures IP and MAC addresses and allows filtering specifically for private IPs from private subnets. You can also search within specified subnets and save the results with a timestamp. 📊💾

**Features ⚡**

- Sniff network packets and detect devices with IP and MAC addresses 🖥️
- Filter results to include only private IPs from private subnets 🌐
- Search for private IPs in a specific user-defined subnet 🗺️
- Save scan results to the Downloads folder with a timestamp ⏰
- Select the network interface for sniffing 🔌
- Access an interruption menu to:
  - Restart the scan 🔄
  - Save current results 📄
  - Change network interface selection 🔧
  - Modify the IP filter type 🌎
  - Exit the program ❌

**Requirements 📦**

- pyshark 🦈
- colorama 🎨
- pyfiglet ✨
- psutil ⚙️
- ipaddress 🌍

**Installation 🛠️**

To get started, install the required libraries:

```bash
pip install pyshark colorama pyfiglet psutil ipaddress
```
