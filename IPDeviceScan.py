import signal
from colorama import Fore, init
import pyfiglet
import ipaddress
import os
import sys
import psutil
import socket
from datetime import datetime
import pyshark

# Initialize colorama
init(autoreset=True)

# Variables for scan management
search_type = "total"
ip_mac_detected = set()  # Set to track detected IPs, MACs, and hostnames
interface = None
sniffer_active = True
subnet_filter = None

def print_header():
    os.system('cls' if os.name == 'nt' else 'clear')
    header = pyfiglet.figlet_format("IP Device Scan", font="standard")
    print(Fore.CYAN + header)
    print(Fore.YELLOW + "v1.3.0")
    print(Fore.YELLOW + "==============================")
    print(Fore.CYAN + "[*] Monitoring all IP packets...")
    print(Fore.YELLOW + "==============================")

def detect_interfaces():
    available_interfaces = [iface for iface in psutil.net_if_addrs().keys()]
    print(Fore.YELLOW + "\nSelect the network interface to use:")
    for index, iface in enumerate(available_interfaces):
        print(Fore.CYAN + f"{index}. {iface}")
    return available_interfaces

def choose_interface():
    print_header()
    global interface
    available_interfaces = detect_interfaces()
    choice = input(Fore.GREEN + "Enter the interface number: ")
    try:
        choice = int(choice)
        interface = available_interfaces[choice]
    except (ValueError, IndexError):
        print(Fore.RED + "[!] Invalid choice. Try again...")
        choose_interface()

def choose_subnet():
    global subnet_filter
    subnet_value = input(Fore.GREEN + "Enter the subnet (e.g., 192.168.1.0/24): ")
    try:
        subnet_filter = ipaddress.ip_network(subnet_value, strict=False)
    except ValueError:
        print(Fore.RED + "[!] Invalid subnet format. Try again...")
        choose_subnet()

def choose_search_type():
    os.system('cls' if os.name == 'nt' else 'clear')
    print_header()
    print(Fore.YELLOW + "\nChoose the search type:")
    print(Fore.CYAN + "1. Total search (private IPs only from private subnets)")
    print(Fore.CYAN + "2. Search for private IPs in a specific subnet")
    print(Fore.RED + "[!] To exit, press 'q'")
    
    choice = input(Fore.GREEN + "Enter the corresponding number: ")
    global search_type

    if choice == "1":
        search_type = "total"  # Total search is restricted to private IPs
    elif choice == "2":
        search_type = "private"
        choose_subnet()  # Prompt for subnet only if searching for private IPs in subnet
    elif choice.lower() == 'q':
        print(Fore.RED + "Exiting...")
        sys.exit(0)
    else:
        print(Fore.RED + "[!] Invalid option. Try again...")
        choose_search_type()

def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname != ip else "N/A"
    except (socket.herror, socket.gaierror):
        return ""  # Return an empty string if hostname cannot be resolved

def process_packet(packet):
    try:
        ip_src = packet.ip.src
        mac_src = packet.eth.src if 'eth' in packet else "N/A"
        hostname = get_hostname(ip_src)

        # Only accept private IPs for the total search option
        if search_type == "total" and not ipaddress.ip_address(ip_src).is_private:
            return
        
        if search_type == "private" and subnet_filter and ipaddress.ip_address(ip_src) not in subnet_filter:
            return

        detection = (ip_src, mac_src, hostname)
        if detection not in ip_mac_detected:
            ip_mac_detected.add(detection)
            print(Fore.GREEN + f"[+] New Device Found: {ip_src} ({mac_src}) - Hostname: {hostname}")

    except AttributeError:
        pass

def save_scan():
    path = os.path.expanduser('~') + "/Downloads/scan_results_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".txt"
    with open(path, "w") as file:
        file.write("Scan Results\n")
        file.write("-" * 40 + "\n")
        for ip, mac, hostname in ip_mac_detected:
            file.write(f"IP: {ip}\tMAC: {mac}\tHostname: {hostname}\n")
        file.write("-" * 40 + "\n")
    print(Fore.GREEN + f"[+] Scan saved at: {path}")

def interruption_menu():
    print(Fore.RED + "\n[!] Interruption detected. Choose an option:")
    print(Fore.CYAN + "1. Restart scan")
    print(Fore.CYAN + "2. Save report of detected addresses in the Downloads folder")
    print(Fore.CYAN + "3. Return to the main menu to choose a network interface")
    print(Fore.CYAN + "4. Return to the menu to choose the IP search type")
    print(Fore.RED + "q. Exit program")
    
    choice = input(Fore.GREEN + "Enter your choice: ")

    if choice == "1":
        ip_mac_detected.clear()
        print_header()
        start_sniffer()
    elif choice == "2":
        save_scan()
        interruption_menu()
    elif choice == "3":
        choose_interface()
        start_sniffer()
    elif choice == "4":
        choose_search_type()
        start_sniffer()
    elif choice.lower() == 'q':
        print(Fore.RED + "[!] Exiting...")
        sys.exit(0)
    else:
        print(Fore.RED + "[!] Invalid option. Try again...")
        interruption_menu()

def start_sniffer():
    global sniffer_active
    try:
        print_header()
        print(Fore.CYAN + "[*] Press Ctrl+C to view the interruption menu.\n")
        
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously():
            process_packet(packet)

    except KeyboardInterrupt:
        interruption_menu()
    except Exception as e:
        print(Fore.RED + f"[!] An unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    choose_interface()
    choose_search_type()
    start_sniffer()
