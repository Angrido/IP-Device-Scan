import socket
import subprocess
import signal
from scapy.all import sniff, ARP, IP, Ether, conf
from colorama import Fore, init
import pyfiglet
import ipaddress
import os
import sys
import psutil
from datetime import datetime
import time

# Initialize colorama
init(autoreset=True)

# Variables to manage the scan
search_type = "total"
devices = []
detected_ips = set()  # We'll use a set to track the already detected IPs
selected_interface = None  # Variable to store the chosen interface
sniffer_active = False  # Variable to manage the sniffing status

# Function to print a simplified header
def print_header():
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear the console
    header = pyfiglet.figlet_format("IP Sniffer", font="slant")  # Stylized font for the title
    signature = pyfiglet.figlet_format("Lucio Gigliofiorito", font="mini")  # Mini font for the signature

    # Display the title and signature
    print(Fore.CYAN + header)
    print(Fore.RED + signature)  # Change the signature color to red
    print(Fore.YELLOW + "===============================")
    print(Fore.CYAN + "[*] Monitoring packets...")  
    print(Fore.YELLOW + "===============================")

# Function to list network interfaces and allow the user to choose one
def choose_interface():
    global selected_interface

    # Get the list of network interfaces with details
    interfaces = []
    for iface_name, iface_info in psutil.net_if_addrs().items():
        # Mapping to make the names more intuitive
        description = iface_name
        if "eth" in iface_name.lower() or "ethernet" in iface_name.lower():
            description = "Ethernet"
        elif "wifi" in iface_name.lower() or "wlan" in iface_name.lower():
            description = "Wi-Fi"
        elif "lo" in iface_name.lower():
            description = "Loopback"
        
        interfaces.append((iface_name, description))

    # Show network interface options with understandable descriptions
    print(Fore.YELLOW + "\nChoose the network interface to use:")
    for i, (iface_name, description) in enumerate(interfaces):
        print(Fore.CYAN + f"{i + 1}. {description} ({iface_name})")
    
    choice = input(Fore.GREEN + "Enter the corresponding number for the interface: ")

    try:
        choice = int(choice) - 1
        if choice < 0 or choice >= len(interfaces):
            raise ValueError("Invalid index.")
        selected_interface = interfaces[choice][0]  # Use the original interface name
        print(Fore.GREEN + f"[+] Selected interface: {interfaces[choice][1]}")
    except ValueError:
        print(Fore.RED + "[!] Invalid choice. Try again...")
        choose_interface()

# Function to determine the gateway for an IP address
def get_gateway(ip_address):
    try:
        result = subprocess.run(['route', 'print'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in result.stdout.splitlines():
            if ip_address in line:
                parts = line.split()
                if len(parts) > 2:
                    return parts[2]
    except Exception as e:
        print(Fore.RED + f"Error determining the gateway for {ip_address}: {str(e)}")
    return "N/A"

# Function to check if an IP is private
def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

# Function to process sniffed packets
def process_packet(packet):
    if IP in packet:
        ip_address = packet[IP].src

        # Ignore already detected IPs
        if ip_address in detected_ips:
            return

        # Add the IP to the detected list
        detected_ips.add(ip_address)

        if search_type == "private" and not is_private_ip(ip_address):
            return
        elif search_type == "public" and is_private_ip(ip_address):
            return

        mac_address = packet[Ether].src
        host_name = None
        gateway = get_gateway(ip_address)

        try:
            host_name = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            host_name = "N/A"
        
        device = {
            'ip': ip_address,
            'mac': mac_address,
            'name': host_name,
            'gateway': gateway
        }

        devices.append(device)

        # Print details about the detected device
        print(Fore.GREEN + f"[+] New device found:")
        print(Fore.WHITE + f"IP: {Fore.WHITE}{ip_address}")  # Changed IP color
        print(Fore.CYAN + f"MAC: {mac_address}")
        print(Fore.CYAN + f"Host Name: {host_name}")
        print(Fore.CYAN + f"Gateway: {gateway}")
        print(Fore.YELLOW + "-"*40)

# Function to ask the user for the search type
def choose_search_type():
    os.system('cls' if os.name == 'nt' else 'clear')  # Clear the console
    print_header()  # Restore the header
    print(Fore.YELLOW + "\nChoose the search type:")
    print(Fore.CYAN + "1. Search only private IPs")
    print(Fore.CYAN + "2. Search only public IPs")
    print(Fore.CYAN + "3. Total search (private and public)")
    print(Fore.RED + "[!] To exit, press 'q'")
    choice = input(Fore.GREEN + "Enter the corresponding number: ")

    global search_type
    if choice == "1":
        search_type = "private"
    elif choice == "2":
        search_type = "public"
    elif choice == "3":
        search_type = "total"
    elif choice.lower() == 'q':
        print(Fore.RED + "Exiting... closing the program.")
        sys.exit(0)
    else:
        print(Fore.RED + "[!] Invalid option. Try again...")
        choose_search_type()

# Function to stop the sniffer
def stop_sniffer():
    global sniffer_active
    sniffer_active = False
    print(Fore.YELLOW + "\n[+] Scan stopped.")

# Function to save the scan results
def save_scan():
    global sniffer_active
    stop_sniffer()  # Stop sniffing before saving the data

    # Create a file name with the current date and time
    date_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_name = os.path.expanduser(f"~/Downloads/scan_{date_time}.txt")
    
    with open(file_name, "w") as f:
        f.write("Scan completed on: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
        f.write("="*50 + "\n")
        for device in devices:
            f.write(f"IP: {device['ip']}\n")
            f.write(f"MAC: {device['mac']}\n")
            f.write(f"Host Name: {device['name']}\n")
            f.write(f"Gateway: {device['gateway']}\n")
            f.write("-" * 50 + "\n")
    print(Fore.GREEN + f"[+] Scan saved to: {file_name}")

# Function to handle interruptions (Ctrl+C)
def signal_handler(sig, frame):
    print(Fore.RED + "\nInterruption received! Press a number to choose an option...")
    show_interrupt_options()

# Function to show options after the user presses Ctrl+C
def show_interrupt_options():
    print(Fore.YELLOW + "\nAvailable options:")
    print(Fore.CYAN + "1. Return to the main menu")
    print(Fore.CYAN + "2. Restart the scan")
    print(Fore.CYAN + "3. Continue the scan")
    print(Fore.CYAN + "4. Save the scan to the 'Downloads' folder")
    print(Fore.RED + "[!] To exit, press 'q'")

    choice = input(Fore.GREEN + "Enter the corresponding number: ")

    if choice == "1":
        choose_search_type()  # Return to the main menu
    elif choice == "2":
        restart_scan()  # Restart the scan
    elif choice == "3":
        continue_scan()  # Continue the scan
    elif choice == "4":
        save_scan()  # Save the scan
    elif choice.lower() == 'q':
        print(Fore.RED + "Exiting... closing the program.")
        sys.exit(0)
    else:
        print(Fore.RED + "[!] Invalid option. Try again...")
        show_interrupt_options()

# Main function to start the program
def start_sniffer():
    print_header()
    choose_interface()  # Ask the user to select the interface
    choose_search_type()  # Ask which type of search to perform
    sniff(filter="ip", prn=process_packet, store=0, iface=selected_interface)  # Start sniffing

# Register the signal handler for Ctrl + C
signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    start_sniffer()