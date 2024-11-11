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

# Inizializza colorama
init(autoreset=True)

# Variabili per gestire la scansione
tipo_ricerca = "totale"
dispositivi = []
ip_rilevati = set()  # Utilizzeremo un set per tenere traccia degli IP già rilevati
interfaccia_selezionata = None  # Variabile per memorizzare l'interfaccia scelta
sniffer_attivo = False  # Variabile per gestire lo stato del sniffing

# Funzione per stampare un'intestazione in stile semplificato
def stampa_intestazione():
    os.system('cls' if os.name == 'nt' else 'clear')  # Pulire la console
    header = pyfiglet.figlet_format("IP Sniffer", font="slant")  # Font stilizzato per il titolo
    firma = pyfiglet.figlet_format("Lucio Gigliofiorito", font="mini")  # Font mini per la firma

    # Visualizzare il titolo e la firma
    print(Fore.CYAN + header)
    print(Fore.RED + firma)  # Cambio il colore della firma a rosso
    print(Fore.YELLOW + "===============================")
    print(Fore.CYAN + "[*] Monitoraggio pacchetti in corso...")
    print(Fore.YELLOW + "===============================")

# Funzione per elencare le interfacce di rete e permettere all'utente di scegliere
def scegli_interfaccia():
    global interfaccia_selezionata

    # Ottieni la lista delle interfacce di rete con dettagli
    interfacce = []
    for iface_name, iface_info in psutil.net_if_addrs().items():
        # Mappatura per rendere i nomi più intuitivi
        descrizione = iface_name
        if "eth" in iface_name.lower() or "ethernet" in iface_name.lower():
            descrizione = "Ethernet"
        elif "wifi" in iface_name.lower() or "wlan" in iface_name.lower():
            descrizione = "Wi-Fi"
        elif "lo" in iface_name.lower():
            descrizione = "Loopback"
        
        interfacce.append((iface_name, descrizione))

    # Mostra le opzioni delle interfacce di rete con descrizioni comprensibili
    print(Fore.YELLOW + "\nScegli l'interfaccia di rete da utilizzare:")
    for i, (iface_name, descrizione) in enumerate(interfacce):
        print(Fore.CYAN + f"{i + 1}. {descrizione} ({iface_name})")
    
    scelta = input(Fore.GREEN + "Inserisci il numero corrispondente all'interfaccia: ")

    try:
        scelta = int(scelta) - 1
        if scelta < 0 or scelta >= len(interfacce):
            raise ValueError("Indice non valido.")
        interfaccia_selezionata = interfacce[scelta][0]  # Usa il nome dell'interfaccia originale
        print(Fore.GREEN + f"[+] Interfaccia selezionata: {interfacce[scelta][1]}")
    except ValueError:
        print(Fore.RED + "[!] Scelta non valida. Riprova...")
        scegli_interfaccia()

# Funzione per determinare il gateway per un indirizzo IP
def ottieni_gateway(indirizzo_ip):
    try:
        result = subprocess.run(['route', 'print'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in result.stdout.splitlines():
            if indirizzo_ip in line:
                parts = line.split()
                if len(parts) > 2:
                    return parts[2]
    except Exception as e:
        print(Fore.RED + f"Errore nel determinare il gateway per {indirizzo_ip}: {str(e)}")
    return "N/D"

# Funzione per verificare se un IP è privato
def is_ip_privato(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

# Funzione per processare i pacchetti sniffati
def processa_pacchetto(pacchetto):
    if IP in pacchetto:
        indirizzo_ip = pacchetto[IP].src

        # Ignora gli IP già rilevati
        if indirizzo_ip in ip_rilevati:
            return

        # Aggiungi l'IP alla lista dei rilevati
        ip_rilevati.add(indirizzo_ip)

        if tipo_ricerca == "privato" and not is_ip_privato(indirizzo_ip):
            return
        elif tipo_ricerca == "pubblico" and is_ip_privato(indirizzo_ip):
            return

        mac_address = pacchetto[Ether].src
        nome_host = None
        gateway = ottieni_gateway(indirizzo_ip)

        try:
            nome_host = socket.gethostbyaddr(indirizzo_ip)[0]
        except socket.herror:
            nome_host = "N/D"
        
        dispositivo = {
            'ip': indirizzo_ip,
            'mac': mac_address,
            'nome': nome_host,
            'gateway': gateway
        }

        dispositivi.append(dispositivo)

        # Stampa dettagli sul dispositivo rilevato
        print(Fore.GREEN + f"[+] Nuovo dispositivo trovato:")
        print(Fore.WHITE + f"IP: {Fore.WHITE}{indirizzo_ip}")  # Cambiato colore dell'IP
        print(Fore.CYAN + f"MAC: {mac_address}")
        print(Fore.CYAN + f"Nome Host: {nome_host}")
        print(Fore.CYAN + f"Gateway: {gateway}")
        print(Fore.YELLOW + "-"*40)

# Funzione per chiedere all'utente quale tipo di ricerca desidera
def scegli_tipo_ricerca():
    os.system('cls' if os.name == 'nt' else 'clear')  # Pulire la console
    stampa_intestazione()  # Ripristina l'header
    print(Fore.YELLOW + "\nScegli il tipo di ricerca:")
    print(Fore.CYAN + "1. Ricerca solo IP privati")
    print(Fore.CYAN + "2. Ricerca solo IP pubblici")
    print(Fore.CYAN + "3. Ricerca totale (privati e pubblici)")
    print(Fore.RED + "[!] Per uscire, premi 'q'")
    scelta = input(Fore.GREEN + "Inserisci il numero corrispondente: ")

    global tipo_ricerca
    if scelta == "1":
        tipo_ricerca = "privato"
    elif scelta == "2":
        tipo_ricerca = "pubblico"
    elif scelta == "3":
        tipo_ricerca = "totale"
    elif scelta.lower() == 'q':
        print(Fore.RED + "Uscita... chiudendo il programma.")
        sys.exit(0)
    else:
        print(Fore.RED + "[!] Opzione non valida. Riprova...")
        scegli_tipo_ricerca()

# Funzione per fermare lo sniffing
def stop_sniffer():
    global sniffer_attivo
    sniffer_attivo = False
    print(Fore.YELLOW + "\n[+] Scansione fermata.")

# Funzione per salvare la scansione
def salva_scansione():
    global sniffer_attivo
    stop_sniffer()  # Fermiamo lo sniffing prima di salvare i dati

    # Crea un nome file con la data e ora corrente
    data_ora = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    nome_file = os.path.expanduser(f"~/Downloads/scansione_{data_ora}.txt")
    
    with open(nome_file, "w") as f:
        f.write("Scansione completata il: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
        f.write("="*50 + "\n")
        for dispositivo in dispositivi:
            f.write(f"IP: {dispositivo['ip']}\n")
            f.write(f"MAC: {dispositivo['mac']}\n")
            f.write(f"Nome Host: {dispositivo['nome']}\n")
            f.write(f"Gateway: {dispositivo['gateway']}\n")
            f.write("-" * 50 + "\n")
    print(Fore.GREEN + f"[+] Scansione salvata in: {nome_file}")

# Funzione per gestire l'interruzione (Ctrl+C)
def signal_handler(sig, frame):
    print(Fore.RED + "\nInterruzione ricevuta! Premere un numero per scegliere un'opzione...")
    mostra_opzioni_interruzione()

# Funzione per mostrare le opzioni dopo che l'utente ha premuto Ctrl+C
def mostra_opzioni_interruzione():
    print(Fore.YELLOW + "\nOpzioni disponibili:")
    print(Fore.CYAN + "1. Ritorna al menu principale")
    print(Fore.CYAN + "2. Riavvia la scansione")
    print(Fore.CYAN + "3. Continua la scansione")
    print(Fore.CYAN + "4. Salva la scansione nella cartella 'Downloads'")
    print(Fore.RED + "[!] Per uscire, premi 'q'")

    scelta = input(Fore.GREEN + "Inserisci il numero corrispondente: ")

    if scelta == "1":
        scegli_tipo_ricerca()  # Torna al menu principale
    elif scelta == "2":
        riavvia_scansione()  # Riavvia la scansione
    elif scelta == "3":
        continua_scansione()  # Continua la scansione
    elif scelta == "4":
        salva_scansione()  # Salva la scansione
    elif scelta.lower() == 'q':
        print(Fore.RED + "Uscita... chiudendo il programma.")
        sys.exit(0)
    else:
        print(Fore.RED + "[!] Opzione non valida. Riprova...")
        mostra_opzioni_interruzione()

# Funzione principale per avviare il programma
def avvia_sniffer():
    stampa_intestazione()
    scegli_interfaccia()  # Chiede all'utente di selezionare l'interfaccia
    scegli_tipo_ricerca()  # Chiede quale tipo di ricerca eseguire
    sniff(filter="ip", prn=processa_pacchetto, store=0, iface=interfaccia_selezionata)  # Avvia lo sniffing

# Registriamo il signal handler per Ctrl + C
signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    avvia_sniffer()