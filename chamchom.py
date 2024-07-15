# sniffer.py
import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, wrpcap
from prettytable import PrettyTable
from datetime import datetime
from colorama import init, Fore, Style
from utils import get_protocol  # Adjust import based on your project structure

# Initialize colorama
init()

# Logo definition
logo = f"""
{Fore.RED}


 ██████ ██   ██  █████  ███    ███  ██████ ██   ██  ██████  ███    ███ 
██      ██   ██ ██   ██ ████  ████ ██      ██   ██ ██    ██ ████  ████ 
██      ███████ ███████ ██ ████ ██ ██      ███████ ██    ██ ██ ████ ██ 
██      ██   ██ ██   ██ ██  ██  ██ ██      ██   ██ ██    ██ ██  ██  ██ 
 ██████ ██   ██ ██   ██ ██      ██  ██████ ██   ██  ██████  ██      ██ 
                                                                       {Style.RESET_ALL}{Fore.CYAN}Network Sniffer By NineX for CodeAlpha {Style.RESET_ALL}
"""

# Print the logo
print(logo)

# Create the table with headers
table = PrettyTable()
table.field_names = ["Timestamp", "Protocol", "Source IP", "Source Port", "Destination IP", "Destination Port"]

# Color definitions
COLORS = {
    "HTTP": Fore.BLUE,
    "HTTPS": Fore.CYAN,
    "FTP": Fore.MAGENTA,
    "SSH": Fore.RED,
    "Telnet": Fore.YELLOW,
    "DNS": Fore.GREEN,
    "ICMP": Fore.WHITE,
    "ARP": Fore.YELLOW,
    "Ethernet": Fore.WHITE,
    "IP": Fore.WHITE,
    "Other": Fore.WHITE
}

# Parse command-line arguments
parser = argparse.ArgumentParser(description="Chamchom Network Sniffer")
parser.add_argument("-i", "--interface", type=str, required=True, help="Network interface to sniff (e.g., eth0)")
parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (default: unlimited)")
parser.add_argument("-f", "--filter", type=str, default=None, choices=["tcp", "udp", "icmp", "dns", "arp"],
                    help="Filter packets by protocol (e.g., tcp)")
parser.add_argument("-w", "--write", type=str, default=None, help="Write captured packets to a PCAP file")
args = parser.parse_args()

# Packet callback function
def packet_callback(packet):
    if IP in packet:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = get_protocol(packet)

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport

        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        elif ICMP in packet:
            sport = "-"
            dport = "-"

        else:
            sport = "-"
            dport = "-"

        # Color protocol based on type
        if protocol in COLORS:
            protocol_color = COLORS[protocol] + protocol + Style.RESET_ALL
        else:
            protocol_color = Fore.WHITE + protocol + Style.RESET_ALL

        row = [timestamp, protocol_color, ip_src, sport, ip_dst, dport]
        table.add_row(row)
        print(table)

        # Write to PCAP file if specified
        if args.write:
            wrpcap(args.write, packet)

        # Check packet count limit
        args.count -= 1
        if args.count == 0:
            print(f"Packet capture complete. Exiting...")
            exit()

# Main function
def main():
    print(f"Sniffing on interface {args.interface}. Press Ctrl+C to stop...")
    try:
        # Sniff packets based on options
        sniff(iface=args.interface, prn=packet_callback, filter=args.filter)
    except KeyboardInterrupt:
        print("\nPacket capture interrupted. Exiting...")

if __name__ == "__main__":
    main()
