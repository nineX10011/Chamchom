# utils.py
from scapy.all import TCP, UDP, ICMP, DNS, ARP, Ether

# Constants for default ports
DEFAULT_PORT_HTTP = 80
DEFAULT_PORT_HTTPS = 443
DEFAULT_PORT_DNS = 53
DEFAULT_PORT_FTP = 21
DEFAULT_PORT_SSH = 22
DEFAULT_PORT_TELNET = 23

# Function to get protocol based on packet inspection
def get_protocol(packet):
    if TCP in packet:
        return get_tcp_protocol(packet)
    elif UDP in packet:
        return get_udp_protocol(packet)
    elif ICMP in packet:
        return "ICMP"
    elif DNS in packet:
        return "DNS"
    elif ARP in packet:
        return "ARP"
    elif Ether in packet:
        return "Ethernet"
    else:
        return "Other"

# Function to get TCP protocol based on port numbers
def get_tcp_protocol(packet):
    sport = packet[TCP].sport
    dport = packet[TCP].dport

    if dport == DEFAULT_PORT_HTTP:
        return "HTTP"
    elif dport == DEFAULT_PORT_HTTPS:
        return "HTTPS"
    elif dport == DEFAULT_PORT_FTP:
        return "FTP"
    elif dport == DEFAULT_PORT_SSH:
        return "SSH"
    elif dport == DEFAULT_PORT_TELNET:
        return "Telnet"
    else:
        return "TCP"

# Function to get UDP protocol based on port numbers
def get_udp_protocol(packet):
    dport = packet[UDP].dport

    if dport == DEFAULT_PORT_DNS:
        return "DNS"
    else:
        return "UDP"
