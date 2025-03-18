import socket
import threading
from utils.Packet import *
from utils.Frame import *


class NIC:
    def __init__(self, mac, ip, gateway_ip, hub_ip, hub_port):
        """
        mac - MAC assigned to the NIC
        ip - IP assigned to the NIC
        gateway - IP of the Router
        hub_ip - socket connection to the hub
        hub_port - socket connection to the hub
        SNIFF - Optional
        """
        self.ARP_TABLE = {
            "0x1A": "N1",
            "0x1B": "N2",
            "0x11": "R1"
        }
        self.mac = mac
        self.ip = ip
        self.hub_addr = (hub_ip, hub_port) # Connection to HUB
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(self.hub_addr)
        self.client_socket.send(mac.encode("utf-8")) # Encode mac address before sending - populate port mapping table
        print(f"[Node {self.mac}] Connected to hub at {hub_ip}")

    def listen(self):
        data = self.client_socket.recv(512)
        if not data:
            return None
        decoded_packet = Frame.decode(data)
        dest_mac = decoded_packet.dest_mac
        if dest_mac == self.mac or dest_mac == "FF":  # Broadcast or direct
            return data
        return None

    def sniff(self):
        data = self.client_socket.recv(512)
        return data

    def send(self, data_frame):
        self.client_socket.send(data_frame)


# Node Usage of NIC class
"""
NIC(gateway, SRC_MAC, sniffing=true) #optional

NIC_CONTROLLER = NIC(gateway, SRC_MAC)
NIC_CONTROLLER.send(dataframe)
"""

# NIC Class
"""
0x1 - NIC1
0x2 - NIC2
socket init
Receive -> update arp, filter (mac dest addr)
send -> validate frame

Sniffing_mode (OFF): 
    Check (bool):
        mac filter = sniffing_mode?

ARP table -> generated dynamically based on sniff
{
    0x11: R1
    0x1A: N1
}
{
    0x21: R2
    0x2A: N2
    0x2B: N3
}
gateway: 0x21
0x2B

0x1A: router mac dest
"""