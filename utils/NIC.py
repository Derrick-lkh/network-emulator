import socket
from utils.Packet import *
from utils.Frame import *


class NIC:
    def __init__(self, mac, ip, gateway_ip, hub_ip, hub_port, ARP_TABLE=None):
        """
        mac - MAC assigned to the NIC
        ip - IP assigned to the NIC
        gateway - IP of the Router
        hub_ip - socket connection to the hub
        hub_port - socket connection to the hub
        SNIFF - Optional
        """

        self.ARP_TABLE = {"0x1A": "N1", "0x1B": "N2", "0x11": "R1"}
        if ARP_TABLE:
            self.ARP_TABLE = ARP_TABLE  # Overwrite default ARP table
        self.mac = mac
        self.ip = ip
        self.gateway_ip = gateway_ip
        self.hub_addr = (hub_ip, hub_port)  # Connection to HUB
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(self.hub_addr)
        self.client_socket.send(
            mac.encode("utf-8")
        )  # Encode mac address before sending - populate port mapping table
        print(f"[Node {self.mac}] Connected to hub at {hub_ip}")

    def listen(self):
        data = self.client_socket.recv(512)
        if not data:
            return None
        decoded_packet = Frame.decode(data)
        dest_mac = decoded_packet.dest_mac
        src_mac = decoded_packet.src_mac
        if dest_mac == self.mac:  # Broadcast or direct
            return data
        elif dest_mac == "FF" and src_mac != self.mac:
            return data
        return None

    def sniff(self):
        data = self.client_socket.recv(512)
        return data

    def send(self, data_frame):
        self.client_socket.send(data_frame)

    def update_ARP_table(self, arp_ip, arp_mac):
        # Validate IP and MAC
        self.ARP_TABLE[arp_ip] = arp_mac
