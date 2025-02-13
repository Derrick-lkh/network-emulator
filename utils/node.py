import socket
import threading
import re
from utils.Packet import *


class Node:
    def __init__(self, mac, ip, hub_ip, hub_port, SNIFF=False):
        self.mac = mac
        self.ip = ip
        self.hub_addr = (hub_ip, hub_port)
        
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(self.hub_addr)
        self.client_socket.send(bytes.fromhex(mac.replace(":", "")))
        print(f"[Node {self.mac}] Connected to hub at {hub_ip}")
        if SNIFF:
            threading.Thread(target=self.sniff, daemon=True).start()
        else:
            threading.Thread(target=self.listen, daemon=True).start()

    def listen(self):
        while True:
            try:
                data = self.client_socket.recv(512)
                if not data:
                    break
                # Decode
                decoded_packet = Packet.decode(data)
                dest_mac = decoded_packet.dest_mac
                if dest_mac == self.mac or dest_mac == "ff:ff":  # Broadcast or direct
                    print(decoded_packet.__str__())
            except:
                break

    def send(self, dest, message):
        # Check for dest type
        if "x" in dest:
            # IP
            packet = Packet(
                message,
                src_ip= self.ip,
                dest_ip= dest,
                src_mac= self.mac,
                protocol="1"
            )
        else:
            # MAC
            packet = Packet(
                message,
                src_mac= self.mac,
                dest_mac= dest, 
            )
        frame = packet.encode()
        self.client_socket.send(frame)
        print(f"[Node {self.mac}] Sent to {dest}: {message}")
    
    def sniff(self):
        while True:
            try:
                data = self.client_socket.recv(512)
                if not data:
                    break
                # Decode
                decoded_packet = Packet.decode(data)
                print(decoded_packet.__str__())
            except:
                break
    

def is_valid_mac_or_hex(dest):
    mac_regex = r'^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$' # AA:BB format
    hex_regex = r'^0x[0-9A-Fa-f]{2}$'  # 0x1A format
    
    return bool(re.match(mac_regex, dest)) or bool(re.match(hex_regex, dest))