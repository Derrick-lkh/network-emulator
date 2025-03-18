from utils.Packet import *
from utils.Frame import *
from utils.NIC import *
import threading


class Node:
    def __init__(self, mac, ip, gateway_ip, hub_ip, hub_port, SNIFF=False):
        self.mac = mac
        self.ip = ip
        self.gateway_ip = gateway_ip
        self.NIC = NIC(mac, ip, gateway_ip, hub_ip, hub_port)

        if SNIFF:
            self.sniff()
        else:
            threading.Thread(target=self.listen, daemon=True).start()

    def send(self, dest_ip, data):
        # Check for dest type
        payload_packet = Packet(data, self.ip, dest_ip, protocol="0")
        packet_encode = payload_packet.encode()
        # Create Frame
        dest_mac = self.NIC.ARP_TABLE.get(dest_ip, None) # Fetch ARP Table from NIC - PP if none
        if dest_mac is None:
            print(f"Mac Destination not found")
            return
        payload_frame = Frame(self.mac, dest_mac, packet_encode)
        frame_encode = payload_frame.encode()
        self.NIC.send(frame_encode)
        print(f"[Node {self.mac}] Sent to {dest_mac}: {data}")
    
    def listen(self):
        while True:
            try:
                # Takes control of NIC Listening - for attack/ sniffing
                data = self.NIC.listen() # Application layer sniff
                if data:
                    # Decode
                    decoded_packet = Frame.decode(data)
                    packet = Packet.decode(decoded_packet.data)
                    print(packet)
            except:
                break

    def sniff(self): # For attacker
        print("Sniffing mode on")
        while True:
            try:
                # Takes control of NIC Listening - for attack/ sniffing
                data = self.NIC.sniff() # Application layer sniff
                if not data:
                    break
                # Decode
                decoded_packet = Frame.decode(data)
                packet = Packet.decode(decoded_packet.data)
                print(packet)
            except:
                break