from utils.Packet import *
from utils.Frame import *
from utils.NIC import *
import threading

PROTOCOL_MAPPING = {
    "0": "ARP_REQUEST",
    "1": "ARP_REPLY",
    "2": "ICMP_REQUEST",
    "3": "ICMP_REPLY",
    "4": "TCPDATA"
}

class Node:
    """
    Configure logic for Node (PC)
    Protocol includes:
        0 - ARP_REQUEST
        1 - ARP_REPLY
        2 - ICMP_REQUEST
        3 - ICMP_REPLY
        4 - TCPDATA
    """
    
    def __init__(self, mac, ip, gateway_ip, hub_ip, hub_port, SNIFF=False, ARP_TABLE=None, DISABLE_ANNOUNCE=False, SPOOF=False, FIREWALL=None):
        self.mac = mac
        self.ip = ip
        self.gateway_ip = gateway_ip
        self.SNIFF = SNIFF
        self.SPOOF = SPOOF  
        self.FIREWALL = FIREWALL
        self.NIC = NIC(mac, ip, gateway_ip, hub_ip, hub_port, ARP_TABLE)
        if not DISABLE_ANNOUNCE:
            self.announce_arp()
       
    def run(self, RUN_IN_SNIFF=False):
        if self.SNIFF or RUN_IN_SNIFF:
            self.sniff()
        else:
            threading.Thread(target=self.listen, daemon=True).start()

    def send_TCP_data(self, dest_ip, data, spoof_ip): # use for sending TCPDATA (plain message) protocol 
        if self.SPOOF:
            if spoof_ip:
                payload_packet = Packet(data, spoof_ip, dest_ip, protocol="4")
        else:
            payload_packet = Packet(data, self.ip, dest_ip, protocol="4")
        packet_encode = payload_packet.encode()
        # Create Frame
        dest_mac = self.NIC.ARP_TABLE.get(dest_ip, None) # Fetch ARP Table from NIC - PP if none

        # If mac not in ARP table, send to default gateway
        if dest_mac is None:
            dest_mac = self.NIC.ARP_TABLE.get(self.gateway_ip, None) # Fetch ARP Table from NIC - PP if none
            print(f"Mac Destination not found. Sending to Gateway")
        payload_frame = Frame(self.mac, dest_mac, packet_encode)
        frame_encode = payload_frame.encode()
        self.NIC.send(frame_encode)
        print(f"[Node {self.mac}] Sent to {dest_mac}: {data}")
    
    def arp_request(self, IP_REQUST):
        payload_packet = Packet(IP_REQUST, self.ip, self.gateway_ip, protocol="0")
        packet_encode = payload_packet.encode()
        dest_mac = "FF" # Broadcast
        payload_frame = Frame(self.mac, dest_mac, packet_encode)
        frame_encode = payload_frame.encode()
        self.NIC.send(frame_encode)
        print(f"[Node {self.mac}] Sent to {dest_mac}: ARP request for {IP_REQUST}")

    def send_arp_reply(self, arp_ip, arp_mac, target_src_ip, target_src_mac):
        ARP_REPLY = f"{arp_ip}:{arp_mac}"
        ARP_PACKET = Packet(ARP_REPLY, self.ip, target_src_ip, protocol="1")
        ARP_FRAME = Frame(self.mac, target_src_mac, ARP_PACKET.encode())
        frame_encode = ARP_FRAME.encode()
        self.NIC.send(frame_encode) # Send out ARP Response

    def send_icmp_request(self, target_ip):
        ICMP_Request = f"ICMP Ping"
        ICMP_PACKET = Packet(ICMP_Request, self.ip, target_ip, protocol="2")
        dest_mac = self.NIC.ARP_TABLE.get(target_ip, None)
        ICMP_FRAME = Frame(self.mac, dest_mac, ICMP_PACKET.encode())
        frame_encode = ICMP_FRAME.encode()
        self.NIC.send(frame_encode) # Send out ARP Response

    def announce_arp(self):
        """
        Announce self ARP info (own location)
            - Sends out ARP reply with {self.ip}:{self.mac}
        """
        ARP_REPLY = f"{self.ip}:{self.mac}"
        ARP_PACKET = Packet(ARP_REPLY, self.ip, self.gateway_ip, protocol="1")
        ARP_FRAME = Frame(self.mac, "FF", ARP_PACKET.encode()) # Broadcast
        frame_encode = ARP_FRAME.encode()
        self.NIC.send(frame_encode) # Send out ARP Response

    def listen(self):
        while True:
            try:
                # Takes control of NIC Listening - for attack/ sniffing
                data = self.NIC.listen() # Application layer sniff
                if data:                        
                    # Decode
                    decoded_packet = Frame.decode(data)
                    print(decoded_packet)
                    packet = Packet.decode(decoded_packet.data)
                    src_mac = decoded_packet.src_mac
                    packet_src = packet.src_ip
                    packet_data = packet.data
                    protocol = packet.protocol
                    
                    # print(packet)
                    # Node Application Logic
                    # Configure logic for ARP Response
                    PROTOCOL_NAME = PROTOCOL_MAPPING.get(protocol, None)
                    if PROTOCOL_NAME == "ARP_REQUEST":
                        # Craft ARP response packet
                        found_mac = self.NIC.ARP_TABLE.get(packet_data, None)
                        if found_mac:
                            ARP_REPLY = f"{packet_src}:{found_mac}"
                            ARP_PACKET = Packet(ARP_REPLY, self.ip, packet_src, protocol="1")
                            ARP_FRAME = Frame(self.mac, src_mac, ARP_PACKET.encode())
                            frame_encode = ARP_FRAME.encode()
                            self.NIC.send(frame_encode) # Send out ARP Response
                    # Handle ARP_RESPONSE
                    elif PROTOCOL_NAME == "ARP_REPLY":
                        ARP_IP, ARP_MAC = packet_data.split(":")
                        # Validate IP and MAC
                        self.NIC.update_ARP_table(ARP_IP, ARP_MAC)
                        print()
                        print("Updated ARP", self.NIC.ARP_TABLE)
                    elif PROTOCOL_NAME == "ICMP_REPLY":
                        print(f"{src_mac} Replied to your ICMP")
                    elif PROTOCOL_NAME == "ICMP_REQUEST":
                        ICMP_REPLY = f"{self.ip}"
                        ICMP_PACKET = Packet(ICMP_REPLY, self.ip, packet_src, protocol="3")
                        ICMP_FRAME = Frame(self.mac, src_mac, ICMP_PACKET.encode())
                        frame_encode = ICMP_FRAME.encode()
                        self.NIC.send(frame_encode) # Send out ICMP Response
                    elif PROTOCOL_NAME == "TCPDATA":
                        print("Incoming TCP Data")
                        print(packet)

                    # Configure logic for ICMP Response
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