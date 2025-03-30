from utils.Packet import *
from utils.Frame import *
from utils.NIC import *
from utils.VPNClient import *
from utils.Firewall import *
import threading
from utils.constants import PROTOCOL_MAPPING, FRAME_MAPPING

class Node:
    """
    Configure logic for Node (PC)
    Protocol includes:
        0 - ARP_REQUEST
        1 - ARP_REPLY
        2 - ICMP_REQUEST
        3 - ICMP_REPLY
        4 - TCPDATA
    # todo
    - reclassify protocol
    0 - TCPDATA
    1 - ICMP

    TODO
    # Update Frame Structure
    """
    
    def __init__(self, mac, ip, gateway_ip, hub_ip, hub_port, SNIFF=False, ARP_TABLE=None, DISABLE_ANNOUNCE=False, FIREWALL=None):
        self.mac = mac
        self.ip = ip
        self.gateway_ip = gateway_ip
        self.SNIFF = SNIFF
        if FIREWALL:
            self.firewall = Firewall(mode=FIREWALL)
        else:
            self.firewall = None
        self.NIC = NIC(mac, ip, gateway_ip, hub_ip, hub_port, ARP_TABLE)
        self.VPN_CTRL: VPN = False
        
        if not DISABLE_ANNOUNCE:
            self.announce_arp()
       
    def run(self, RUN_IN_SNIFF=False):
        if self.SNIFF or RUN_IN_SNIFF:
            self.sniff()
        else:
            threading.Thread(target=self.listen, daemon=True).start()

    def connect_VPN(self, VPN_GATEWAY, V_NIC_IP, SECRET):
        self.VPN_CTRL = VPNClient(VPN_GATEWAY, V_NIC_IP, SECRET)
        pass

    def send_VPN_tunnel(self, dest_ip, data):
        # Encrypt packet
        # VPN_PUBKEY = "SECRET" # Encryption key for payload

        # Packet(VPN_PACKET. self.VPN_CTRL.VPN_GATEWAY)
        
        pass

    def send_TCP_data(self, dest_ip, data, spoof_ip=False): # use for sending TCPDATA (plain message) protocol 
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
    
    def arp_request(self, IP_REQUEST):
        frame_data = f"R:{IP_REQUEST}".encode("utf-8")
        dest_mac = "FF" # Broadcast
        payload_frame = Frame(self.mac, dest_mac, frame_data, frame_type="A") # ARP TYPE
        frame_encode = payload_frame.encode()
        self.NIC.send(frame_encode)
        print(f"[Node {self.mac}] Sent to {dest_mac}: ARP request for {IP_REQUEST}")

    def send_arp_reply(self, arp_ip, arp_mac, target_src_ip, target_src_mac):
        # Spoofing
        ARP_REPLY = f"A:{arp_ip}:{arp_mac}"
        # ARP_PACKET = Packet(ARP_REPLY, self.ip, target_src_ip, protocol="1")
        ARP_FRAME = Frame(self.mac, target_src_mac, ARP_REPLY)
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
        # change ARP logic, remove packet
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
                    # print(decoded_packet)

                    src_mac = decoded_packet.src_mac
                    frame_type = decoded_packet.frame_type
                    frame_data = decoded_packet.data
                    FRAME_NAME = FRAME_MAPPING.get(frame_type, None)
                    if FRAME_NAME == "IPV4":
                        # ICMP or TCPDATA (MESSAGE)
                        packet = Packet.decode(frame_data)
                        packet_src = packet.src_ip
                        if self.firewall and not self.firewall.check_packet(packet):
                            print(f"Blocked packet from {packet_src}")
                            continue # skip blocked packet
                        packet_data = packet.data
                        protocol = packet.protocol
                        # print(packet)
                        # Node Application Logic
                        # Configure logic for ARP Response
                        PROTOCOL_NAME = PROTOCOL_MAPPING.get(protocol, None)
                        if PROTOCOL_NAME == "TCPDATA":
                            print("Incoming TCP Data")
                            print(packet)

                    # Move to data layer
                    elif FRAME_NAME == "ARP":
                        # Craft ARP response packet
                        # found_mac = self.NIC.ARP_TABLE.get(packet_data, None)
                        ARP_TYPE = packet.data[0]
                        if ARP_TYPE == "R": # Incoming req
                            ## REQUEST
                            _, ARP_IP = packet.data.split(":")
                            if ARP_IP == self.mac:
                                ARP_REPLY = f"A:{packet_src}:{self.mac}".encode("utf-8")
                                # ARP_PACKET = Packet(ARP_REPLY, self.ip, packet_src, protocol="1")
                                ARP_FRAME = Frame(self.mac, src_mac, ARP_REPLY)
                                frame_encode = ARP_FRAME.encode()
                                self.NIC.send(frame_encode) # Send out ARP Response
                        elif ARP_TYPE == "A": # Receive answer
                            ## Answer
                            _, ARP_IP, ARP_MAC = frame_data.split(":")
                            # Validate IP and MAC
                            self.NIC.update_ARP_table(ARP_IP, ARP_MAC)
                            print()
                            print("Updated ARP", self.NIC.ARP_TABLE)
                    elif FRAME_NAME == "ICMP":
                            ICMP_TYPE = packet.data[0]
                            if ICMP_TYPE == "A": ## Answer
                                print(f"{src_mac} Replied to your ICMP")
                            elif ICMP_TYPE == "R": ## Request
                                ICMP_REPLY = f"{self.ip}"
                                ICMP_PACKET = Packet(ICMP_REPLY, self.ip, packet_src, protocol="3")
                                ICMP_FRAME = Frame(self.mac, src_mac, ICMP_PACKET.encode())
                                frame_encode = ICMP_FRAME.encode()
                                self.NIC.send(frame_encode) # Send out ICMP Response
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
