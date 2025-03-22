import socket
import threading
import os
from utils.Packet import *
from utils.Frame import *
from utils.NIC import *



class Router:
    def __init__(self, PORT_1, PORT_2, GATEWAY_1, GATEWAY_2, HUB_BASE_IP, mac1, ip1, mac2, ip2, ARP_TABLE_1=None, ARP_TABLE_2=None):
        # Define the routing table as a dictionary
        self.routing_table = {
            "0x1": {"interface": "R1"},  
            "0x2": {"interface": "R2"},  
        }

        self.R1 = NIC(mac1, ip1, gateway_ip=GATEWAY_1, hub_ip=HUB_BASE_IP, hub_port=PORT_1, ARP_TABLE=ARP_TABLE_1)
        self.R2 = NIC(mac2, ip2, gateway_ip=GATEWAY_2, hub_ip=HUB_BASE_IP, hub_port=PORT_2, ARP_TABLE=ARP_TABLE_2)

        self.nics = {
            "R1": self.R1,
            "R2": self.R2,
        }

    def start(self):
        print("[Router] Starting router...")
        for nic_name, nic in self.nics.items():
            # Start a thread for each NIC's listen method
            threading.Thread(target=self.listen, args=(nic_name, nic), daemon=True).start()
        print("[Router] All NICs are now listening.")

    def listen(self, nic_name, nic):
        """Listen for incoming packets from a specific NIC."""
        while True:
            try:
                # Receive raw data from the NIC
                data = nic.listen()  
                if data:
                    print("*" * 50)
                    decoded_frame = Frame.decode(data)
                    print(decoded_frame)
                    packet = Packet.decode(decoded_frame.data)
                    print(f"[Router] Packet received on {nic_name}: \n{packet}")
                    print("*" * 50)


                    # If the packet is meant for the router
                    if packet.dest_ip == nic.ip:
                        print(f"[Router] Packet is for this router: \n{packet}")
                    # Otherwise, forward the packet
                    else:
                        self.route_packet(packet, incoming_nic=nic_name)
            except Exception as e:
                print(f"[Router] Error while listening on {nic_name}: {e}")
                break

    def route_packet(self, packet, incoming_nic):
        """Route a packet based on the routing table."""
        destination = packet.dest_ip
        print(f"[Router] Packet received on NIC {incoming_nic} for destination {destination}")
        route = None

        for network, network_info in self.routing_table.items():
            if destination.startswith(network):
                route = network_info
                break
        
        if route is None:
            print(f"[Router] No route found for destination {destination}. Packet dropped.")
            return
        
        outgoing_interface = route["interface"]
        if outgoing_interface == incoming_nic:
            print(f"[Router] Packet for {destination} is already on the correct NIC {incoming_nic}. Handling locally")
            nic = self.nics[incoming_nic]

        else:
            print(f"[Router] Forwarding packet for {destination} via via NIC {outgoing_interface}")
            nic = self.nics[outgoing_interface]
            print(nic)
        packet_encode = packet.encode()
        dest_mac = nic.ARP_TABLE.get(destination, None)
        print(destination)
        print(dest_mac)
        if dest_mac is None:
            print(f"[Router] MAC address for destination {destination} not found in ARP table. Packet dropped.")
            return
        payload_frame = Frame(nic.mac, dest_mac, packet_encode)
        frame_encode = payload_frame.encode()
        nic.send(frame_encode)
        print(f"[Router {nic.mac}] Forwarded frame to [Node {dest_mac}]")
        return

