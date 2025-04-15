import socket
import threading
import os
from utils.Packet import *
from utils.Frame import *
from utils.NIC import *
from utils.constants import FRAME_MAPPING, FRAME_TYPE, PROTOCOL_TYPE


class Router:
    def __init__(
        self,
        PORT_1,
        PORT_2,
        GATEWAY_1,
        GATEWAY_2,
        HUB_BASE_IP,
        mac1,
        ip1,
        mac2,
        ip2,
        ARP_TABLE_1=None,
        ARP_TABLE_2=None,
    ):
        # Define the routing table as a dictionary
        self.routing_table = {
            "0x1": {"interface": "R1"},
            "0x2": {"interface": "R2"},
        }
        self.IP_INTERFACE = ["0x11", "0x21"]
        self.R1 = NIC(
            mac1,
            ip1,
            gateway_ip=GATEWAY_1,
            hub_ip=HUB_BASE_IP,
            hub_port=PORT_1,
            ARP_TABLE=ARP_TABLE_1,
        )
        self.R2 = NIC(
            mac2,
            ip2,
            gateway_ip=GATEWAY_2,
            hub_ip=HUB_BASE_IP,
            hub_port=PORT_2,
            ARP_TABLE=ARP_TABLE_2,
        )

        self.nics = {
            "R1": self.R1,
            "R2": self.R2,
        }

    def start(self):
        print("[Main] Starting router...")
        for nic_name, nic in self.nics.items():
            # Start a thread for each NIC's listen method
            threading.Thread(
                target=self.listen, args=(nic_name, nic), daemon=True
            ).start()
        print("[Main] All NICs are now listening...")

    def listen(self, nic_name, nic: NIC):
        """Listen for incoming packets from a specific NIC."""
        while True:
            try:
                # Receive raw data from the NIC
                data = nic.listen()
                if data:
                    decoded_frame = Frame.decode(data)
                    print(f"[Router] Frame received on {nic_name}: \n{decoded_frame}\n")
                    src_mac = decoded_frame.src_mac
                    dest_mac = decoded_frame.dest_mac
                    frame_type = decoded_frame.frame_type
                    frame_data = decoded_frame.data
                    FRAME_NAME = FRAME_MAPPING.get(frame_type, None)
                    # Handle IPv4
                    if FRAME_NAME == "IPV4":
                        packet = Packet.decode(decoded_frame.data)
                        packet_src = packet.src_ip
                        # If the packet is meant for the router
                        if packet.dest_ip in self.IP_INTERFACE:
                            print(f"[Router] Packet is for this router: \n{packet}")
                            print()
                            protocol = packet.protocol
                            PROTOCOL_NAME = PROTOCOL_MAPPING.get(protocol, None)
                            if PROTOCOL_NAME == "ICMP":
                                ICMP_TYPE = packet.data
                                if ICMP_TYPE == "A":  ## Answer
                                    print(f"[ICMP] Ping Reply received from {packet.src_ip}")
                                    print()
                                elif ICMP_TYPE == "R":  ## Request
                                    print(f"[ICMP] Ping received from {packet.src_ip}")
                                    print()
                                    ICMP_REPLY = f"A"
                                    ICMP_PACKET = Packet(
                                        ICMP_REPLY,
                                        nic.ip,
                                        packet_src,
                                        protocol=PROTOCOL_TYPE.get("ICMP"),
                                    )
                                    self.route_packet(
                                        ICMP_PACKET, incoming_nic=nic_name
                                    )
                                pass
                            elif PROTOCOL_NAME == "TCPDATA":
                                print(f"[TCP] Message received from {packet.src_ip}: {packet.data}")
                                print()
                        # Otherwise, forward the packet
                        else:
                            print(f"[Router] Packet received on {nic_name}: \n{packet}\n")
                            self.route_packet(packet, incoming_nic=nic_name)
                    # Handle ARP
                    elif FRAME_NAME == "ARP":
                        if dest_mac == nic.mac or dest_mac == "FF":
                            # Craft ARP response packet
                            decoded_frame_data = frame_data.decode("utf-8")
                            ARP_TYPE = decoded_frame_data[0]

                            print(f"[ARP] ARP PACKET {ARP_TYPE} received on {nic.mac}")
                            if ARP_TYPE == "R":  # Incoming req
                                ## REQUEST
                                _, ARP_IP = decoded_frame_data.split(":")
                                if ARP_IP == nic.ip:
                                    self.send_arp_reply(ARP_IP, nic.mac, src_mac, nic)
                            elif ARP_TYPE == "A":  # Receive answer
                                ## Answer
                                _, ARP_IP, ARP_MAC = decoded_frame_data.split(":")
                                # Validate IP and MAC
                                nic.update_ARP_table(ARP_IP, ARP_MAC)
                                print(f"[ARP] Updated ARP on {nic.mac}", nic.ARP_TABLE)
                                print()
            except Exception as e:
                print(f"[Router] Error while listening on {nic_name}: {e}")
                break

    def route_packet(self, packet, incoming_nic):
        """Route a packet based on the routing table."""
        destination = packet.dest_ip
        print(
            f"[Router] Packet received on NIC {incoming_nic} for destination {destination}"
        )
        print()
        route = None

        for network, network_info in self.routing_table.items():
            if destination.startswith(network):
                route = network_info
                break

        if route is None:
            print(
                f"[Router] No route found for destination {destination}. Packet dropped."
            )
            print()
            return

        outgoing_interface = route["interface"]
        if outgoing_interface == incoming_nic:
            print(
                f"[Router] Packet for {destination} is already on the correct NIC {incoming_nic}. Handling locally"
            )
            print()
            nic = self.nics[incoming_nic]

        else:
            print(
                f"[Router] ⏩ Forwarding packet for {destination} via NIC {outgoing_interface}"
            )
            print()
            nic = self.nics[outgoing_interface]
        packet_encode = packet.encode()

        dest_mac = nic.ARP_TABLE.get(destination, None)
        if dest_mac is None:
            print(
                f"[Router] MAC address for destination {destination} not found in ARP table. Packet dropped."
            )
            return
        payload_frame = Frame(nic.mac, dest_mac, packet_encode)
        frame_encode = payload_frame.encode()
        nic.send(frame_encode)
        print(f"[Router] ⏩ {nic.mac} Forwarded frame to {dest_mac}")
        print(f"[Router] ⏩ Frame forwarded: \n", payload_frame)
        print(f"[Router] ⏩ Packet forwarded: \n", packet)
        print()
        return

    def send_arp_reply(self, arp_ip, arp_mac, target_src_mac, nic):
        ARP_REPLY = f"A:{arp_ip}:{arp_mac}".encode("utf-8")
        ARP_FRAME = Frame(self.mac, target_src_mac, ARP_REPLY, FRAME_TYPE.get("ARP"))
        frame_encode = ARP_FRAME.encode()
        nic.send(frame_encode)  # Send out ARP Response
        print(f"[Router] 🚀 ARP Reply Sent:")
        print(ARP_FRAME)
        print()
