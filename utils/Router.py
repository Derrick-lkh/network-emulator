import socket
import threading
import os
from utils.Packet import *
from utils.Frame import *
from utils.NIC import *
from utils.constants import FRAME_MAPPING, PROTOCOL_TYPE


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
        self.IP_INTERFACE = ["0x11", "0x22"]
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
        print("[Router] Starting router...")
        for nic_name, nic in self.nics.items():
            # Start a thread for each NIC's listen method
            threading.Thread(
                target=self.listen, args=(nic_name, nic), daemon=True
            ).start()
        print("[Router] All NICs are now listening.")

    def listen(self, nic_name, nic: NIC):
        """Listen for incoming packets from a specific NIC."""
        while True:
            try:
                # Receive raw data from the NIC
                data = nic.listen()
                if data:
                    print("*" * 50)
                    decoded_frame = Frame.decode(data)
                    print(decoded_frame)

                    # TODO: Add a checker for Packet validation
                    # only handle Frame with Packet
                    packet = Packet.decode(decoded_frame.data)
                    packet_src = packet.src_ip
                    print(f"[Router] Packet received on {nic_name}: \n{packet}")
                    print("*" * 50)
                    src_mac = decoded_frame.src_mac
                    dest_mac = decoded_frame.dest_mac
                    frame_type = decoded_frame.frame_type
                    frame_data = decoded_frame.data
                    FRAME_NAME = FRAME_MAPPING.get(frame_type, None)
                    # ARP
                    if FRAME_NAME == "IPV4":
                        # If the packet is meant for the router
                        if packet.dest_ip in self.IP_INTERFACE:
                            print(f"[Router] Packet is for this router: \n{packet}")
                            protocol = packet.protocol
                            PROTOCOL_NAME = PROTOCOL_MAPPING.get(protocol, None)
                            if PROTOCOL_NAME == "ICMP":
                                ICMP_TYPE = packet.data
                                if ICMP_TYPE == "A":  ## Answer
                                    print(f"{src_mac} Replied to your ICMP")
                                elif ICMP_TYPE == "R":  ## Request
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
                        # Otherwise, forward the packet
                        else:
                            self.route_packet(packet, incoming_nic=nic_name)
                    elif FRAME_NAME == "ARP":
                        if dest_mac == nic.mac or dest_mac == "FF":
                            # Craft ARP response packet
                            decoded_frame_data = frame_data.decode("utf-8")
                            ARP_TYPE = decoded_frame_data[0]

                            print(f"ARP PACKET {ARP_TYPE}")
                            if ARP_TYPE == "R":  # Incoming req
                                ## REQUEST
                                _, ARP_IP = decoded_frame_data.split(":")
                                if ARP_IP == self.ip:
                                    self.send_arp_reply(ARP_IP, self.mac, src_mac)
                            elif ARP_TYPE == "A":  # Receive answer
                                ## Answer
                                _, ARP_IP, ARP_MAC = decoded_frame_data.split(":")
                                # Validate IP and MAC
                                nic.update_ARP_table(ARP_IP, ARP_MAC)
                                print()
                                print("Updated ARP", nic.ARP_TABLE)
            except Exception as e:
                print(f"[Router] Error while listening on {nic_name}: {e}")
                break

    def route_packet(self, packet, incoming_nic):
        """Route a packet based on the routing table."""
        destination = packet.dest_ip
        print(
            f"[Router] Packet received on NIC {incoming_nic} for destination {destination}"
        )
        route = None

        for network, network_info in self.routing_table.items():
            if destination.startswith(network):
                route = network_info
                break

        if route is None:
            print(
                f"[Router] No route found for destination {destination}. Packet dropped."
            )
            return

        outgoing_interface = route["interface"]
        if outgoing_interface == incoming_nic:
            print(
                f"[Router] Packet for {destination} is already on the correct NIC {incoming_nic}. Handling locally"
            )
            nic = self.nics[incoming_nic]

        else:
            print(
                f"[Router] Forwarding packet for {destination} via via NIC {outgoing_interface}"
            )
            nic = self.nics[outgoing_interface]

            print(nic)
            if packet.protocol == "TCP":
                if packet.dest_ip == nic.ip:
                    print(f"[Router] Packet is for this router: \n{packet}")
                    return
        print(packet)
        packet_encode = packet.encode()
        print("check dest here")
        print(destination)
        dest_mac = nic.ARP_TABLE.get(destination, None)
        print(destination)
        print(dest_mac)
        if dest_mac is None:
            print(
                f"[Router] MAC address for destination {destination} not found in ARP table. Packet dropped."
            )
            return
        payload_frame = Frame(nic.mac, dest_mac, packet_encode)
        frame_encode = payload_frame.encode()
        nic.send(frame_encode)
        print(payload_frame)
        print(f"[Router {nic.mac}] Forwarded frame to [Node {dest_mac}]")
        return
