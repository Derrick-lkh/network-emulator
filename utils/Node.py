from utils.Packet import *
from utils.Frame import *
from utils.NIC import *
from utils.VPN import *
from utils.Firewall import *
import threading
from utils.constants import PROTOCOL_MAPPING, PROTOCOL_TYPE, FRAME_MAPPING, FRAME_TYPE
from utils.VPNClient import *
from utils.VPNServer import *

import time


class Node:
    """
    Configure logic for Node (PC)
    # Protocol includes:
    0 - TCPDATA
    1 - ICMP

    TODO
    # Update Frame Structure
    """

    def __init__(
        self,
        mac,
        ip,
        gateway_ip,
        hub_ip,
        hub_port,
        SNIFF=False,
        ARP_TABLE=None,
        DISABLE_ANNOUNCE=False,
        FIREWALL=None,
        client_VPN=None,
        server_vpn=None,
    ):
        self.mac = mac
        self.ip = ip
        self.gateway_ip = gateway_ip
        self.SNIFF = SNIFF
        if FIREWALL:
            self.firewall = Firewall(mode=FIREWALL)
        else:
            self.firewall = None
        self.NIC = NIC(mac, ip, gateway_ip, hub_ip, hub_port, ARP_TABLE)

        self.client_VPN: VPNClient = client_VPN
        self.server_VPN: VPNServer = server_vpn

        if not DISABLE_ANNOUNCE:
            self.announce_arp()
        time.sleep(5)
        #################################
        ###            VPN            ###
        #################################
        # Establish connection with VPN
        if self.client_VPN:
            conn_packet = self.client_VPN.get_establish_conn_frame()
            packet_encoded = conn_packet.encode()

            # Craft Frame
            router_mac = self.get_mac(self.gateway_ip)

            conn_frame = Frame(
                self.mac, router_mac, packet_encoded, frame_type=FRAME_TYPE.get("IPV4")
            )
            frame_encoded = conn_frame.encode()
            print("🔗 [VPN 1/4] Establishing Key Exchange with VPN Server - Sending Client's Public Key")
            # print(Frame.decode(frame_encoded))
            # Sending to server
            self.NIC.send(frame_encoded)

    def run(self, RUN_IN_SNIFF=False, VPN_SERVER=False):
        if self.SNIFF or RUN_IN_SNIFF:
            self.sniff()
        elif VPN_SERVER:
            print("🛡️ Now running on VPN Server mode")
            threading.Thread(target=self.vpn_listen, daemon=True).start()
        else:
            print("Now listening...")
            threading.Thread(target=self.listen, daemon=True).start()

    #################################
    ###           IPV4            ###
    #################################

    def send_TCP_data(
        self, dest_ip, data, spoof_ip=False
    ):  # use for sending TCPDATA (plain message) protocol

        # TODO: add LOGIC FOR VPN
        if self.client_VPN:
            payload_packet = self.client_VPN.craft_encrypted_payload(
                data, dest_ip, protocol=PROTOCOL_TYPE.get("TCPDATA")
            )
        else:
            if spoof_ip:
                payload_packet = Packet(
                    data, spoof_ip, dest_ip, protocol=PROTOCOL_TYPE.get("TCPDATA")
                )
            else:
                payload_packet = Packet(
                    data, self.ip, dest_ip, protocol=PROTOCOL_TYPE.get("TCPDATA")
                )
        packet_encode = payload_packet.encode()
        # Create Frame
        # dest_mac = self.NIC.ARP_TABLE.get(dest_ip, None) # Fetch ARP Table from NIC - PP if none
        dest_mac = self.get_mac(dest_ip)

        # If mac not in ARP table, send to default gateway
        if dest_mac is None:
            dest_mac = self.NIC.ARP_TABLE.get(
                self.gateway_ip, None
            )  # Fetch ARP Table from NIC - PP if none
            print(f"Mac Destination not found. Sending to Gateway")
        payload_frame = Frame(self.mac, dest_mac, packet_encode)
        frame_encode = payload_frame.encode()
        self.NIC.send(frame_encode)
        print()
        print(f"[Node {self.mac}] 🚀 Message send to {dest_ip}: {data}")
        print()

    #################################
    ###            ARP            ###
    #################################

    def arp_request(self, IP_REQUEST):
        frame_data = f"R:{IP_REQUEST}".encode("utf-8")
        dest_mac = "FF"  # Broadcast
        payload_frame = Frame(
            self.mac, dest_mac, frame_data, frame_type=FRAME_TYPE.get("ARP")
        )  # ARP TYPE
        frame_encode = payload_frame.encode()
        self.NIC.send(frame_encode)
        print(f"[ARP] {self.mac} Sent to {dest_mac}: ARP request for {IP_REQUEST}")

    def send_arp_reply(self, arp_ip, arp_mac, target_src_mac):
        ARP_REPLY = f"A:{arp_ip}:{arp_mac}".encode("utf-8")
        ARP_FRAME = Frame(self.mac, target_src_mac, ARP_REPLY, FRAME_TYPE.get("ARP"))
        frame_encode = ARP_FRAME.encode()
        self.NIC.send(frame_encode)  # Send out ARP Response

    def announce_arp(self, BC_IP=False, BC_MAC=False):
        """
        Announce self ARP info (own location)
            - Sends out ARP reply with {self.ip}:{self.mac}
        """
        if not BC_IP or not BC_MAC:
            BC_IP = self.ip
            BC_MAC = self.mac
        # change ARP logic, remove packet
        ARP_REPLY = f"A:{BC_IP}:{BC_MAC}".encode("utf-8")
        ARP_FRAME = Frame(
            self.mac, "FF", ARP_REPLY, frame_type=FRAME_TYPE.get("ARP")
        )  # Broadcast
        frame_encode = ARP_FRAME.encode()
        print(f"📢 ARP Broadcast: {BC_IP} MAC identifier at {BC_MAC}")
        self.NIC.send(frame_encode)  # Send out ARP Response

    #################################
    ###          ICMP             ###
    #################################
    def send_icmp_request(self, target_ip):
        ICMP_Request = f"R"
        if self.client_VPN:
            ICMP_PACKET = self.client_VPN.craft_encrypted_payload(
                ICMP_Request, target_ip, protocol=PROTOCOL_TYPE.get("ICMP")
            )
        else:
            ICMP_PACKET = Packet(
                ICMP_Request, self.ip, target_ip, protocol=PROTOCOL_TYPE.get("ICMP")
            )
        dest_mac = self.get_mac(target_ip)
        ICMP_FRAME = Frame(self.mac, dest_mac, ICMP_PACKET.encode())
        frame_encode = ICMP_FRAME.encode()
        self.NIC.send(frame_encode)  # Send out ARP Response

    #################################
    ###   Lookup Dest Mac (ARP)   ###
    #################################
    def get_mac(self, dest_ip):
        dest_mac = self.NIC.ARP_TABLE.get(
            dest_ip, self.NIC.ARP_TABLE.get(self.NIC.gateway_ip)
        )
        return dest_mac

    def vpn_listen(self):
        """
        Handles VPN Server logic - Turn node into a server
        Pre-req: Initiate node as VPNServer
        """
        while True:
            try:
                data = self.NIC.listen()  # Application layer sniff
                if data:
                    decoded_frame = Frame.decode(data)
                    frame_type = decoded_frame.frame_type
                    frame_data = decoded_frame.data
                    FRAME_NAME = FRAME_MAPPING.get(frame_type, None)
                    if FRAME_NAME == "IPV4":
                        packet = Packet.decode(frame_data)
                        protocol = packet.protocol

                        PROTOCOL_NAME = PROTOCOL_MAPPING.get(protocol, None)
                        ## Newly added for VPN - copy paste to listen later
                        if PROTOCOL_NAME == "VPN_AUTH":
                            self.handle_VPN_connection(decoded_frame, packet)
                        elif PROTOCOL_NAME == "VPN":
                            self.handle_VPN_packets(decoded_frame, packet)
                        elif PROTOCOL_NAME == "TCPDATA" or PROTOCOL_NAME == "ICMP":
                            print(packet)
                            dest_ip = packet.dest_ip
                            connected_client = self.server_VPN.get_client_ip_mapping(
                                dest_ip
                            )
                            if connected_client:
                                # Recraft the packet
                                vpn_packet_data = {
                                    "message_type": "VPN_PACKET",
                                    "data": packet.data,
                                }
                                vpn_packet_data = json.dumps(vpn_packet_data)
                                payload_packet = self.server_VPN.encrypt(
                                    connected_client,
                                    vpn_packet_data,
                                    self.ip,
                                    packet.src_ip,
                                    packet.dest_ip,
                                    connected_client,
                                    protocol=protocol,
                                )
                                payload_packet_encoded = payload_packet.encode()
                                dest_mac = self.NIC.ARP_TABLE.get(self.gateway_ip, None)
                                payload_frame = Frame(
                                    self.mac, dest_mac, payload_packet_encoded
                                )
                                payload_frame_encoded = payload_frame.encode()
                                self.NIC.send(payload_frame_encoded)
                                print(
                                    f"📌 Sent to {dest_ip} [{connected_client}] - {packet.data}"
                                )
            except:
                break

    def handle_VPN_connection(self, frame: Frame, packet: Packet):
        # print(frame)
        # print(packet)
        src_ip = packet.src_ip
        data_json = json.loads(packet.data)
        VPN_message_type = data_json.get("message_type")
        print(f"⚡ [VPN 1/4] Incoming client establishing handshake from {src_ip}!")
        
        if VPN_message_type == "VPN_AUTH_KEY_EXCHANGE":
            client_pub = data_json.get("public_key")
            # print(f"Public key: {client_pub}")
            client_ip = packet.src_ip
            server_pub = self.server_VPN.establish_conn(client_ip, client_pub)
            print(f"⚡ [VPN 2/4] Unique key pair generated for {src_ip}!")
            conn_packet = Packet(
                server_pub,
                self.NIC.ip,
                dest_ip=src_ip,
                protocol=PROTOCOL_TYPE.get("VPN_AUTH"),
            )
            conn_packet_encoded = conn_packet.encode()

            # Craft frame
            router_mac = self.get_mac(self.gateway_ip)
            conn_frame = Frame(
                self.mac,
                router_mac,
                conn_packet_encoded,
                frame_type=FRAME_TYPE.get("IPV4"),
            )
            # print()
            # print("Sending frame")
            # print(conn_frame)
            print(f"⚡ [VPN 3/4] Sending public key to {src_ip}!")
            conn_frame_encoded = conn_frame.encode()
            self.NIC.send(conn_frame_encoded)

    def handle_VPN_packets(self, frame: Frame, packet: Packet):
        """
        Sample incoming packet data (encrypted)
        vpn_packet_data = {
            "message_type": "VPN_AUTH_CRED",
            "username": self.username,
            "password": self.password
        }

        Steps:
            - decrypt data payload
            - identify message_type
        """
        # print("Handling VPN Incoming")
        # print(frame)
        # print(packet)
        import zlib
        import base64

        client_ip = packet.src_ip
        encoded_payload = packet.data
        # # # Decode the Base64 string
        decoded_payload = base64.b64decode(encoded_payload)
        # # # Decompress the data using zlib
        decompressed_payload = zlib.decompress(decoded_payload).decode("utf-8")
        # # # Convert it back to JSON
        vpn_payload_retrieved = json.loads(decompressed_payload)
        # print(vpn_payload_retrieved)
        print(f"🔔 [VPN] Incoming VPN packet from {client_ip}!")
        # Identify sender
        packet_src = packet.src_ip
        ## Decrypt cyber
        VPN_CTRL = self.server_VPN.get_vpn_mapping(packet_src)

        payload_cipher = vpn_payload_retrieved.get("c")
        payload_iv = vpn_payload_retrieved.get("iv")
        payload_tag = vpn_payload_retrieved.get("tag")

        decrypted_packet = VPN_CTRL.decrypt_data(
            payload_cipher, payload_iv, payload_tag
        )
        # convert to actual packet
        client_packet = Packet.decode(decrypted_packet)
        print(client_packet)

        #### LOGIC FOR ALL FORWARDING
        client_packet_data = json.loads(client_packet.data)
        message_type = client_packet_data.get("message_type")

        if message_type == "VPN_AUTH_CRED":
            username, password = client_packet_data.get(
                "username"
            ), client_packet_data.get("password")
            # Craft auth payload
            payload_data, is_auth = self.server_VPN.auth_user_creds(
                client_ip, username, password
            )

            payload_packet = self.server_VPN.encrypt(
                client_ip, payload_data, self.ip, self.ip, packet_src
            )
            payload_packet_encoded = payload_packet.encode()

            router_mac = self.get_mac(self.gateway_ip)
            payload_frame = Frame(self.mac, router_mac, payload_packet_encoded)
            payload_frame_encoded = payload_frame.encode()

            self.NIC.send(payload_frame_encoded)


            client_vnic_ip = client_packet.src_ip
            if is_auth:
                print(f"⚡ [VPN 4/4] Authenticate from {client_ip} VPN Connection Success! ✅")
                self.server_VPN.update_client_ip_mapping(client_vnic_ip, client_ip)
                self.announce_arp(client_vnic_ip, self.mac)  # announce client
                print(f"🤝 [VPN] VPN connection has been established with {client_ip}!")
            else:
                self.server_VPN.remove_client_ip_mapping(client_vnic_ip)
                print(f"⚡ [VPN 4/4] Authenticate from {client_ip} VPN Connection Failed! ❌")
            
        elif message_type == "VPN_PACKET":
            # Authenticated
            connected_client = self.server_VPN.get_client_ip_mapping(
                client_packet.src_ip
            )
            if not connected_client:
                print(f"🚩 Unauthenticated Connection from {client_packet.src_ip} - Packet dropped")
                return
            # Forward packet to dest
            VPN_PACKET_DATA = client_packet_data.get("data")
            fwd_packet = Packet(
                VPN_PACKET_DATA,
                client_packet.src_ip,
                client_packet.dest_ip,
                protocol=client_packet.protocol,
            )
            fwd_packet_encoded = fwd_packet.encode()
            dest_mac = self.get_mac(client_packet.dest_ip)
            if dest_mac is None:
                dest_mac = self.NIC.ARP_TABLE.get(
                    self.gateway_ip, None
                )  # Fetch ARP Table from NIC - PP if none
            fwd_frame = Frame(self.mac, dest_mac, fwd_packet_encoded)
            fwd_frame_encoded = fwd_frame.encode()
            self.NIC.send(fwd_frame_encoded)

    def listen(self):
        while True:
            try:
                # Takes control of NIC Listening - for attack/ sniffing
                data = self.NIC.listen()  # Application layer sniff
                if data:
                    # Decode
                    decoded_frame = Frame.decode(data)
                    print(f"[Node {self.mac}] Frame received from {decoded_frame.src_mac}: \n{decoded_frame}\n")
                    src_mac = decoded_frame.src_mac
                    frame_type = decoded_frame.frame_type
                    frame_data = decoded_frame.data
                    FRAME_NAME = FRAME_MAPPING.get(frame_type, None)
                    if FRAME_NAME == "IPV4":
                        # ICMP or TCPDATA (MESSAGE)
                        packet = Packet.decode(frame_data)
                        packet_src = packet.src_ip
                        if self.firewall and not self.firewall.check_packet(packet):
                            print(f"[Firewall] Blocked packet from {packet_src}")
                            continue  # skip blocked packet
                        protocol = packet.protocol
                        # Node Application Logic
                        # Configure logic for ARP Response
                        print(f"[Node {self.mac}] Packet received from {packet.src_ip}: \n{packet}")
                        print()
                        PROTOCOL_NAME = PROTOCOL_MAPPING.get(protocol, None)
                        if PROTOCOL_NAME == "TCPDATA":
                            print(f"[TCP] Message received from {packet.src_ip}: {packet.data}")
                            print()
                        
                        elif PROTOCOL_NAME == "ICMP":
                            ICMP_TYPE = packet.data
                            if ICMP_TYPE == "A":  ## Answer
                                print(f"[ICMP] ❤️  Ping Reply received from {packet.src_ip}")
                            elif ICMP_TYPE == "R":  ## Request
                                print(f"[ICMP] ❤️  Ping received from {packet.src_ip}")
                                ICMP_REPLY = f"A"
                                
                                ICMP_PACKET = Packet(
                                    ICMP_REPLY,
                                    self.ip,
                                    packet_src,
                                    protocol=PROTOCOL_TYPE.get("ICMP"),
                                )
                                dest_mac = self.get_mac(packet_src)
                                
                                ICMP_FRAME = Frame(
                                    self.mac, dest_mac, ICMP_PACKET.encode()
                                )
                                frame_encode = ICMP_FRAME.encode()
                                self.NIC.send(frame_encode)  # Send out ICMP Response
                                print(f"[ICMP] ❤️  Sending ICMP Reply to {packet_src}")
                        elif PROTOCOL_NAME == "VPN_AUTH":
                            # logic to handle VPN packets
                            # Conn exchange keys
                            # Cipher message
                            if self.client_VPN:
                                # Client Logic
                                print("🔗 [VPN 2/4] Establishing Key Exchange with VPN Server - Received Server's Public Key")
                                # print(packet)
                                data_json = json.loads(packet.data)
                                VPN_message_type = data_json.get("message_type")
                                if VPN_message_type == "VPN_AUTH_KEY_EXCHANGE":
                                    server_pub = data_json.get("public_key")
                                    # Contains username and password for server auth
                                    cred_packet = (
                                        self.client_VPN.generate_shared_secret(
                                            server_pub
                                        )
                                    )
                                    # print(cred_packet)
                                    cred_packet_encoded = cred_packet.encode()

                                    # print("ENCODED IS ", cred_packet_encoded)
                                    router_mac = self.get_mac(self.gateway_ip)
                                    cred_frame = Frame(
                                        self.mac, router_mac, cred_packet_encoded
                                    )
                                    cred_frame_encoded = cred_frame.encode()
                                    # print("FRAME")
                                    # print(cred_frame)
                                    print("🔗 [VPN 4/4] Authenticating with VPN Server - Sending encrypted credentials")
                                    self.NIC.send(cred_frame_encoded)
                            else:
                                # VPN Server LOGIC (INCOMING)
                                pass
                        elif PROTOCOL_NAME == "VPN":
                            if self.client_VPN:  # Client logic
                                # print(packet)
                                #########################################################
                                # Decrypt IP packet                                     #
                                #########################################################
                                decrypted_packet = self.client_VPN.decrypt(
                                    packet
                                )  # Offload to Server Client

                                #########################################################
                                # Handle IP packet (Incoming)                           #
                                #########################################################
                                client_packet = Packet.decode(decrypted_packet)
                                client_packet_data = json.loads(client_packet.data)

                                client_packet_message_type = client_packet_data.get(
                                    "message_type"
                                )
                                if client_packet_message_type == "VPN_AUTH_CRED":
                                    if client_packet_data.get("status") == "Success":
                                        print(
                                            "✅ VPN Handshake Success! You are authenticated with VPN server. Communications is now encrypted!"
                                        )
                                    else:
                                        print(
                                            "❌ Auth Failed! Credentials error, authentication with server failed."
                                        )
                                elif client_packet_message_type == "VPN_PACKET":
                                    protocol = PROTOCOL_MAPPING.get(client_packet.protocol, None)
                                    vpn_packet_data = client_packet_data.get("data")
                                    print(client_packet)
                                    print(
                                        "💬🔐 VPN Decrypted message: ",
                                        vpn_packet_data
                                    )

                                    if protocol == "ICMP":
                                        ICMP_TYPE = vpn_packet_data
                                        if ICMP_TYPE == "A":  ## Answer
                                            print(f"[ICMP] ❤️  Ping Reply received from {client_packet.src_ip}")
                                        elif ICMP_TYPE == "R":  ## Request
                                            print(f"[ICMP] ❤️  Ping received from {client_packet.src_ip}")
                                            ICMP_REPLY = f"A"
                                            ICMP_PACKET = self.client_VPN.craft_encrypted_payload(
                                                ICMP_REPLY, client_packet.src_ip, protocol=client_packet.protocol
                                            )
                                            router_mac = self.get_mac(self.gateway_ip)
                                            ICMP_FRAME = Frame(
                                                self.mac, router_mac, ICMP_PACKET.encode()
                                            )
                                            frame_encode = ICMP_FRAME.encode()
                                            self.NIC.send(frame_encode)  # Send out ICMP Response
                                            print(f"❤️  Sending ICMP Reply to {client_packet.src_ip}")
                                    
                                    
                    # Move to data layer
                    elif FRAME_NAME == "ARP":
                        # Craft ARP response packet
                        decoded_frame_data = frame_data.decode("utf-8")
                        ARP_TYPE = decoded_frame_data[0]
                        print()
                        print(f"[ARP] ARP PACKET {ARP_TYPE} received on {self.mac}")
                        if ARP_TYPE == "R":  # Incoming req
                            ## REQUEST
                            _, ARP_IP = decoded_frame_data.split(":")
                            if ARP_IP == self.ip:
                                self.send_arp_reply(ARP_IP, self.mac, src_mac)
                        elif ARP_TYPE == "A":  # Receive answer
                            ## Answer
                            _, ARP_IP, ARP_MAC = decoded_frame_data.split(":")
                            # Validate IP and MAC
                            self.NIC.update_ARP_table(ARP_IP, ARP_MAC)
                            print(f"[ARP] Updated ARP Table on {self.mac}", self.NIC.ARP_TABLE)
                            print()
            except:
                break

    def sniff(self):  # For attacker
        print("Sniffing mode on...")
        print()
        while True:
            try:
                # Takes control of NIC Listening - for attack/ sniffing
                data = self.NIC.sniff()  # Application layer sniff
                if not data:
                    break
                # Decode
                decoded_frame = Frame.decode(data)
                frame_type = decoded_frame.frame_type
                frame_data = decoded_frame.data
                print("[SNIFFED]")
                print(decoded_frame)
                print()
                FRAME_NAME = FRAME_MAPPING.get(frame_type, None)
                if FRAME_NAME == "IPV4":
                    packet = Packet.decode(frame_data)
                    print("[SNIFFED]")
                    print(packet)
                    print()

            except:
                break
