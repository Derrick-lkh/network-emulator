from utils.Packet import *
from utils.VPN import VPN
from utils.constants import PROTOCOL_TYPE
import json
import zlib
import base64


class VPNClient:
    def __init__(self, vpn_gateway: str, vnic_ip: str, nic_ip: str):
        """
        Args:
            vpn_gateway (str): IP address of the VPN gateway (e.g., 11.22.33.1)
            vnic_ip (str): IP address of the virtual NIC (e.g., 11.22.33.44)
            nic_ip (str): IP address of the real NIC (e.g., 12.34.56.78)
            secret (str): Secret key for encryption
        """

        self.vpn_gateway = vpn_gateway
        self.vnic_ip = vnic_ip
        self.nic_ip = nic_ip
        self.vpn_ctrl = VPN()
        self.username = "user"
        self.password = "password123"

    def get_establish_conn_frame(self) -> Packet:
        """
        Hello to vpn server - sends over its ECDH keys
        """
        packet_data = self.vpn_ctrl.packet_auth_key_exchange_data()
        packet = Packet(
            packet_data,
            self.nic_ip,
            self.vpn_gateway,
            protocol=PROTOCOL_TYPE.get("VPN_AUTH"),
        )
        return packet

    def generate_shared_secret(self, server_pub) -> Packet:
        print("🔗 [VPN 3/4] Generating shared key with Server's public key")
        self.vpn_ctrl.generate_shared_secret(server_pub)
        # Next phase
        ## password
        vpn_packet_data = {
            "message_type": "VPN_AUTH_CRED",
            "username": self.username,
            "password": self.password,
        }
        vpn_packet_data = json.dumps(vpn_packet_data)
        encrypted_payload = self.encrypt(vpn_packet_data, self.vpn_gateway)
        return encrypted_payload

    def craft_encrypted_payload(self, data, dest_ip, protocol) -> Packet:
        """
        Use for encrypting communications to vpn server
        """
        vpn_packet_data = {"message_type": "VPN_PACKET", "data": data}
        vpn_packet_data = json.dumps(vpn_packet_data)
        encrypted_payload = self.encrypt(vpn_packet_data, dest_ip, protocol)
        return encrypted_payload

    def encrypt(self, data: str, dest_ip: str, protocol="0") -> Packet:
        """
        Encrypt the data and create a packet to send to the VPN gateway.
        """
        data_packet = Packet(data, self.vnic_ip, dest_ip, protocol)
        data_packet_encoded = data_packet.encode()
        ciphertext, iv, tag = self.vpn_ctrl.encrypt_data(data_packet_encoded)
        vpn_payload = {
            "c": f"{ciphertext.hex()}",
            "iv": f"{iv.hex()}",
            "tag": f"{tag.hex()}",
        }
        vpn_payload_str = json.dumps(vpn_payload)
        compressed_data = zlib.compress(vpn_payload_str.encode("utf-8"))
        encoded_payload = base64.b64encode(compressed_data).decode("utf-8")
        vpn_packet = Packet(
            encoded_payload,
            self.nic_ip,
            self.vpn_gateway,
            protocol=PROTOCOL_TYPE.get("VPN"),
        )
        return vpn_packet

    def decrypt(self, packet: Packet) -> Packet:
        """
        Decrypt an incoming packet from the VPN gateway to get the original IP packet.
        """
        encoded_payload = packet.data
        decoded_payload = base64.b64decode(encoded_payload)
        decompressed_payload = zlib.decompress(decoded_payload).decode("utf-8")
        vpn_payload_retrieved = json.loads(decompressed_payload)
        payload_cipher = vpn_payload_retrieved.get("c")
        payload_iv = vpn_payload_retrieved.get("iv")
        payload_tag = vpn_payload_retrieved.get("tag")
        decrypted_packet = self.vpn_ctrl.decrypt_data(
            payload_cipher, payload_iv, payload_tag
        )
        return decrypted_packet
