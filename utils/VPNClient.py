from utils.Packet import *
from cryptography.fernet import Fernet
import base64


class VPNClient:
    def __init__(self, vpn_gateway: str, vnic_ip: str, nic_ip: str, secret: str):
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
        self.cipher = Fernet(
            base64.urlsafe_b64encode(secret.encode()[:32].ljust(32, b"\0"))
        )

    def encrypt(self, data: str, dest_ip: str) -> Packet:
        """
        Encrypt the data and create a packet to send to the VPN gateway.
        Args:
            data (str): The data to encrypt (e.g., the original IP packet as a string).
            dest_ip (str): The destination IP chosen by the app.
        Returns:
            Packet: The outer packet to be sent to the VPN gateway.
        Raises:
            ValueError: If the packet is invalid.
        """

        inner_packet = Packet(data, self.vnic_ip, dest_ip, "4")
        if not inner_packet.validate_packet():
            raise ValueError("Invalid packet")

        inner_packet_str = (
            f"{inner_packet.src_ip}|{inner_packet.dst_ip}|{inner_packet.data}"
        )
        encrypted_data = self.cipher.encrypt(inner_packet_str.encode()).decode()

        # Create the outer packet (from real NIC to VPN gateway) with the encrypted data
        outer_packet = Packet(encrypted_data, self.nic_ip, self.vpn_gateway, "4")
        if not outer_packet.validate_packet():
            raise ValueError("Invalid outer packet")

        return outer_packet

    def decrypt(self, packet: Packet) -> Packet:
        """
        Decrypt an incoming packet from the VPN gateway to get the original IP packet.
        Args:
            packet (Packet): The packet received from the VPN gateway.
        Returns:
            Packet: The decrypted inner packet.
        Raises:
            ValueError: If decryption fails or the packet is invalid.
        """

        if not packet.validate_packet():
            raise ValueError("Invalid incoming packet")

        try:
            decrypted_data = self.cipher.decrypt(packet.data.encode()).decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

        try:
            src_ip, dst_ip, original_data = decrypted_data.split("|", 2)
        except ValueError:
            raise ValueError("Invalid decrypted packet format")

        inner_packet = Packet(original_data, src_ip, dst_ip, "4")
        if not inner_packet.validate_packet():
            raise ValueError("Invalid decrypted inner packet")

        return inner_packet
