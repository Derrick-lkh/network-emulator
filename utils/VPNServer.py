from utils.Packet import *
from utils.Frame import *
from utils.NIC import *
from utils.VPNClient import *
from utils.Firewall import *
from utils.constants import PROTOCOL_TYPE

from utils.Node import *
from utils.VPN import *


class VPNServer:
    """
    # Handle VPN
    # Establish connection
        - exchange keys
    # Profile - IP mapping
    # Hashing - HMAC
    # Encrypt & Decrypt
    """

    def __init__(self):
        # self.node_ctrl: Node = node_ctrl
        # self.client_profile = client_profile
        self.client_ip_mapping = {
            # Hard code
            "0x2F": "0x1B",
        }
        self.client_arp = {"N5": "0x2E"}
        self.vpn_mapping = {
            # Client IP: VPN()
        }
        self.credentials = {"user": "password123"}
        self.authenticated = {
            # IP - True/ False
        }

    def get_vpn_mapping(self, client_ip) -> VPN:
        return self.vpn_mapping.get(client_ip, None)

    def get_client_ip_mapping(self, vnic_ip) -> str:
        return self.client_ip_mapping.get(vnic_ip, None)

    def is_client_authenticated(self, client_ip) -> str:
        return self.authenticated.get(client_ip, None)

    def update_client_ip_mapping(self, client_vnic_ip, client_pub_ip):
        self.client_ip_mapping[client_vnic_ip] = client_pub_ip

    def auth_user_creds(self, client_ip, username, password) -> str:
        # Craft auth status packet
        auth_status = "Fail"
        self.authenticated[client_ip] = False
        if username in self.credentials:
            if self.credentials.get(username) == password:
                auth_status = "Success"
                self.authenticated[client_ip] = True

        vpn_packet_data = {"message_type": "VPN_AUTH_CRED", "status": auth_status}
        vpn_packet_data = json.dumps(vpn_packet_data)
        return vpn_packet_data, auth_status == "Success"

    def encrypt(
        self, client_ip, data, pub_src_ip, src_ip, dest_ip, pub_dest_ip="", protocol="0"
    ) -> Packet:
        """
        SERVER_IP - To mimic sender from vpn server
        """
        VPN_CTRL = self.get_vpn_mapping(client_ip)
        if VPN_CTRL is None:
            return None
        data_packet = Packet(data, src_ip, dest_ip, protocol)
        # print(data_packet)

        data_packet_encoded = data_packet.encode()
        ciphertext, iv, tag = VPN_CTRL.encrypt_data(data_packet_encoded)
        vpn_payload = {
            "c": f"{ciphertext.hex()}",
            "iv": f"{iv.hex()}",
            "tag": f"{tag.hex()}",
        }
        vpn_payload_str = json.dumps(vpn_payload)
        compressed_data = zlib.compress(vpn_payload_str.encode("utf-8"))
        encoded_payload = base64.b64encode(compressed_data).decode("utf-8")
        if not pub_dest_ip:
            pub_dest_ip = dest_ip  # For when ip is not assign to client
        vpn_packet = Packet(
            encoded_payload, pub_src_ip, pub_dest_ip, protocol=PROTOCOL_TYPE.get("VPN")
        )
        return vpn_packet

    def establish_conn(self, client_ip, client_pub):
        """
        This function receive client public key and gnerate the shared secret
        - returns server pub key generated for this session
        """
        # Map client pub - client ip
        session_vpn_ctrl = VPN()
        session_vpn_ctrl.generate_shared_secret(client_pub)
        self.vpn_mapping[client_ip] = session_vpn_ctrl
        # send over pub key
        packet_data = session_vpn_ctrl.packet_auth_key_exchange_data()
        return packet_data
