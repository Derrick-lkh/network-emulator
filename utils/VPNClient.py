from utils.Packet import *

class VPNClient:
    def __init__(self, VPN_GATEWAY, V_NIC_IP, SECRET):
        self.VPN_GATEWAY = VPN_GATEWAY
        self.V_NIC_IP = V_NIC_IP
        self.SECRET = SECRET
        pass

    def encrypt_(self, data: str, dest) -> Packet:
        pass