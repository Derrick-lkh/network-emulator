from utils.Node import Node
from utils.VPN import VPN
import os
from dotenv import load_dotenv
from utils.NodeInputHandler import NodeInputHandler

load_dotenv()

from utils.VPNServer import *

if __name__ == "__main__":
    PORT = int(os.getenv("HUB_2_PORT", 0))
    GATEWAY = os.getenv("HUB_2_GATEWAY", "0x21")
    HUB_BASE_IP = os.getenv("HUB_BASE_IP", "127.0.0.1")
    ARP_TABLE = {
        "0x21": "R2",
        # "0x2A": "N2",
        "0x2B": "N3",
    }
    VPN_server = VPNServer()
    node = Node(
        mac="N6",
        ip="0x2E",
        gateway_ip=GATEWAY,
        hub_ip=HUB_BASE_IP,
        hub_port=PORT,
        ARP_TABLE=ARP_TABLE,
        server_vpn=VPN_server,
    )
    node.run(VPN_SERVER=True)
    while True:
        pass