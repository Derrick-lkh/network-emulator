from utils.Node import Node
from utils.VPNClient import *
import os
from dotenv import load_dotenv
from utils.NodeInputHandler import NodeInputHandler
import time

load_dotenv()

if __name__ == "__main__":
    PORT = int(os.getenv("HUB_1_PORT", 0))
    GATEWAY = os.getenv("HUB_1_GATEWAY", "0x11")
    HUB_BASE_IP = os.getenv("HUB_BASE_IP", "127.0.0.1")
    ARP_TABLE = {
        "0x11": "R1",
    }
    vpn_user = "user2"
    vpn_pass = "password123"
    client_VPN = VPNClient("0x2D", "0x2F", "0x1C", vpn_user, vpn_pass)
    node = Node(
        mac="N7",
        ip="0x1C",
        gateway_ip=GATEWAY,
        hub_ip=HUB_BASE_IP,
        hub_port=PORT,
        ARP_TABLE=ARP_TABLE,
        client_VPN=client_VPN,
    )
    node.run()
    input_handler = NodeInputHandler(node, spoof_flag=False, firewall_flag=False)
    time.sleep(8)
    input_handler.run()
