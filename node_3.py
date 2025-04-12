from utils.Node import Node
import os
from dotenv import load_dotenv

from utils.NodeInputHandler import NodeInputHandler

load_dotenv()

if __name__ == "__main__":
    PORT = int(os.getenv("HUB_2_PORT", 0))
    GATEWAY = os.getenv("HUB_2_GATEWAY", "0x21")
    HUB_BASE_IP = os.getenv("HUB_BASE_IP", "127.0.0.1")
    ARP_TABLE = {
        "0x21": "R2",
        "0x2A": "N2",
        # "0x2B": "N3"
    }

    node = Node(
        mac="N3",
        ip="0x2B",
        gateway_ip=GATEWAY,
        hub_ip=HUB_BASE_IP,
        hub_port=PORT,
        SNIFF=False,
        ARP_TABLE=ARP_TABLE,
    )
    node.run()
    input_handler = NodeInputHandler(node, spoof_flag=False, firewall_flag=False)
    input_handler.run()
