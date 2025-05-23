from utils.Node import Node
import os
from dotenv import load_dotenv
from utils.NodeInputHandler import NodeInputHandler
# from utils.Enums import Mode


load_dotenv()

if __name__ == "__main__":
    PORT = int(os.getenv("HUB_1_PORT", 0))
    GATEWAY = os.getenv("HUB_1_GATEWAY", "0x11")
    HUB_BASE_IP = os.getenv("HUB_BASE_IP", "127.0.0.1")
    ARP_TABLE = {"0x11": "R1"}
    node = Node(
        mac="N1",
        ip="0x1A",
        gateway_ip=GATEWAY,
        hub_ip=HUB_BASE_IP,
        hub_port=PORT,
        ARP_TABLE=ARP_TABLE,
    )
    node.run()
    input_handler = NodeInputHandler(node, spoof_flag=False, firewall_flag=False)
    input_handler.run()
