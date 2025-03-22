from utils.node import Node
import os
from dotenv import load_dotenv
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
    spoof_flag=False
    node = Node(mac="N3", ip="0x2B", gateway_ip=GATEWAY, hub_ip=HUB_BASE_IP, hub_port=PORT, SNIFF=False, ARP_TABLE=ARP_TABLE, SPOOF=spoof_flag)
    node.run()
    while True:
        dest = input("Enter destination MAC or IP: ")
        msg = input("Enter message: ")
        spoof_ip = ""
        if spoof_flag:
            spoof_ip = input("Enter ip address to spoof as: ")
        node.send_TCP_data(dest, msg, spoof_ip)