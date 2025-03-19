from utils.node import Node
import os
from dotenv import load_dotenv
load_dotenv()
import time

if __name__ == "__main__":
    """
    ICMP Script
    """
    PORT = int(os.getenv("HUB_2_PORT", 0))
    GATEWAY = os.getenv("HUB_2_GATEWAY", "0x21")
    HUB_BASE_IP = os.getenv("HUB_BASE_IP", "127.0.0.1")
    ARP_TABLE = {
        "0x21": "R2",
        "0x2A": "N2",
        "0x2B": "N3"
    }
    node = Node(mac="N5", ip="0x2D", gateway_ip=GATEWAY, hub_ip=HUB_BASE_IP, hub_port=PORT, ARP_TABLE=ARP_TABLE, DISABLE_ANNOUNCE=True)
    time.sleep(2) # Await Node creation complete
    node.run()
    while True:
        user_input = input("Enter a command: ")
        if user_input == "1":
            node.send_icmp_request("0x2A")
        elif user_input == "2":
            while True:
                print("sending ping")
                node.send_icmp_request("0x2A")
                time.sleep(2)
        pass