from utils.node import Node
import os
from dotenv import load_dotenv
load_dotenv()
import threading

if __name__ == "__main__":
    PORT = int(os.getenv("HUB_2_PORT", 0))
    GATEWAY = os.getenv("HUB_2_GATEWAY", "0x00")
    HUB_BASE_IP = os.getenv("HUB_BASE_IP", "0x00")
    node = Node(mac="N3", ip="0x2B", gateway_ip=GATEWAY, hub_ip=HUB_BASE_IP, hub_port=PORT, SNIFF=True)
    while True:
        dest = input("Enter destination MAC or IP: ")
    
        msg = input("Enter message: ")
        node.send(dest, msg)