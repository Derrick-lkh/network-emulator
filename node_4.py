from utils.Node import Node
import os
from dotenv import load_dotenv

load_dotenv()
import time

if __name__ == "__main__":
    """
    ARP Poisoning Script
    - Use Node send_arp_reply() to manipulate ARP table of selected target
    - For broadcast use FF for mac, IP can be anyone within the network
    """
    PORT = int(os.getenv("HUB_2_PORT", 0))
    GATEWAY = os.getenv("HUB_2_GATEWAY", "0x21")
    HUB_BASE_IP = os.getenv("HUB_BASE_IP", "127.0.0.1")
    ARP_TABLE = {"0x21": "R2", "0x2A": "N2", "0x2B": "N3"}
    node = Node(
        mac="N4",
        ip="0x2C",
        gateway_ip=GATEWAY,
        hub_ip=HUB_BASE_IP,
        hub_port=PORT,
        ARP_TABLE=ARP_TABLE,
        DISABLE_ANNOUNCE=True,
    )

    node.run()
    time.sleep(2)  # Await Node creation complete

    while True:
        arp_ip = input("Input the target IP Address for ARP Poisoning: ")
        target_mac = input("Input the target MAC Address for ARP Poisoning: ")
        # node.send_arp_reply("0x2A", "N4", "N3")
        node.send_arp_reply(arp_ip, node.mac, target_mac)
        print(f"Node {target_mac}'s ARP table is poisoned 💀. {arp_ip}:{node.mac} mapping sent 📬\n")
        pass
