from utils.node import Node, is_valid_mac_or_hex
import os
from dotenv import load_dotenv
load_dotenv()

if __name__ == "__main__":
    PORT = int(os.getenv("HUB_A_PORT", 0))
    node = Node(mac="aa:bb", ip="0x1A", hub_ip="127.0.0.1", hub_port=PORT)
    while True:
        dest = input("Enter destination MAC or IP: ")
    
        if is_valid_mac_or_hex(dest):
            msg = input("Enter message: ")
            node.send(dest, msg)
        else:
            print("Invalid MAC or hex format. Please enter a valid destination.")