from utils.node import Node, is_valid_mac_or_hex


if __name__ == "__main__":
    node = Node(mac="ee:ff", ip="0x2B", hub_ip="127.0.0.1", hub_port=6000)
    while True:
        dest = input("Enter destination MAC or IP: ")
    
        if is_valid_mac_or_hex(dest):
            msg = input("Enter message: ")
            node.send(dest, msg)
        else:
            print("Invalid MAC or hex format. Please enter a valid destination.")