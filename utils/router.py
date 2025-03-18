import socket
import threading
from utils.Packet import *


class Router:
    def __init__(self, PORT_A, PORT_B, host='127.0.0.1'):
        # Network 0x1
        self.r1_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.r1_socket.connect((host, PORT_A))
        self.r1_socket.send(bytes.fromhex("dd:ee".replace(":", "")))

        # Network 0x2
        self.r2_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.r2_socket.connect((host, PORT_B))
        self.r2_socket.send(bytes.fromhex("dd:ff".replace(":", "")))

        self.clients = {}
        self.networks = {
            "0x1": {
                "0x1A": "aa:bb"
            },
            "0x2": {
                "0x2A": "cc:dd",
                "0x2B": "ee:ff"
            }
        }
        print("[Router] Listening for connections...")

        threading.Thread(target=self.listen, args=("0x1",), daemon=True).start()
        threading.Thread(target=self.listen, args=("0x2",), daemon=True).start()

    def listen(self, network):
        while True:
            try:
                # Choose the socket based on the network
                socket_map = {"0x1": self.r1_socket, "0x2": self.r2_socket}
                current_socket = socket_map.get(network)

                # Receive data from the respective socket
                if current_socket is None:
                    break

                data = current_socket.recv(512)
                if not data:
                    break

                # Decode the packet
                decoded_packet = Packet.decode(data)
                dest_ip = decoded_packet.dest_ip

                # If destination IP does not match the current network, forward it
                if network not in dest_ip:
                    print(decoded_packet)
                    target_network = "0x2" if network == "0x1" else "0x1"
                    target_mac = self.networks.get(target_network, {}).get(dest_ip)

                    if target_mac:
                        decoded_packet.dest_mac = target_mac
                        target_socket = socket_map.get(target_network)
                        if target_socket:
                            target_socket.send(decoded_packet.encode())
                    else:
                        print(f"Destination MAC for {dest_ip} not found in network {target_network}.")

            except (socket.error, Exception) as e:
                print(f"Error occurred in {network}: {e}")
                break
