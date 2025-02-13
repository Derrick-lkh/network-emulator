import socket
import threading
import sys
from utils.Packet import *


class Hub:
    def __init__(self, host='0.0.0.0', port=5000):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)
        self.clients = {}
        print("[Hub] Listening for connections...")

    def handle_client(self, conn, addr):
        mac = conn.recv(2).hex(":")
        self.clients[mac] = conn
        print(f"[Hub] Registered {mac} from {addr}")

        while True:
            try:
                data = conn.recv(512)
                if not data:
                    break
                print(data)
                # Decode
                packet = Packet.decode(data)
                src_mac = packet.src_mac
                for client_mac, client_conn in self.clients.items():
                    if client_mac != src_mac:
                        client_conn.send(data)
            except:
                break

        print(f"[Hub] Client {mac} disconnected")
        del self.clients[mac]
        conn.close()

    def run(self):
        while True:
            try:
                conn, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
            except KeyboardInterrupt:
                print("[Hub] Shutting down gracefully...")
                for client_conn in self.clients.values():
                    client_conn.close()
                self.server_socket.close()
                sys.exit()