import socket
import threading

class Node:
    def __init__(self, mac, ip, hub_ip, hub_port=5000):
        self.mac = bytes.fromhex(mac.replace(":", ""))  # Convert MAC to bytes
        self.ip = ip
        self.hub_addr = (hub_ip, hub_port)
        
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect(self.hub_addr)
        self.client_socket.send(self.mac)
        print(f"[Node {self.mac.hex()}] Connected to hub at {hub_ip}")
        
        threading.Thread(target=self.listen, daemon=True).start()
    
    def listen(self):
        while True:
            try:
                data = self.client_socket.recv(512)
                if not data:
                    break
                src_mac = data[:2].hex()
                dest_mac = data[2:4].hex()
                payload = data[5:].decode()
                
                if dest_mac == self.mac.hex() or dest_mac == "ffff":  # Broadcast or direct
                    print(f"[Node {self.mac.hex()}] Received from {src_mac}: {payload}")
            except:
                break
    
    def send(self, dest_mac, message):
        dest_mac_bytes = bytes.fromhex(dest_mac.replace(":", ""))
        length = len(message).to_bytes(1, 'big')
        frame = self.mac + dest_mac_bytes + length + message.encode()
        self.client_socket.send(frame)
        print(f"[Node {self.mac.hex()}] Sent to {dest_mac}: {message}")
    
if __name__ == "__main__":
    node = Node(mac="AA:BB", ip="192.168.1.2", hub_ip="127.0.0.1")
    
    while True:
        dest = input("Enter destination MAC: ")
        msg = input("Enter message: ")
        node.send(dest, msg)
