class Packet:
    def __init__(self, data, src_ip="", dest_ip="", protocol="0", src_mac="", dest_mac=""):
        # Store IPs, MACs, protocol, and data length as strings
        self.src_ip = src_ip if src_ip else "00"  # Default to "00" if src_ip is empty
        self.dest_ip = dest_ip if dest_ip else "00"  # Default to "00" if dest_ip is empty
        self.src_mac = src_mac if src_mac else "00:00"  # Default MAC if empty, fixed format AA:BB
        self.dest_mac = dest_mac if dest_mac else "00:00"  # Default MAC if empty, fixed format AA:BB
        self.protocol = protocol  # Keep protocol as string
        self.data = data  # Keep data as a string
        self.data_length = str(len(data))  # Store data length as a string

    def encode(self):
        """Encodes the packet into bytes for transmission."""
        # Convert IPs and MACs to bytes during encoding
        src_ip_bytes = int(self.src_ip, 16).to_bytes(1, 'big')
        dest_ip_bytes = int(self.dest_ip, 16).to_bytes(1, 'big')

        src_mac_bytes = bytes.fromhex(self.src_mac.replace(":", ""))
        dest_mac_bytes = bytes.fromhex(self.dest_mac.replace(":", ""))
        
        # Encoding the data when necessary
        encoded_data = self.data.encode()
        
        # Convert data_length (string) to bytes
        data_length_bytes = int(self.data_length).to_bytes(1, 'big')

        return src_ip_bytes + dest_ip_bytes + int(self.protocol).to_bytes(1, 'big') + src_mac_bytes + dest_mac_bytes + data_length_bytes + encoded_data

    @staticmethod
    def decode(raw_data):
        """Decodes a received byte stream back into a Packet object."""
        src_ip = f"0x{raw_data[0]:02X}"  # Convert 1-byte to hex format
        dest_ip = f"0x{raw_data[1]:02X}"
        protocol = str(int.from_bytes(raw_data[2:3], 'big'))
        src_mac = raw_data[3:5].hex(":")  # Convert bytes to hex with ":"
        dest_mac = raw_data[5:7].hex(":")
        data_length = str(int.from_bytes(raw_data[7:8], 'big'))  # Store data_length as a string
        data = raw_data[8:8+int(data_length)].decode()
        
        return Packet(data, src_ip, dest_ip, protocol, src_mac, dest_mac)

    def __str__(self):
        """Returns a string representation of the packet."""
        return f"Packet:\n" \
               f"  Source IP: {self.src_ip}\n" \
               f"  Destination IP: {self.dest_ip}\n" \
               f"  Source MAC: {self.src_mac}\n" \
               f"  Destination MAC: {self.dest_mac}\n" \
               f"  Protocol: {self.protocol}\n" \
               f"  Data Length: {self.data_length}\n" \
               f"  Data: {self.data}"
