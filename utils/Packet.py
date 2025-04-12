from utils.constants import PROTOCOL_MAPPING


class Packet:
    def __init__(self, data, src_ip="", dest_ip="", protocol="0"):
        # Store IPs, MACs, protocol, and data length as strings
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.protocol = protocol  # Keep protocol as string
        self.data = data  # Keep data as a string
        self.data_length = str(len(data))  # Store data length as a string

    def encode(self) -> str:
        """Encodes the packet into bytes for transmission."""
        # Convert IPs and MACs to bytes during encoding
        src_ip_bytes = int(self.src_ip, 16).to_bytes(1, "big")
        dest_ip_bytes = int(self.dest_ip, 16).to_bytes(1, "big")
        # Encoding the data when necessary
        encoded_data = self.data
        if not isinstance(self.data, bytes):
            encoded_data = self.data.encode("utf-8")

        data_length_bytes = int(self.data_length).to_bytes(1, "big")
        encode_protocol = int(self.protocol).to_bytes(1, "big")
        return (
            src_ip_bytes
            + dest_ip_bytes
            + encode_protocol
            + data_length_bytes
            + encoded_data
        )

    @staticmethod
    def decode(raw_data) -> "Packet":
        """Decodes a received byte stream back into a Packet object."""
        src_ip = f"0x{raw_data[0]:02X}"  # Convert 1-byte to hex format
        dest_ip = f"0x{raw_data[1]:02X}"
        protocol = str(int.from_bytes(raw_data[2:3], "big"))
        data_length = str(
            int.from_bytes(raw_data[3:4], "big")
        )  # Store data_length as a string
        data = raw_data[4 : 4 + int(data_length)].decode()

        return Packet(data, src_ip, dest_ip, protocol)

    def validate_packet(self) -> bool:
        """
        - IP addresses must be valid hexadecimal strings in range
        - Protocol must be either these values
            "0" - TCPDATA
            "1" - ICMP
            "2" - VPN

        - Data length must match actual data and be representable in 1 byte
        - Data must be non-empty and encodable

        TODO: add a checker to ensure data_len is 1 byte (255 max)
        """

        src_ip_sanitised = int(self.src_ip, 16)
        dest_ip_sanitised = int(self.dest_ip, 16)
        data_len = int(self.data_length)

        invalid_conditions = [
            not self.src_ip.startswith("0x"),
            not self.dest_ip.startswith("0x"),
            src_ip_sanitised not in range(256),
            dest_ip_sanitised not in range(256),
            self.protocol not in PROTOCOL_MAPPING,
            not self.data or len(self.data) == 0,
            data_len != len(self.data),
            data_len not in range(256),
        ]

        return not any(invalid_conditions)

    def __str__(self):
        """Returns a string representation of the packet."""
        return (
            f"Packet:\n"
            f"  Source IP: {self.src_ip}\n"
            f"  Destination IP: {self.dest_ip}\n"
            f"  Protocol: {self.protocol}\n"
            f"  Data Length: {self.data_length}\n"
            f"  Data: {self.data}"
        )


def main():
    # Test Functions - ignore
    x = Packet("MESSAGE", "0x1A", "0x2B", protocol="0")
    print(x.encode())
    encoded = x.encode()
    print(len(encoded))


if __name__ == "__main__":
    main()
