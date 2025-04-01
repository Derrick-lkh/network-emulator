if __name__ == "__main__":
    from Packet import *
    import os
    main()
else:
    from utils.Packet import *

"""
Frame Type in Frame (1 byte)
A - ARP
# B - ICMP
C - IPV4

# ARP
R:0x1A
A:0x1A:N1
"""

class Frame:
    def __init__(self, src_mac="", dest_mac="", data="", frame_type="C"):
        self.src_mac = src_mac
        self.dest_mac = dest_mac
        self.data = data
        self.data_length = len(data)
        self.frame_type = frame_type
    
    def encode(self) -> str:
        # Converts Object to Bytes
        encoded_src_mac = self.src_mac.encode("utf-8")       # Convert source MAC to bytes
        encoded_dest_mac = self.dest_mac.encode("utf-8")     # Convert destination MAC to bytes
        encoded_data = self.data # alr encoded
        encoded_data_length = self.data_length.to_bytes(1, byteorder='big')
        encoded_frame_type = self.frame_type.encode("utf-8") 
        return encoded_src_mac + encoded_dest_mac + encoded_frame_type + encoded_data_length + encoded_data

    @staticmethod
    def decode(raw_data) -> "Frame":
        # Assuming encoded_data is the concatenated byte sequence
        # Step 1: Extract the parts
        src_mac_len = 2  # Adjust length based on the actual byte length of src_mac
        dest_mac_len = 2  # Adjust length based on the actual byte length of dest_mac
        data_length_len = 1  # 1 byte for data length (adjusted)
        frame_type_len = 1
        # Extract each component from the encoded data
        encoded_src_mac = raw_data[:src_mac_len]
        encoded_dest_mac = raw_data[src_mac_len:src_mac_len+dest_mac_len]
        encoded_frame_type = raw_data[src_mac_len+dest_mac_len:src_mac_len+dest_mac_len+frame_type_len]
        encoded_data_length = raw_data[src_mac_len+dest_mac_len+frame_type_len:src_mac_len+dest_mac_len+frame_type_len+data_length_len]
        encoded_data = raw_data[src_mac_len+dest_mac_len+frame_type_len+data_length_len:]

        # Step 2: Decode each component
        src_mac = encoded_src_mac.decode("utf-8")
        dest_mac = encoded_dest_mac.decode("utf-8")
        frame_type = encoded_frame_type.decode("utf-8")
        # data_length = encoded_data_length[0]  # Since data_length is 1 byte, just take the first byte

        # Return the decoded result (if needed)
        return Frame(src_mac, dest_mac, encoded_data, frame_type=frame_type)

    def get_packet(self) -> Packet:
        # Check if data is Packet class
        return Packet.decode(self.data)
    
    def validate_frame(self) -> bool:
        """
        - Checks if source MAC address is present and not empty
        - Checks if destination MAC address is present and not empty
        - Verifies that the stored data length matches the actual length of the data
        - Ensures the data length isn't negative
        - Confirms that data isn't None
        - Validates that MAC addresses meet a minimum length requirement
        - Ensures the frame doesn't exceed a maximum size
        """

        MAX_FRAME_SIZE = int(os.getenv(MAX_FRAME_SIZE))
        MIN_MAC_LENGTH = int(os.getenv(MIN_MAC_LENGTH))

        invalid_conditions = [
            not self.src_mac,                    # Source MAC is empty/None
            not self.dest_mac,                   # Dest MAC is empty/None
            self.data is None,                   # Data is None
            self.data_length != len(self.data),  # Data length mismatch
            self.data_length < 0,                # Negative data length
            self.data_length > MAX_FRAME_SIZE,   # Exceeds max size
            len(self.src_mac) < MIN_MAC_LENGTH,  # Source MAC too short
            len(self.dest_mac) < MIN_MAC_LENGTH, # Dest MAC too short
            self.src_mac == self.dest_mac,       # Source and dest MACs identical
            not isinstance(self.src_mac, str),   # Source MAC not a string
            not isinstance(self.dest_mac, str),  # Dest MAC not a string
        ]

        return not any(invalid_conditions)
    
    
    
    def __str__(self):
        """Returns a string representation of the packet."""
        return f"Frame:\n" \
               f"  Source MAC: {self.src_mac}\n" \
               f"  Destination MAC: {self.dest_mac}\n" \
               f"  Data Length: {self.data_length}\n" \
               f"  Data: {self.data}\n" \
               f"  Frame Type: {self.frame_type}"

    

def main():
    # print(Frame.decode(b'R2N3\x07\x1a+\x00\x03123'))
    return
    # Test Functions - ignore
    encoded_packet = Packet("MESSAGE", "0x1A", "0x2B", "0").encode() # b'\x1a+\x00\x07MESSAGE'
    
    frame = Frame("N1", "R1", encoded_packet)
    encoded_frame = frame.encode()
    print(encoded_frame)
    
    #
    incoming_frame = Frame.decode(encoded_frame)
    incoming_frame.dest_mac #
    print(incoming_frame)
    incoming_packet = incoming_frame.get_packet()
    print(incoming_packet)
