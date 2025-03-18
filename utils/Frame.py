from Packet import *

class Frame:
    def __init__(self, src_mac="", dest_mac="", data=""):
        self.src_mac = src_mac
        self.dest_mac = dest_mac
        self.data = data
        self.data_length = len(data)
    
    def encode(self) -> str:
        # Converts Object to Bytes
        encoded_src_mac = self.src_mac.encode("utf-8")       # Convert source MAC to bytes
        encoded_dest_mac = self.dest_mac.encode("utf-8")     # Convert destination MAC to bytes
        encoded_data = self.data # alr encoded
        encoded_data_length = self.data_length.to_bytes(1, byteorder='big')
        return encoded_src_mac + encoded_dest_mac + encoded_data_length + encoded_data

    @staticmethod
    def decode(raw_data) -> "Frame":
        # Assuming encoded_data is the concatenated byte sequence
        # Step 1: Extract the parts
        src_mac_len = 2  # Adjust length based on the actual byte length of src_mac
        dest_mac_len = 2  # Adjust length based on the actual byte length of dest_mac
        data_length_len = 1  # 1 byte for data length (adjusted)
        
        # Extract each component from the encoded data
        encoded_src_mac = raw_data[:src_mac_len]
        encoded_dest_mac = raw_data[src_mac_len:src_mac_len+dest_mac_len]
        encoded_data_length = raw_data[src_mac_len+dest_mac_len:src_mac_len+dest_mac_len+data_length_len]
        encoded_data = raw_data[src_mac_len+dest_mac_len+data_length_len:]

        # Step 2: Decode each component
        src_mac = encoded_src_mac.decode("utf-8")
        dest_mac = encoded_dest_mac.decode("utf-8")
        data_length = encoded_data_length[0]  # Since data_length is 1 byte, just take the first byte

        # Return the decoded result (if needed)
        return Frame(src_mac, dest_mac, encoded_data)

    def get_packet(self) -> Packet:
        return Packet.decode(self.data)
    
    def validate_frame(self) -> bool:
        return True
    
    def __str__(self):
        """Returns a string representation of the packet."""
        return f"Frame:\n" \
               f"  Source MAC: {self.src_mac}\n" \
               f"  Destination MAC: {self.dest_mac}\n" \
               f"  Data Length: {self.data_length}\n" \
               f"  Data: {self.data}"

    

def main():
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
    


if __name__ == "__main__":
    main()