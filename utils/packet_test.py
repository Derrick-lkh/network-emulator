import unittest
from Packet import Packet

class TestPacket(unittest.TestCase):

    def test_packet_encoding_decoding(self):
        # Create a packet instance
        packet = Packet("123", src_ip="0x1A", dest_ip="0x2B", src_mac="AA:BB", dest_mac="CC:DD", protocol="1")
        
        # Encode the packet
        encoded_packet = packet.encode()
        
        # Decode the packet
        decoded_packet = Packet.decode(encoded_packet)
        
        # Assert that the decoded values match the original input
        self.assertEqual(decoded_packet.src_ip, "0x1A")
        self.assertEqual(decoded_packet.dest_ip, "0x2B")
        self.assertEqual(decoded_packet.src_mac, "aa:bb")
        self.assertEqual(decoded_packet.dest_mac, "cc:dd")
        self.assertEqual(decoded_packet.data_length, "3")  # Data length should be a string
        self.assertEqual(decoded_packet.data, "123")  # Data should be the same as the original data

if __name__ == "__main__":
    unittest.main()
