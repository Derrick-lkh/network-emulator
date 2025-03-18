# Node Usage of NIC class
"""
NIC(gateway, SRC_MAC, sniffing=true) #optional

NIC_CONTROLLER = NIC(gateway, SRC_MAC)
NIC_CONTROLLER.send(dataframe)
"""

# NIC Class
0x1 - NIC1
0x2 - NIC2
"""
socket init
Receive -> update arp, filter (mac dest addr)
send -> validate frame

Sniffing_mode (OFF): 
    Check (bool):
        mac filter = sniffing_mode?

ARP table -> generated dynamically based on sniff
{
    0x11: R1
    0x1A: N1
}
{
    0x21: R2
    0x2A: N2
    0x2B: N3
}
gateway: 0x21
0x2B

0x1A: router mac dest
"""