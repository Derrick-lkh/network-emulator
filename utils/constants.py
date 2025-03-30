
PROTOCOL_MAPPING = {
    # "0": "ARP_REQUEST",
    # "1": "ARP_REPLY",
    # "2": "ICMP_REQUEST",
    # "3": "ICMP_REPLY",
    # "4": "TCPDATA"
    "1": "TCPDATA",
    "2": "ICMP"
}

PROTOCOL_TYPE = {
    "TCPDATA": "1",
    "ICMP": "2"
}
FRAME_MAPPING = { 
    "A": "ARP",
    "C": "IPV4"
}

FRAME_TYPE = {
    "ARP": "A",
    "IPV4": "C"
}