class VPNServer:
    def __init__(self):
        CLIENTS = {
            "CLIENT IPV4": "SOCKET OBJ"
        }
        self.NIC = False # VPN GATEWAY
        # create socker for VPN server

        pass

    def decrypt(self):
        pass

    def encrypt(self):
        pass
    
    def connect(self):
        #
        # new socket
        # update my Client-socket mapping


        pass
    # Toggle Logic (within network or outside)


    # N1 -> VPN 1 (encrypted)
    # VPN 1 -> N2 (encrypted)
    # 

    # Firewall
    """
    RULE:
    - N3 block all from N2
    
    
    N1 (VPN CLIENT)
    N4 (whitelist, accepts only internal packet IPV4), N5 (VPN SERVER)
    N4 (PASSWORD)
    N1 -> N4

    # Reply N4 -> N1
    N4 -> N5 
    --- -- -  N5?
    N5 -> N1

    """
    