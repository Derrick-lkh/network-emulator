from utils.Router import Router
import os
from dotenv import load_dotenv

load_dotenv()

if __name__ == "__main__":
    PORT_1 = int(os.getenv("HUB_1_PORT", 0))
    PORT_2 = int(os.getenv("HUB_2_PORT", 0))
    GATEWAY_1 = os.getenv("HUB_1_GATEWAY", "0x00")
    GATEWAY_2 = os.getenv("HUB_2_GATEWAY", "0x00")
    HUB_BASE_IP = os.getenv("HUB_BASE_IP", "0x00")
    ARP_TABLE_1 = {"0x1A": "N1", "0x1B": "N7"}
    ARP_TABLE_2 = {"0x2A": "N2", "0x2B": "N3", "0x2E": "N6"}
    router = Router(
        PORT_1,
        PORT_2,
        GATEWAY_1,
        GATEWAY_2,
        HUB_BASE_IP,
        mac1="R1",
        ip1="0x11",
        mac2="R2",
        ip2="0x21",
        ARP_TABLE_1=ARP_TABLE_1,
        ARP_TABLE_2=ARP_TABLE_2,
    )
    router.start()
    print("[Main] Router is running. Press Ctrl+C to stop.\n")

    while True:
        pass
