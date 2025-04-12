from utils.Hub import *
import os
from dotenv import load_dotenv

load_dotenv()

if __name__ == "__main__":
    HOST = os.getenv("HUB_BASE_IP", 0)
    PORT = int(os.getenv("HUB_1_PORT", 0))
    hub = Hub(HOST, port=PORT)
    hub.run()
