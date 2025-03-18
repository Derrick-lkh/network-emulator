from utils.hub import *
import os
from dotenv import load_dotenv
load_dotenv()

if __name__ == "__main__":
    PORT = int(os.getenv("HUB_B_PORT", 0))
    hub = Hub(port=PORT)
    hub.run()