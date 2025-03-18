"""
Author: Derrick
File: router_main.py
Date: 14/02/2025
---------
Description:
"""
from utils.router import Router
import os
from dotenv import load_dotenv
load_dotenv()

if __name__ == "__main__":
    PORT_A = int(os.getenv("HUB_A_PORT", 0))
    PORT_B = int(os.getenv("HUB_B_PORT", 0))
    router = Router(PORT_A, PORT_B)
    while True:
        pass