# Network Emulator

## Overview
A simple network emulator simulating communication between nodes through hubs and routing between two networks via a router. It allows packet transmission, broadcasting, and routing between different network segments.

## Network Setup

### Network 0x1
- **Hub A** 127.0.0.1 Port 5000
- **Node 1**: IP: `0x1A`, MAC: `AA:BB`

### Network 0x2
- **Hub B**: 127.0.0.1 Port 6000
- **Node 2**: IP: `0x2A`, MAC: `CC:DD`
- **Node 3**: IP: `0x2B`, MAC: `EE:FF`

### Router
- **Interface 1** (R1 Network 0x1): IP: `0x11`
- **Interface 2** (R2 Network 0x2): IP: `0x21`

## Features
- **Node-to-Node Communication**: Direct message exchange within the same network.
- **Broadcasting**: Nodes can broadcast messages to all other nodes in the same network.
- **Routing**: Facilitates communication between different networks.
  
## Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Derrick-lkh/network-emulator.git
   cd network-emulator
    ```
2. Run the Router:
   ```bash
   python router_main.py
    ```
2. Run the Hubs:
   ```bash
   python hub_A.py
   python hub_B.py
    ```
3. Run the Nodes:
   ```bash
   python node_A,py
   python node_B.py
   python node_C.py
    ```
